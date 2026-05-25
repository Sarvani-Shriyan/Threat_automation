# pip install openai pydantic

import hashlib
import json
import logging
import re
import time
from typing import Any, Callable

from openai import APIConnectionError, APITimeoutError, OpenAI

from generators.knowledge_base import GroundingResult, KnowledgeBase
from generators.models import DetectionRule, ThreatRuleBatch
from ingestion.config import (
    KNOWLEDGE_BASE_MAX_ACTIONS,
    OLLAMA_BASE_URL,
    OLLAMA_PHI4_MODEL,
    OLLAMA_PHI4_TIMEOUT_SECONDS,
    RULE_VARIANTS_MAX,
    RULE_VARIANTS_MIN,
)

logger = logging.getLogger(__name__)

SYSTEM_PROMPT_BASE = f"""You are an expert detection engineer building production SIEM/detection rules.

Given a verified security threat article, generate exactly {RULE_VARIANTS_MIN} to {RULE_VARIANTS_MAX} DISTINCT detection rule variants that catch different behavioral variations of the same attack.

Output ONLY a valid JSON object with this exact structure (no markdown):
{{"rules": [ ...array of {RULE_VARIANTS_MIN}-{RULE_VARIANTS_MAX} rule objects... ]}}

Each rule object MUST conform exactly to this schema:
{{
  "name": "String — format: '[Platform]: [Actionable, Precise Indicator Title]'",
  "description": "String — detailed operational triggers, condition boundaries, and focus context",
  "actionNames": ["String — exact infrastructure/API actions to monitor from the threat text"],
  "defaultSeverity": "String — one of: Low, Medium, High, Critical",
  "threatType": "String — MITRE ATT&CK Tactic name classification",
  "recommend": "String — strategic structural hardening and configuration recommendations",
  "remediate": "String — tactical response, host containment, validation steps"
}}

Requirements:
- Each variant must target a different detection angle (e.g., auth anomaly, API abuse, config drift, lateral movement signal).
- Names must include the primary platform (AWS, Azure, Okta, etc.) from the article context."""


def build_grounded_system_prompt(grounding: GroundingResult) -> str:
    allowed_actions = grounding.allowed_actions
    platform = grounding.primary_platform or "cloud"

    if grounding.primary_platform == "github":
        env_line = (
            "\n\nENVIRONMENT: You are generating rules for a GitHub environment "
            "(Actions workflows and/or organization audit logs)."
        )
        forbid = (
            "\nYou are strictly forbidden from inventing fake event paths or action strings. "
            "You MUST populate the 'actionNames' array ONLY using strings found inside this "
            "verified collection (LOOKUP_ARRAY)."
        )
    elif grounding.primary_platform == "okta" or "okta" in grounding.matched_platforms:
        env_line = (
            "\n\nENVIRONMENT: You are generating rules for an Okta Enterprise Directory "
            "system environment (System Log event types)."
        )
        forbid = (
            "\nYou are strictly forbidden from inventing fake event paths or guessing "
            "period-notation structures. You MUST populate 'actionNames' ONLY using strings "
            "explicitly found inside this reference collection (LOOKUP_ARRAY)."
        )
    elif grounding.primary_platform == "azure" or "azure" in grounding.matched_platforms:
        env_line = (
            "\n\nENVIRONMENT: You are generating rules for an Azure Resource Manager (ARM) "
            "environment (ARM operations and/or Entra ID audit activities)."
        )
        forbid = (
            "\nYou are strictly forbidden from inventing fake permission namespaces or guessing "
            "slash/period paths. You MUST populate the 'actionNames' array ONLY using strings "
            "explicitly found inside this reference collection (LOOKUP_ARRAY)."
        )
    else:
        env_line = f"\n\nENVIRONMENT: You are generating rules for a {platform} environment."
        forbid = (
            "\nYou are strictly forbidden from creating or guessing event names. "
            "You MUST select and populate the 'actionNames' array ONLY from this verified list of choices."
        )

    if not allowed_actions:
        vocab_block = (
            "\n\nSTRICT ALLOWED VOCABULARY (LOOKUP_ARRAY):\n"
            "[No verified action names retrieved — do not invent API/event names.]"
        )
    else:
        vocab_json = json.dumps(allowed_actions, indent=2)
        vocab_block = (
            f"\n\nSTRICT ALLOWED VOCABULARY (LOOKUP_ARRAY — verified authoritative catalog):\n"
            f"{vocab_json}"
        )

    profile_note = ""
    if grounding.routed_profiles:
        profile_note = f"\nRouted catalog profiles: {', '.join(grounding.routed_profiles)}."

    return SYSTEM_PROMPT_BASE + env_line + profile_note + vocab_block + forbid


class RuleEngine:
    """Phi-4 rule generation with knowledge-base grounded actionNames."""

    def __init__(
        self,
        knowledge_base: KnowledgeBase,
        base_url: str = OLLAMA_BASE_URL,
        model: str = OLLAMA_PHI4_MODEL,
        timeout_seconds: float = OLLAMA_PHI4_TIMEOUT_SECONDS,
    ) -> None:
        self._kb = knowledge_base
        self._model = model
        self._client = OpenAI(
            base_url=base_url,
            api_key="ollama",
            timeout=timeout_seconds,
        )

    def ground_threat(self, threat: dict[str, Any]) -> GroundingResult:
        text = f"{threat.get('title', '')}\n{threat.get('content', '')}"
        return self._kb.lookup(text)

    def generate_for_threat(
        self,
        threat: dict[str, Any],
        grounding: GroundingResult | None = None,
    ) -> tuple[list[DetectionRule], str | None, GroundingResult]:
        grounding = grounding or self.ground_threat(threat)
        system_prompt = build_grounded_system_prompt(grounding)

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": self._build_user_prompt(threat, grounding)},
                ],
                temperature=0.3,
                response_format={"type": "json_object"},
            )
            raw = response.choices[0].message.content or "{}"
            batch = self._parse_rules(raw)
            return batch.rules, None, grounding
        except (APIConnectionError, APITimeoutError, ConnectionError, TimeoutError) as exc:
            msg = f"Phi-4 offline or timeout: {exc}"
            logger.error("phi4_timeout threat=%s error=%s", threat.get("title"), exc)
            return [], msg, grounding
        except Exception as exc:
            msg = f"Generation failed: {exc}"
            logger.error("phi4_generation_failed threat=%s error=%s", threat.get("title"), exc)
            return [], msg, grounding

    def process_threat_stream(
        self,
        threats: list[dict[str, Any]],
        *,
        on_before: Callable[[int, int, dict[str, Any], GroundingResult], None] | None = None,
        on_after: Callable[[int, int, dict[str, Any], dict[str, Any], float], None] | None = None,
        skip_ids: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        total = len(threats)
        skip_ids = skip_ids or set()
        produced: list[dict[str, Any]] = []

        for index, threat in enumerate(threats, start=1):
            tid = threat_id(threat)
            title = threat.get("title", "Untitled")

            if tid in skip_ids:
                logger.info("skip_already_staged %d/%d threat_id=%s", index, total, tid)
                print(f"[Skipped Threat {index}/{total}] Already staged: {title}")
                continue

            grounding = self.ground_threat(threat)
            if on_before:
                on_before(index, total, threat, grounding)

            started = time.perf_counter()
            rules, error, grounding = self.generate_for_threat(threat, grounding=grounding)
            elapsed = time.perf_counter() - started

            entry = build_staging_entry(threat, rules, error, grounding=grounding)
            produced.append(entry)

            if on_after:
                on_after(index, total, threat, entry, elapsed)

        return produced

    @staticmethod
    def _build_user_prompt(threat: dict[str, Any], grounding: GroundingResult) -> str:
        verdict = threat.get("gemma_verdict") or {}
        allowed_preview = ", ".join(grounding.allowed_actions[:8])
        if len(grounding.allowed_actions) > 8:
            allowed_preview += ", ..."
        return (
            f"Threat Title: {threat.get('title', '')}\n"
            f"Source: {threat.get('source', '')}\n"
            f"URL: {threat.get('url', 'N/A')}\n"
            f"Gemma Justification: {verdict.get('justification', 'N/A')}\n"
            f"MITRE Hint: {verdict.get('mitre_tactic_hint', '')}\n"
            f"Grounded Platforms: {', '.join(grounding.matched_platforms) or 'none'}\n"
            f"Routed Profiles: {', '.join(grounding.routed_profiles) or 'none'}\n"
            f"Verified actionNames sample: {allowed_preview or 'none'}\n\n"
            f"Threat Content:\n{(threat.get('content') or '')[:5000]}"
        )

    @staticmethod
    def _parse_rules(raw: str) -> ThreatRuleBatch:
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
        data = json.loads(text)
        if isinstance(data, list):
            return ThreatRuleBatch(rules=data)
        if "rules" in data:
            return ThreatRuleBatch(rules=data["rules"])
        if "variants" in data:
            return ThreatRuleBatch(rules=data["variants"])
        raise ValueError("Response missing 'rules' array")


def threat_id(threat: dict[str, Any]) -> str:
    key = f"{threat.get('title', '')}|{threat.get('url', '')}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def build_staging_entry(
    threat: dict[str, Any],
    rules: list[DetectionRule],
    error: str | None,
    *,
    grounding: GroundingResult | None = None,
) -> dict[str, Any]:
    status = "success" if rules and not error else "failed"
    entry: dict[str, Any] = {
        "threat_id": threat_id(threat),
        "threat_title": threat.get("title", ""),
        "threat_url": threat.get("url"),
        "source": threat.get("source", ""),
        "gemma_verdict": threat.get("gemma_verdict"),
        "variants": [r.model_dump() for r in rules],
        "variant_count": len(rules),
        "generation_status": status,
        "error": error,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if grounding:
        entry["grounding_context"] = {
            "matched_platforms": grounding.matched_platforms,
            "primary_platform": grounding.primary_platform,
            "routed_profiles": grounding.routed_profiles,
            "injected_action_count": grounding.action_count,
            "allowed_actions": grounding.allowed_actions,
            "source_files": grounding.source_files,
        }
    return entry
