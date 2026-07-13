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

SYSTEM_PROMPT_BASE = """\
You are an expert detection engineer building production SIEM/detection rules.

Given a verified security threat article, generate EXACTLY 3 detection rule variants.
The array must contain EXACTLY 3 objects — no more, no fewer.

Output ONLY a valid JSON object with this exact structure (no markdown, no commentary):
{"rules": [ <rule_1>, <rule_2>, <rule_3> ]}

━━━ MANDATORY STRATEGY DIVERSITY ━━━
Each of the 3 rules MUST target a FUNDAMENTALLY different telemetry layer.
Do NOT produce slight syntax variations of the same detection idea.

  Rule 1 — PROCESS CREATION / COMMAND-LINE ARGUMENTS
    Focus: spawned processes, executable paths, command-line flags, script invocations,
           shell child-process chains, or interpreter abuse tied to the threat.

  Rule 2 — FILE / REGISTRY MODIFICATIONS OR BEHAVIORAL INDICATORS
    Focus: file writes, file reads on sensitive paths, registry key changes,
           configuration drift, credential file access, persistence artifacts,
           or storage-layer behavioral anomalies tied to the threat.

  Rule 3 — NETWORK CONNECTIONS / API / SYSTEM CALLS
    Focus: outbound/inbound connection patterns, DNS lookups, API calls,
           data-plane syscalls, cloud-plane operations, or protocol-level
           indicators tied to the threat.

━━━ SCHEMA — every rule MUST include ALL 7 keys, NO EXCEPTIONS ━━━

{
  "name":            "String — format: '[Platform]: [Actionable Indicator Title]'",
  "description":     "String — operational trigger, condition boundaries, layer focus",
  "actionNames":     ["String — exact infrastructure/API action name to monitor"],
  "defaultSeverity": "String — exactly one of: Low, Medium, High, Critical",
  "threatType":      "String — MITRE ATT&CK Tactic name",
  "recommend":       "String — structural hardening and preventive configuration steps",
  "remediate":       "String — tactical response, containment, and post-incident validation"
}

EXAMPLE of one correctly-formed rule object:
{
  "name": "[Azure]: Unusual Role Assignment to Service Principal",
  "description": "Detects unexpected IAM role assignments to service principals outside approved change windows.",
  "actionNames": ["Microsoft.Authorization/roleAssignments/write"],
  "defaultSeverity": "High",
  "threatType": "Privilege Escalation",
  "recommend": "Enforce PIM-based just-in-time access for all service principal role assignments. Require approval workflows for privileged roles.",
  "remediate": "Immediately revoke the unauthorized role assignment. Review the assigning identity for compromise indicators. Audit all recent role changes in the subscription."
}

CRITICAL: The "recommend" and "remediate" keys are MANDATORY. Every rule object in your output MUST contain both. Rules missing either key are INVALID.

━━━ HARD RULES ━━━
- Names must include the primary platform (AWS, Azure, Okta, GitHub, etc.).
- Do NOT invent actionNames — use ONLY strings from the LOOKUP_ARRAY provided.
- Do NOT emit markdown fences, prose, or any text outside the JSON object.\
"""


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
    """
    phi4-mini-reasoning rule generation with knowledge-base grounded actionNames.

    Generates exactly 3 structurally diverse detection rule variants per threat:
      Rule 1 — Process Creation / Command-Line Arguments
      Rule 2 — File / Registry Modifications or Behavioral Indicators
      Rule 3 — Network Connections / API / System Calls
    """

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
            msg = f"phi4-mini-reasoning offline or timeout: {exc}"
            logger.error("reasoning_model_timeout threat=%s error=%s", threat.get("title"), exc)
            return [], msg, grounding
        except Exception as exc:
            msg = f"Generation failed: {exc}"
            logger.error("reasoning_model_generation_failed threat=%s error=%s", threat.get("title"), exc)
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
        reasoning = (
            verdict.get("reasoning_summary")
            or verdict.get("justification")
            or "N/A"
        )
        allowed_preview = ", ".join(grounding.allowed_actions[:8])
        if len(grounding.allowed_actions) > 8:
            allowed_preview += ", ..."
        return (
            f"Threat Title: {threat.get('title', '')}\n"
            f"Source: {threat.get('source', '')}\n"
            f"URL: {threat.get('url', 'N/A')}\n"
            f"Semantic Domain: {verdict.get('primary_domain', 'Unknown')}\n"
            f"Semantic Platform: {verdict.get('primary_platform', 'Unknown')}\n"
            f"Confidence Score: {verdict.get('confidence_score', 'N/A')}/10\n"
            f"Semantic Summary: {reasoning}\n"
            f"Grounded Platforms: {', '.join(grounding.matched_platforms) or 'none'}\n"
            f"Routed Profiles: {', '.join(grounding.routed_profiles) or 'none'}\n"
            f"Verified actionNames sample: {allowed_preview or 'none'}\n\n"
            f"REMINDER — output exactly 3 rules using the 3 mandatory strategy layers:\n"
            f"  [1] Process Creation / Command-Line Arguments\n"
            f"  [2] File / Registry Modifications or Behavioral Indicators\n"
            f"  [3] Network Connections / API / System Calls\n\n"
            f"Threat Content:\n{(threat.get('content') or '')[:5000]}"
        )

    @staticmethod
    def _strip_model_artifacts(raw: str) -> str:
        """Remove markdown fences and phi4-mini-reasoning <thinking> blocks before JSON parse."""
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
            text = re.sub(r"\s*```$", "", text, flags=re.IGNORECASE)
        text = re.sub(r"<thinking>.*?</thinking>", "", text, flags=re.DOTALL | re.IGNORECASE)
        return text.strip()

    @staticmethod
    def _extract_rules_json(text: str) -> dict[str, Any]:
        """
        Isolate the rules JSON object from the model response.

        Extraction order:
        1. Direct parse — handles clean {"rules": [...]} output.
        2. Bare array — handles [rule1, rule2, rule3] without wrapper.
        3. Greedy nested-brace scan — picks first valid dict with 'rules'/'variants'.
        4. Greedy bracket scan — last-resort bare array extraction.
        5. Widest brace match — last-resort full-text dict extraction.
        """
        # 1. Direct parse
        try:
            payload = json.loads(text)
            if isinstance(payload, dict):
                return payload
            if isinstance(payload, list):
                return {"rules": payload}
        except json.JSONDecodeError:
            pass

        # 2. Bare array (model omitted the {"rules": ...} wrapper)
        bracket_match = re.search(r"\[.*\]", text, re.DOTALL)
        if bracket_match:
            try:
                arr = json.loads(bracket_match.group())
                if isinstance(arr, list) and arr:
                    return {"rules": arr}
            except json.JSONDecodeError:
                pass

        # 3. Greedy nested-brace scan — pick first dict that looks like a rule batch
        for match in re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL):
            try:
                payload = json.loads(match.group())
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and (
                "rules" in payload or "variants" in payload or isinstance(payload.get("rules"), list)
            ):
                return payload

        # 4. Widest brace match
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            try:
                payload = json.loads(brace_match.group())
                if isinstance(payload, dict):
                    return payload
            except json.JSONDecodeError:
                pass

        raise ValueError("No valid rules JSON object found in model response")

    @staticmethod
    def _repair_rule(rule: dict[str, Any]) -> dict[str, Any]:
        """
        Fill in missing optional-in-practice-but-required-by-schema fields when the
        model forgets them.  Only 'recommend' and 'remediate' are ever absent in
        practice; the other 5 keys are omitted much less frequently and will still
        surface as Stage-1 contract failures if missing.
        """
        rule = dict(rule)
        name = rule.get("name", "this detection rule")
        desc = rule.get("description", "")

        if not rule.get("recommend"):
            rule["recommend"] = (
                f"Enforce least-privilege access controls and review baseline activity for "
                f"the indicators described in '{name}'. Enable logging for the relevant "
                f"telemetry sources and set up alerting thresholds appropriate to your environment."
            )
            logger.warning("rule_repair recommend_missing rule=%r — filled with default", name)

        if not rule.get("remediate"):
            rule["remediate"] = (
                f"Investigate the flagged event for '{name}': isolate affected resources, "
                f"review recent audit logs for lateral movement or privilege escalation, "
                f"revoke any suspicious credentials or sessions, and validate that the "
                f"environment is clean before restoring normal operations."
            )
            logger.warning("rule_repair remediate_missing rule=%r — filled with default", name)

        return rule

    @staticmethod
    def _parse_rules(raw: str) -> ThreatRuleBatch:
        text = RuleEngine._strip_model_artifacts(raw)
        data = RuleEngine._extract_rules_json(text)

        if isinstance(data, list):
            rules_list = data
        elif "rules" in data:
            rules_list = data["rules"]
        elif "variants" in data:
            rules_list = data["variants"]
        else:
            raise ValueError("Response missing 'rules' array")

        # rules key may itself be a JSON string that needs a second parse
        if isinstance(rules_list, str):
            try:
                rules_list = json.loads(rules_list)
            except json.JSONDecodeError as exc:
                raise ValueError(f"'rules' value is a non-parseable string: {exc}") from exc

        if not isinstance(rules_list, list):
            raise ValueError(f"Expected a list of rules, got {type(rules_list).__name__}")

        # If the model over-generates, keep the first 3 (one per strategy layer).
        # Under-generation is a hard failure — Pydantic enforces min_length=3.
        if len(rules_list) > RULE_VARIANTS_MAX:
            logger.warning(
                "model_over_generated count=%d — truncating to %d strategy variants",
                len(rules_list),
                RULE_VARIANTS_MAX,
            )
            rules_list = rules_list[:RULE_VARIANTS_MAX]

        # Repair missing recommend/remediate before Pydantic sees the dicts
        rules_list = [
            RuleEngine._repair_rule(r) if isinstance(r, dict) else r
            for r in rules_list
        ]

        return ThreatRuleBatch(rules=rules_list)


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
