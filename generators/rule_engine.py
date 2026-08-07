import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Callable

from openai import APIConnectionError, APITimeoutError

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
from llm.observability import create_threat_trace, flush as langfuse_flush, step3_generation_span
from llm.schemas import RULE_BATCH_SCHEMA
from llm.structured_client import StructuredLLMClient

logger = logging.getLogger(__name__)

# Default path for the supplementary flat API knowledge base.
DEFAULT_API_KB_PATH = Path("data/api_knowledge_base.json")

# Maximum number of supplementary actions merged into the LOOKUP_ARRAY per threat.
# Keeps prompt size bounded while still broadening the grounded vocabulary.
_SUPPLEMENTARY_ACTION_LIMIT = 20

# Path to the GEPA-evolved system prompt (written by main_feedback.py Step 6).
# When the file exists, it supersedes the hardcoded SYSTEM_PROMPT_BASE below.
_GEPA_PROMPT_FILE = Path("data/generator_system_prompt.txt")

SYSTEM_PROMPT_BASE = """\
You are an expert detection engineer building production SIEM/detection rules for cloud, SaaS, and identity platforms.

Given a verified security threat article, generate EXACTLY 3 detection rule variants.
The array must contain EXACTLY 3 objects — no more, no fewer.

Output ONLY a valid JSON object with this exact structure (no markdown, no commentary):
{"rules": [ <rule_1>, <rule_2>, <rule_3> ]}

━━━ THREAT-CENTRIC MULTI-VARIANT STRATEGY ━━━
Each variant MUST capture a DISTINCT detection angle derived directly from the threat advisory.
Do NOT produce slight syntax variations of the same detection idea.
Do NOT force host-OS telemetry categories (process/file/network/registry) if the threat is
cloud-API, SaaS, or identity-plane focused — select the most appropriate telemetry for the threat.

  Variant 1 — PRIMARY HIGH-FIDELITY TRIGGER
    Focus: The single most direct, explicit API action or event from the LOOKUP_ARRAY
           identified in the threat advisory as the core exploitation step.
           Use ONE specific, high-signal actionName that an adversary MUST invoke to execute
           this particular attack. Minimise false positives — this is the smoking-gun signal.

  Variant 2 — BEHAVIORAL & CHAINED ACTION INDICATOR
    Focus: Two or more complementary KB actionNames that together reveal the attack chain
           (e.g., privilege change followed by token grant, credential access then lateral move,
           resource creation then data exfiltration).
           Detect adversarial behaviour patterns through correlated, sequenced events
           rather than a single atomic action.

  Variant 3 — DEFENSE-IN-DEPTH / SECONDARY VECTOR
    Focus: Peripheral administrative changes, persistent configuration mutations, or
           fallback log events from the LOOKUP_ARRAY that indicate the attacker's broader
           footprint — not the primary exploit path, but the residual evidence left behind
           (e.g., audit-log tampering, policy drift, persistence artefacts, access-key creation).

━━━ CRITICAL KB GROUNDING RULE ━━━
You MUST select actionNames EXCLUSIVELY from the LOOKUP_ARRAY provided below.
NEVER invent, abbreviate, guess, or paraphrase action strings.
NEVER use action names not explicitly present in the LOOKUP_ARRAY — this causes downstream
Stage 2 validation failure and the rule will be rejected.

━━━ SCHEMA — every rule MUST include ALL 7 keys, NO EXCEPTIONS ━━━

{
  "name":            "String — format: '[Platform]: [Actionable Indicator Title]'",
  "description":     "String — operational trigger, condition boundaries, detection logic",
  "actionNames":     ["String — exact API/event action name from LOOKUP_ARRAY ONLY"],
  "defaultSeverity": "String — exactly one of: Low, Medium, High, Critical",
  "threatType":      "String — MITRE ATT&CK Tactic name",
  "recommend":       "String — structural hardening and preventive configuration steps",
  "remediate":       "String — tactical response, containment, and post-incident validation"
}

EXAMPLE of one correctly-formed rule object:
{
  "name": "[Azure]: Unauthorized Role Assignment to Service Principal",
  "description": "Detects unexpected IAM role assignments to service principals outside approved change windows — primary indicator of privilege escalation as described in the threat advisory.",
  "actionNames": ["Microsoft.Authorization/roleAssignments/write"],
  "defaultSeverity": "High",
  "threatType": "Privilege Escalation",
  "recommend": "Enforce PIM-based just-in-time access for all service principal role assignments. Require approval workflows for privileged roles.",
  "remediate": "Immediately revoke the unauthorized role assignment. Review the assigning identity for compromise indicators. Audit all recent role changes in the subscription."
}

CRITICAL: The "recommend" and "remediate" keys are MANDATORY. Every rule object in your output MUST contain both. Rules missing either key are INVALID.

━━━ HARD RULES ━━━
- Names must include the primary platform (AWS, Azure, Okta, GCP, GitHub, etc.).
- actionNames MUST come ONLY from the LOOKUP_ARRAY — zero exceptions.
- Do NOT emit markdown fences, prose, or any text outside the JSON object.\
"""


def _load_system_prompt_base() -> str:
    """
    Return the current base system prompt for Step 3 rule generation.

    Priority order
    ──────────────
    1. GEPA-evolved file (data/generator_system_prompt.txt) — written by Step 6
       main_feedback.py whenever the GEPA engine completes a successful run.
    2. Hardcoded SYSTEM_PROMPT_BASE constant — always the safe fallback.

    This means Step 3 automatically adopts optimised prompts produced by the
    feedback loop without any manual config change.
    """
    if _GEPA_PROMPT_FILE.is_file():
        try:
            content = _GEPA_PROMPT_FILE.read_text(encoding="utf-8").strip()
            if content:
                logger.info(
                    "rule_engine_using_evolved_prompt path=%s chars=%d",
                    _GEPA_PROMPT_FILE,
                    len(content),
                )
                return content
        except OSError as exc:
            logger.warning(
                "rule_engine_evolved_prompt_load_failed path=%s error=%s — "
                "falling back to hardcoded baseline",
                _GEPA_PROMPT_FILE,
                exc,
            )
    return SYSTEM_PROMPT_BASE


def _load_api_knowledge_base(
    path: Path = DEFAULT_API_KB_PATH,
) -> dict[str, list[str]]:
    """
    Load the flat per-platform supplementary API knowledge base from
    ``data/api_knowledge_base.json``.

    Expected format::

        {
          "aws":   ["AssumeRole", "CreateUser", ...],
          "azure": ["Microsoft.Authorization/roleAssignments/write", ...],
          ...
        }

    Returns an empty dict when the file is absent or malformed, so callers
    degrade gracefully to the existing knowledge_base/ directory grounding.
    """
    if not path.is_file():
        logger.debug("api_kb_not_found path=%s — using KB-directory grounding only", path)
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            logger.warning("api_kb_invalid_format path=%s — root must be a JSON object", path)
            return {}
        result: dict[str, list[str]] = {}
        for platform, actions in data.items():
            if isinstance(actions, list):
                result[str(platform).lower()] = [
                    str(a).strip() for a in actions if isinstance(a, str) and a.strip()
                ]
        logger.info(
            "api_kb_loaded path=%s platforms=%d total_actions=%d",
            path,
            len(result),
            sum(len(v) for v in result.values()),
        )
        return result
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("api_kb_load_failed path=%s error=%s", path, exc)
        return {}


def _merge_supplementary_actions(
    grounding: GroundingResult,
    api_kb: dict[str, list[str]],
    threat_text: str,
    limit: int = _SUPPLEMENTARY_ACTION_LIMIT,
) -> list[str]:
    """
    Augment ``grounding.allowed_actions`` with platform-specific actions from
    ``api_kb``, scored by relevance to the threat text.

    Strategy
    --------
    1. Identify the primary platform from ``grounding.primary_platform``.
    2. Retrieve that platform's action list from ``api_kb`` (also checks
       closely related platform aliases).
    3. Exclude actions already present in ``grounding.allowed_actions``.
    4. Score remaining actions: actions whose token segments appear in the
       threat text rank first; others follow alphabetically.
    5. Append up to ``limit`` highest-scoring supplementary actions and
       return the combined, deduplicated list.
    """
    if not api_kb:
        return grounding.allowed_actions

    primary = (grounding.primary_platform or "").lower()
    # Try the primary platform and common aliases
    candidates: list[str] = []
    for key in (primary, primary.replace("_", ""), primary.split("_")[0]):
        if key in api_kb:
            candidates = api_kb[key]
            break
    # Also fold in any matched secondary platforms (adds cross-platform breadth)
    for matched_plat in grounding.matched_platforms:
        mlower = matched_plat.lower()
        if mlower in api_kb and mlower != primary:
            candidates = candidates + [
                a for a in api_kb[mlower] if a not in candidates
            ]

    existing: set[str] = set(grounding.allowed_actions)
    novel = [a for a in candidates if a not in existing]

    # Score by token overlap with the threat text (case-insensitive)
    lower_text = threat_text.lower()
    def _action_score(action: str) -> float:
        parts = re.split(r"[\W_./:]+", action.lower())
        return sum(1.0 for p in parts if len(p) > 3 and p in lower_text)

    novel.sort(key=lambda a: (-_action_score(a), a))
    supplementary = novel[:limit]

    if supplementary:
        logger.info(
            "api_kb_supplementary platform=%s injected=%d",
            primary, len(supplementary),
        )

    return grounding.allowed_actions + supplementary


def build_grounded_system_prompt(
    grounding: GroundingResult,
    supplementary_actions: list[str] | None = None,
) -> str:
    """
    Compose the grounded system prompt for a specific threat.

    Parameters
    ----------
    grounding:
        Result of KnowledgeBase.lookup() — contains the KB-scored allowed actions
        and platform routing metadata.
    supplementary_actions:
        Optional additional action names sourced from data/api_knowledge_base.json,
        already merged and deduplicated by _merge_supplementary_actions().
        When provided, these are injected into the LOOKUP_ARRAY alongside the
        KB-scored actions so the model has a broader, platform-verified vocabulary.
    """
    # Use the merged action list if supplementary actions were provided; otherwise
    # fall back to the KB-scored list.
    all_actions = supplementary_actions if supplementary_actions is not None else grounding.allowed_actions
    platform = grounding.primary_platform or "cloud"

    # Use GEPA-evolved prompt when available; fall back to hardcoded baseline.
    base = _load_system_prompt_base()

    if grounding.primary_platform == "github":
        env_line = (
            "\n\nENVIRONMENT: You are generating rules for a GitHub environment "
            "(Actions workflows and/or organization audit logs)."
        )
        forbid = (
            "\nYou are strictly forbidden from inventing fake event paths or action strings. "
            "You MUST select actionNames EXCLUSIVELY from strings present in the LOOKUP_ARRAY "
            "below — failure to do so causes Stage 2 validation rejection."
        )
    elif grounding.primary_platform == "okta" or "okta" in grounding.matched_platforms:
        env_line = (
            "\n\nENVIRONMENT: You are generating rules for an Okta Enterprise Directory "
            "system environment (System Log event types)."
        )
        forbid = (
            "\nYou are strictly forbidden from inventing or guessing Okta event type strings. "
            "You MUST select actionNames EXCLUSIVELY from strings present in the LOOKUP_ARRAY "
            "below — failure to do so causes Stage 2 validation rejection."
        )
    elif grounding.primary_platform == "azure" or "azure" in grounding.matched_platforms:
        env_line = (
            "\n\nENVIRONMENT: You are generating rules for an Azure Resource Manager (ARM) "
            "environment (ARM operations and/or Entra ID audit activities)."
        )
        forbid = (
            "\nYou are strictly forbidden from inventing Azure permission namespaces or "
            "guessing slash/period paths. You MUST select actionNames EXCLUSIVELY from strings "
            "present in the LOOKUP_ARRAY below — failure to do so causes Stage 2 validation rejection."
        )
    elif grounding.primary_platform == "aws" or "aws" in grounding.matched_platforms:
        env_line = (
            "\n\nENVIRONMENT: You are generating rules for an AWS CloudTrail / IAM environment."
        )
        forbid = (
            "\nYou are strictly forbidden from inventing AWS API action names. "
            "You MUST select actionNames EXCLUSIVELY from strings present in the LOOKUP_ARRAY "
            "below — failure to do so causes Stage 2 validation rejection."
        )
    else:
        env_line = f"\n\nENVIRONMENT: You are generating rules for a {platform} environment."
        forbid = (
            "\nYou are strictly forbidden from creating or guessing event names. "
            "You MUST select actionNames EXCLUSIVELY from strings present in the LOOKUP_ARRAY "
            "below — failure to do so causes Stage 2 validation rejection."
        )

    if not all_actions:
        vocab_block = (
            "\n\nSTRICT ALLOWED VOCABULARY (LOOKUP_ARRAY):\n"
            "[No verified action names retrieved — do not invent API/event names.]"
        )
    else:
        vocab_json = json.dumps(all_actions, indent=2)
        vocab_block = (
            f"\n\nSTRICT ALLOWED VOCABULARY (LOOKUP_ARRAY — verified authoritative catalog):\n"
            f"{vocab_json}"
        )

    profile_note = ""
    if grounding.routed_profiles:
        profile_note = f"\nRouted catalog profiles: {', '.join(grounding.routed_profiles)}."

    return base + env_line + profile_note + vocab_block + forbid


class RuleEngine:
    """
    phi4-mini-reasoning rule generation with KB-grounded actionNames.

    Generates exactly 3 threat-centric detection rule variants per threat:
      Variant 1 — Primary High-Fidelity Trigger
                  Single most direct API action identified in the threat advisory.
      Variant 2 — Behavioral & Chained Action Indicator
                  Two or more correlated KB actions that reveal the attack chain.
      Variant 3 — Defense-in-Depth / Secondary Vector
                  Peripheral administrative changes or residual attacker footprint.

    actionNames grounding
    ─────────────────────
    All generated actionNames are constrained to a LOOKUP_ARRAY built from:
      1. knowledge_base/ directory catalogs (KB-scored, threat-relevant actions).
      2. data/api_knowledge_base.json (supplementary flat per-platform map, loaded
         once at startup and merged per-threat up to _SUPPLEMENTARY_ACTION_LIMIT).

    LLM routing
    ───────────
    Routes completions through StructuredLLMClient:
      • OpenAI cloud  → strict JSON schema (RULE_BATCH_SCHEMA), no post-repair needed.
      • Local Ollama  → json_object mode + 5-level fallback parser + repair.
    """

    def __init__(
        self,
        knowledge_base: KnowledgeBase,
        base_url: str = OLLAMA_BASE_URL,
        model: str = OLLAMA_PHI4_MODEL,
        timeout_seconds: float = OLLAMA_PHI4_TIMEOUT_SECONDS,
        api_kb_path: Path | None = None,
    ) -> None:
        self._kb = knowledge_base
        self._model = model
        self._llm = StructuredLLMClient(
            base_url=base_url,
            model=model,
            api_key="ollama",
            timeout=timeout_seconds,
        )
        # Supplementary flat API knowledge base (data/api_knowledge_base.json).
        # Loaded once here; merged per-threat in generate_for_threat.
        _kb_path = api_kb_path if api_kb_path is not None else DEFAULT_API_KB_PATH
        self._api_kb: dict[str, list[str]] = _load_api_knowledge_base(_kb_path)

    def ground_threat(self, threat: dict[str, Any]) -> GroundingResult:
        text = f"{threat.get('title', '')}\n{threat.get('content', '')}"
        return self._kb.lookup(text)

    def generate_for_threat(
        self,
        threat: dict[str, Any],
        grounding: GroundingResult | None = None,
        parent_observation: Any = None,
    ) -> tuple[list[DetectionRule], str | None, GroundingResult]:
        grounding = grounding or self.ground_threat(threat)

        # Merge supplementary API KB actions into the grounded vocabulary.
        # The combined list is what the LLM sees in the LOOKUP_ARRAY.
        threat_text = f"{threat.get('title', '')}\n{threat.get('content', '')}"
        merged_actions = _merge_supplementary_actions(
            grounding, self._api_kb, threat_text
        )

        system_prompt = build_grounded_system_prompt(
            grounding, supplementary_actions=merged_actions
        )
        messages: list[dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": self._build_user_prompt(threat, grounding)},
        ]

        try:
            raw_dict = self._llm.generate_structured_output(
                messages,
                RULE_BATCH_SCHEMA,
                "detection_rule_batch",
                temperature=0.3,
                parent_observation=parent_observation,  # Langfuse span A linkage
            )
            batch = self._parse_rules(raw_dict)
            return batch.rules, None, grounding
        except (APIConnectionError, APITimeoutError, ConnectionError, TimeoutError) as exc:
            msg = f"phi4-mini-reasoning offline or timeout: {exc}"
            logger.error("reasoning_model_timeout threat=%s error=%s", threat.get("title"), exc)
            return [], msg, grounding
        except Exception as exc:
            msg = f"Generation failed: {exc}"
            logger.error(
                "reasoning_model_generation_failed threat=%s error=%s",
                threat.get("title"),
                exc,
            )
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

            # ── Langfuse: root trace + Span A ──────────────────────────────
            lf_trace = create_threat_trace(
                tid, title,
                metadata={
                    "source": threat.get("source"),
                    "url":    threat.get("url"),
                    "gemma_score": (threat.get("gemma_verdict") or {}).get("confidence_score"),
                },
            )
            lf_trace_id: str | None = (
                f"threat-{tid}" if lf_trace is not None else None
            )

            started = time.perf_counter()
            with step3_generation_span(lf_trace, threat) as span_a:
                rules, error, grounding = self.generate_for_threat(
                    threat, grounding=grounding, parent_observation=span_a
                )
                # Update span output before the context manager closes it
                if span_a is not None:
                    try:
                        span_a.update(output={
                            "rules_generated": len(rules),
                            "status":          "success" if rules and not error else "failed",
                            "error":           error,
                        })
                    except Exception:
                        pass
            elapsed = time.perf_counter() - started

            entry = build_staging_entry(threat, rules, error, grounding=grounding)
            # Persist trace_id so Step 4 (validator) and Step 5 (triage)
            # can attach Span B and feedback scores to the same root trace.
            entry["langfuse_trace_id"] = lf_trace_id
            produced.append(entry)

            if on_after:
                on_after(index, total, threat, entry, elapsed)

        # Flush buffered Langfuse events before the process exits
        langfuse_flush()
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
            f"REMINDER — output exactly 3 threat-centric variants:\n"
            f"  [1] PRIMARY HIGH-FIDELITY TRIGGER\n"
            f"      — single most direct API action from the LOOKUP_ARRAY for this specific threat\n"
            f"  [2] BEHAVIORAL & CHAINED ACTION INDICATOR\n"
            f"      — 2+ correlated KB actions that together reveal the attack chain\n"
            f"  [3] DEFENSE-IN-DEPTH / SECONDARY VECTOR\n"
            f"      — peripheral changes or residual attacker footprint from the LOOKUP_ARRAY\n\n"
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
    def _parse_rules(raw: str | dict[str, Any]) -> ThreatRuleBatch:
        """
        Parse a rules payload from either a raw model string or a pre-parsed dict.

        When called with a dict (cloud path or StructuredLLMClient Ollama path),
        the artifact-stripping and JSON-extraction steps are skipped — the dict
        is used directly.  All downstream repair and Pydantic validation still run.

        When called with a string (legacy / direct Ollama text path), the full
        5-level fallback chain is applied before Pydantic validation.
        """
        if isinstance(raw, dict):
            data = raw
        else:
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
