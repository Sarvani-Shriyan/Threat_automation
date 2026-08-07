#!/usr/bin/env python3
"""
Step 4: Deterministic rule validation pipeline.

Stage 1  — Python contract enforcement (7-key schema, non-empty fields, severity enum)
Stage 2  — Knowledge base action-name lookup (case-insensitive match; loads both
            knowledge_base/ catalogs and data/api_knowledge_base.json supplementary KB)
Stage 3  — phi4-mini-reasoning cognitive audit (Sherman Kent CTI discipline;
            cloud/NHI/AI-aware — no host OS penalty for API-focused rules;
            evaluates Telemetry Storm Risk and Analytic Leap Risk explicitly)

Single write-back: data/generated_rules_staging.json is read once; the fully annotated
result is written to data/validated_rules.json only after every entry/variant finishes.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from llm.observability import flush as langfuse_flush, step4_validation_span

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_STAGING_INPUT = Path("data/generated_rules_staging.json")
DEFAULT_VALIDATED_OUTPUT = Path("data/validated_rules.json")
KB_DIR = Path("knowledge_base")
# Supplementary API knowledge base created during Step 3 grounding.
API_KB_PATH = Path("data/api_knowledge_base.json")

# The 7 mandatory contract keys every rule variant must contain, non-empty.
REQUIRED_RULE_KEYS: tuple[str, ...] = (
    "name",
    "description",
    "actionNames",
    "defaultSeverity",
    "threatType",
    "recommend",
    "remediate",
)

VALID_SEVERITIES: frozenset[str] = frozenset({"None", "Low", "Medium", "High", "Critical"})

# Raw files that are upstream sources, not curated action catalogs — skip them.
_KB_RAW_SUFFIXES = (".raw.json",)

# ---------------------------------------------------------------------------
# Stage 3 — phi4-mini-reasoning Ollama config (mirrors ingestion/config.py)
# ---------------------------------------------------------------------------

# Override via environment variables for Docker / host-bridge setups.
import os as _os  # noqa: E402  (inline import keeps config block self-contained)

STAGE3_OLLAMA_BASE_URL: str = _os.environ.get(
    "OLLAMA_BASE_URL", "http://localhost:11434/v1"
)
STAGE3_OLLAMA_MODEL: str = _os.environ.get("OLLAMA_PHI4_MODEL", "phi4-mini-reasoning")
STAGE3_TIMEOUT_SECONDS: float = float(_os.environ.get("STAGE3_TIMEOUT_SECONDS", "300"))

# Lazy singleton — created on first Stage 3 call so tests can import this
# module without triggering an OpenAI client instantiation.
_STAGE3_CLIENT: "StructuredLLMClient | None" = None  # type: ignore[name-defined]

# ---------------------------------------------------------------------------
# Stage 3 — Sherman Kent CTI system prompt (exact, word-for-word)
# ---------------------------------------------------------------------------

STAGE3_SYSTEM_PROMPT: str = """\
You are an expert Cyber Threat Intelligence (CTI) Analyst and Detection Engineering Auditor trained rigorously in Sherman Kent's analytic discipline. Your goal is to audit a proposed detection rule against its source threat data and produce a disciplined, transparent intelligence assessment.

You must strictly separate hard evidence from analytical assumptions.

---

### STEP 0: THREAT CONTEXT CLASSIFICATION
Before scoring, classify the threat context from the input data:
- **Cloud/API Threat**: The threat exploits cloud service APIs, IAM, SaaS platforms, or cloud-native resources (AWS, Azure, GCP, Okta, GitHub).
- **NHI Threat**: The threat targets Non-Human Identities — service accounts, service principals, workload identities, machine identities, OAuth apps, or automated pipelines.
- **AI Agent Threat**: The threat exploits AI agents, LLM systems, MCP vulnerabilities, prompt injection, or autonomous AI pipelines.
- **Host OS Threat**: The threat involves host operating system artefacts — process trees, file system modifications, Windows Registry changes, or local endpoint telemetry.

> **CRITICAL AUDIT RULE**: If the threat context is Cloud/API, NHI, or AI Agent, do NOT penalize the detection rule for lacking host OS file/registry/process telemetry conditions. Cloud-native and NHI-focused rules are expected to target API log events and cloud control plane actions, NOT endpoint artefacts. Penalizing a cloud rule for missing Windows Registry checks is an analytic error.

---

### STEP 1: RISK EVALUATION MATRIX
Evaluate the rule against exactly these two risk dimensions:

#### Telemetry Storm Risk (Signal-to-Noise)
Does the detection rule risk generating excessive false-positive alerts?
- **High Storm Risk**: The actionNames are too broad (e.g., generic read/list operations triggered by normal operations). The rule would fire on hundreds of benign events per day.
- **Medium Storm Risk**: The actionNames are moderately specific but could fire in common administrative scenarios without additional context filters.
- **Low Storm Risk**: The actionNames directly correspond to the exact attack technique described in the threat data. Benign triggers are rare or require anomalous combinations.

#### Analytic Leap Risk (Assumption Gap)
Does the detection rule make logical leaps not supported by the threat text or API log evidence?
- **High Leap Risk**: The rule assumes attacker behaviour, tooling, or sequences that are not described or inferable from the source threat advisory.
- **Medium Leap Risk**: The rule extrapolates plausible but unconfirmed behaviour from the threat description.
- **Low Leap Risk**: Every actionName in the rule maps directly to an explicit API call, log event, or technique described in the threat advisory.

---

### STEP 2: ANALYTICAL DEFINITIONS
When writing the report, strictly adhere to these definitions:

#### Estimative Probability Scale (How likely this detection fires on the real attack)
- Almost Certain: 90%–99% chance
- Highly Likely / Probable: 60%–85% chance
- Likely / Possible: 35%–55% chance
- Unlikely: 10%–30% chance
- Remote / Highly Unlikely: Less than 10% chance

#### Confidence Levels (Strength of the evidence backing the rule)
- High Confidence: Rule actionNames map directly to verified, first-hand API calls or log events described in the threat advisory.
- Medium Confidence: Rule is based on plausible third-party reporting but lacks direct API log confirmation.
- Low Confidence: Rule is based on fragmented, unverified, or highly perishable data.

---

### STEP 3: PROCEDURAL WORKFLOW
1. Classify the threat context (Cloud/API, NHI, AI Agent, or Host OS).
2. Evaluate Telemetry Storm Risk and Analytic Leap Risk using the matrix above.
3. Categorize each technical indicator as: Source-observed, Reported, or Inferred.
4. Brainstorm at least one alternative hypothesis or detection gap.
5. Identify collection gaps — what telemetry is missing.

---

### REPORT FORMAT
Output the report using this exact structure:

## 1. Executive Summary
(Brief overview using precise probability language. State the threat context classification.)

## 2. Technical Observations & Evidence Categorization
(Bullet points of actionNames, API events, or behaviors categorized as Source-observed / Reported / Inferred)

## 3. Core Analysis & Assessment
- Threat Context: (Cloud/API | NHI | AI Agent | Host OS)
- Telemetry Storm Risk: (High / Medium / Low — with one-sentence justification)
- Analytic Leap Risk: (High / Medium / Low — with one-sentence justification)
- Primary Hypothesis: (What this rule is designed to detect)
- Probability Assessment: (Choose from Step 2 scale)
- Confidence Assessment & Justification: (Choose from Step 2 scale and justify)

## 4. Alternative Hypotheses
(Alternative explanations or gaps — e.g., attacker could achieve same goal via a different API action not covered by this rule)

## 5. Collection Gaps
(What data or telemetry is missing that would increase detection fidelity?)\
"""

# Safe fallback emitted when Ollama is unreachable or returns an unusable response.
_STAGE3_FALLBACK: dict[str, Any] = {
    "is_valid": False,
    "kent_probability_tag": "Unknown",
    "audit_rationale": "Stage 3 audit unavailable — Ollama offline or response parse failed.",
    "full_report": None,
    "model": STAGE3_OLLAMA_MODEL,
    "model_error": None,
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("main_validator")

# ---------------------------------------------------------------------------
# Stage 3 — phi4-mini-reasoning cognitive audit (Sherman Kent CTI discipline)
# ---------------------------------------------------------------------------

# Ordered so compound / more-specific phrases are checked before their substrings.
# e.g. "Highly Likely" before "Likely", "Highly Unlikely" before "Unlikely".
_KENT_TAGS: list[str] = [
    "Almost Certain",
    "Highly Likely",
    "Highly Unlikely",
    "Probable",
    "Unlikely",
    "Likely",
    "Possible",
    "Remote",
]
_KENT_PATTERN: re.Pattern[str] = re.compile(
    r"Probability Assessment[:\s]+([^\n]+)", re.IGNORECASE
)


def _strip_thinking_tags(text: str) -> str:
    """Remove phi4-mini-reasoning <thinking>…</thinking> chain-of-thought blocks."""
    text = re.sub(r"<thinking>.*?</thinking>", "", text, flags=re.DOTALL | re.IGNORECASE)
    # Also strip stray opening/closing thinking tags left by truncated output.
    text = re.sub(r"</?thinking>", "", text, flags=re.IGNORECASE)
    return text.strip()


def _extract_kent_tag(report: str) -> str:
    """
    Parse the 'Probability Assessment' line from the model's CTI report and
    return the matching Sherman Kent tag, or 'Unknown' if none is found.

    Uses whole-word regex matching so that "Likely" cannot accidentally match
    inside "Unlikely" or "Highly Likely".  Tags are checked in priority order
    (most specific / highest confidence first) to prevent shorter tags from
    shadowing longer compound ones.
    """
    def _word_match(tag: str, text: str) -> bool:
        return bool(re.search(r"\b" + re.escape(tag) + r"\b", text, re.IGNORECASE))

    match = _KENT_PATTERN.search(report)
    if match:
        assessment_line = match.group(1)
        for tag in _KENT_TAGS:
            if _word_match(tag, assessment_line):
                return tag
    # Fallback: scan the full report for any recognised tag
    for tag in _KENT_TAGS:
        if _word_match(tag, report):
            return tag
    return "Unknown"


def _extract_executive_summary(report: str) -> str:
    """
    Pull the text under '## 1. Executive Summary' as a compact audit_rationale.
    Falls back to the first 400 chars of the report if the section is absent.
    """
    match = re.search(
        r"##\s*1\.\s*Executive Summary\s*\n(.*?)(?=\n##|\Z)",
        report,
        re.DOTALL | re.IGNORECASE,
    )
    if match:
        return match.group(1).strip()[:600]
    return report[:400].strip()


def _get_stage3_client() -> "StructuredLLMClient":
    """
    Lazy singleton that creates the StructuredLLMClient once per process.

    Using a singleton avoids re-constructing the OpenAI client on every
    rule variant while still supporting tests that mock _call_ollama_sync
    at the function level without needing a client at all.
    """
    global _STAGE3_CLIENT
    if _STAGE3_CLIENT is None:
        from llm.structured_client import StructuredLLMClient  # noqa: PLC0415

        _STAGE3_CLIENT = StructuredLLMClient(
            base_url=STAGE3_OLLAMA_BASE_URL,
            model=STAGE3_OLLAMA_MODEL,
            api_key="ollama",
            timeout=STAGE3_TIMEOUT_SECONDS,
        )
    return _STAGE3_CLIENT  # type: ignore[return-value]


def _call_ollama_sync(rule_data: dict[str, Any], lf_span: Any = None) -> dict[str, Any]:
    """
    Synchronous Stage 3 cognitive audit call — run via asyncio.to_thread().

    Hybrid routing
    ──────────────
    OpenAI cloud endpoint
        generate_structured_output() with KENT_AUDIT_SCHEMA enforces the
        three-key JSON contract server-side.  The kent_probability_tag,
        audit_rationale, and full_report values arrive pre-validated.

    Local Ollama / LiteLLM endpoint
        generate_text() returns the free-form 5-section markdown CTI report.
        The existing _strip_thinking_tags → _extract_kent_tag →
        _extract_executive_summary regex pipeline populates the three keys,
        exactly as before this refactor.

    The system prompt (STAGE3_SYSTEM_PROMPT) and all regex helpers are
    completely unchanged regardless of the routing path taken.
    """
    from openai import APIConnectionError, APITimeoutError  # noqa: PLC0415
    from llm.schemas import KENT_AUDIT_SCHEMA  # noqa: PLC0415

    user_prompt = f"### SOURCE DATA TO ANALYZE:\n{json.dumps(rule_data, indent=2)}"
    messages: list[dict[str, str]] = [
        {"role": "system", "content": STAGE3_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    try:
        client = _get_stage3_client()

        if client.is_cloud:
            # ── OpenAI cloud: strict JSON schema, keys delivered directly ──
            raw_dict = client.generate_structured_output(
                messages, KENT_AUDIT_SCHEMA, "kent_audit",
                temperature=0.2,
                parent_observation=lf_span,      # Langfuse Span B linkage
            )
            kent_tag = raw_dict.get("kent_probability_tag") or "Unknown"
            rationale = (raw_dict.get("audit_rationale") or "")[:600]
            full_report = raw_dict.get("full_report") or ""
            if not full_report:
                logger.warning(
                    "stage3_cloud_empty_report model=%s", STAGE3_OLLAMA_MODEL
                )
                return {
                    **_STAGE3_FALLBACK,
                    "model_error": "Cloud model returned empty full_report",
                }
        else:
            # ── Local Ollama: free-form CTI report → regex extraction ──
            raw = client.generate_text(
                messages, temperature=0.2, parent_observation=lf_span
            )
            full_report = _strip_thinking_tags(raw)
            if not full_report:
                logger.warning(
                    "stage3_empty_response model=%s", STAGE3_OLLAMA_MODEL
                )
                return {
                    **_STAGE3_FALLBACK,
                    "model_error": "Model returned empty response after stripping",
                }
            kent_tag = _extract_kent_tag(full_report)
            rationale = _extract_executive_summary(full_report)

    except (APIConnectionError, APITimeoutError, ConnectionError, TimeoutError) as exc:
        logger.error("stage3_ollama_timeout model=%s error=%s", STAGE3_OLLAMA_MODEL, exc)
        return {**_STAGE3_FALLBACK, "model_error": f"Ollama timeout/connection: {exc}"}
    except Exception as exc:
        logger.error("stage3_ollama_error model=%s error=%s", STAGE3_OLLAMA_MODEL, exc)
        return {**_STAGE3_FALLBACK, "model_error": f"Stage 3 call failed: {exc}"}

    logger.info(
        "stage3_audit_complete model=%s provider=%s kent_tag=%r rationale_len=%d",
        STAGE3_OLLAMA_MODEL,
        "cloud" if client.is_cloud else "local",
        kent_tag,
        len(rationale),
    )
    return {
        "is_valid": True,
        "kent_probability_tag": kent_tag,
        "audit_rationale": rationale,
        "full_report": full_report,
        "model": STAGE3_OLLAMA_MODEL,
        "model_error": None,
    }


async def run_stage3_cognitive_audit(
    rule_data: dict[str, Any],
    lf_span: Any = None,
) -> dict[str, Any]:
    """
    phi4-mini-reasoning cognitive audit using Sherman Kent's CTI analytic discipline.

    Runs the blocking Ollama call in a thread pool so the asyncio event loop
    remains free to process other variants concurrently.  `lf_span` is forwarded
    to `_call_ollama_sync` so the generation is linked to Step 4's Langfuse span.
    """
    return await asyncio.to_thread(_call_ollama_sync, rule_data, lf_span)


# ---------------------------------------------------------------------------
# Knowledge base loader
# ---------------------------------------------------------------------------


def load_kb_action_set(
    kb_dir: Path = KB_DIR,
    api_kb_path: Path = API_KB_PATH,
) -> frozenset[str]:
    """
    Walk every JSON file under kb_dir and also read data/api_knowledge_base.json,
    collecting all authoritative actionNames into a single flat frozenset for O(1)
    lookup.

    Case normalisation
    ------------------
    All actions are stored **lower-cased** so that Stage 2 matching is
    case-insensitive.  The LLM may capitalise API actions inconsistently
    ("assumeRole" vs "AssumeRole"), and a failed lookup for a legitimately
    grounded action should never block an otherwise valid rule.

    Raw upstream dumps (*.raw.json) are excluded — they are source artifacts,
    not the curated catalog format.
    """
    actions: set[str] = set()
    loaded_files: list[str] = []
    skipped_files: list[str] = []

    # ── Directory KB (knowledge_base/*.json) ──────────────────────────────
    for json_path in sorted(kb_dir.rglob("*.json")):
        name = json_path.name
        if any(name.endswith(suffix) for suffix in _KB_RAW_SUFFIXES):
            skipped_files.append(name)
            continue
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("kb_load_failed file=%s error=%s", name, exc)
            continue
        if not isinstance(payload, dict):
            continue
        raw_actions = payload.get("actionNames")
        if isinstance(raw_actions, list):
            count_before = len(actions)
            actions.update(str(a).lower() for a in raw_actions if a)
            loaded_files.append(f"{name}(+{len(actions) - count_before})")

    # ── Supplementary API KB (data/api_knowledge_base.json) ───────────────
    # Format: {"aws": [...], "azure": [...], "nhi": [...], "ai_agent": [...], …}
    if api_kb_path.is_file():
        try:
            api_payload = json.loads(api_kb_path.read_text(encoding="utf-8"))
            if isinstance(api_payload, dict):
                api_count = 0
                for platform, acts in api_payload.items():
                    if isinstance(acts, list):
                        for a in acts:
                            if a:
                                actions.add(str(a).lower())
                                api_count += 1
                loaded_files.append(f"api_knowledge_base.json(+{api_count})")
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("api_kb_load_failed path=%s error=%s", api_kb_path, exc)
    else:
        logger.debug("api_kb_not_found path=%s — skipping supplementary KB", api_kb_path)

    logger.info(
        "kb_loaded total_actions=%d files=%d skipped=%d",
        len(actions),
        len(loaded_files),
        len(skipped_files),
    )
    return frozenset(actions)


# ---------------------------------------------------------------------------
# Stage 1 — Contract enforcement
# ---------------------------------------------------------------------------


def run_stage1_contract(rule: dict[str, Any]) -> list[str]:
    """
    Verify all 7 mandatory keys are present and non-empty.
    Returns a list of human-readable violation strings (empty = pass).
    """
    violations: list[str] = []

    for key in REQUIRED_RULE_KEYS:
        value = rule.get(key)
        if value is None:
            violations.append(f"missing required key: '{key}'")
            continue
        if isinstance(value, str) and not value.strip():
            violations.append(f"empty string for required key: '{key}'")
        elif isinstance(value, list) and len(value) == 0:
            violations.append(f"empty list for required key: '{key}'")

    # Explicit severity checks: word-characters-only first, then enum membership.
    severity = rule.get("defaultSeverity", "")
    if severity:
        if not re.fullmatch(r"[A-Za-z]+", severity):
            violations.append(
                f"invalid defaultSeverity '{severity}' — must be a pure word string "
                f"(no digits, decimals, or punctuation); allowed: {sorted(VALID_SEVERITIES)}"
            )
        elif severity not in VALID_SEVERITIES:
            violations.append(
                f"invalid defaultSeverity '{severity}' — must be one of "
                f"{sorted(VALID_SEVERITIES)}"
            )

    return violations


# ---------------------------------------------------------------------------
# Stage 2 — Knowledge base lookup
# ---------------------------------------------------------------------------


def run_stage2_kb_lookup(
    rule: dict[str, Any],
    kb_actions: frozenset[str],
) -> list[str]:
    """
    Cross-reference every actionName in the rule against the full KB action set.

    Matching is **case-insensitive**: both the KB (built by load_kb_action_set)
    and each rule action are normalised to lowercase before comparison.  This
    means a rule using "AssumeRole", "assumerole", or "ASSUMEROLE" all pass if
    the KB contains any casing of that action.

    Multi-action behavioral chains (e.g. Variant 2) are validated action-by-action
    — every member of actionNames must exist in the KB.

    Returns a list of violation strings for actions not found (empty list = pass).
    """
    rule_actions: list[str] = rule.get("actionNames") or []
    violations: list[str] = []

    for action in rule_actions:
        if not isinstance(action, str) or not action.strip():
            violations.append(f"actionName is blank or non-string: {action!r}")
            continue
        if action.lower() not in kb_actions:
            violations.append(
                f"actionName '{action}' not found in knowledge base catalogs"
            )

    return violations


# ---------------------------------------------------------------------------
# Per-variant validation runner
# ---------------------------------------------------------------------------


async def validate_variant(
    variant: dict[str, Any],
    variant_index: int,
    threat_title: str,
    kb_actions: frozenset[str],
    *,
    lf_span: Any = None,
) -> dict[str, Any]:
    """
    Run a single rule variant through all three stages.
    Returns the variant dict with a 'validation' sub-object appended.
    """
    rule_name = variant.get("name", f"variant_{variant_index}")
    result = dict(variant)  # shallow copy; we append 'validation' key

    # -- Stage 1 --
    s1_errors = run_stage1_contract(variant)
    if s1_errors:
        result["validation"] = {
            "stage": "failed_stage_1",
            "errors": s1_errors,
            "stage3_audit": None,
        }
        for err in s1_errors:
            logger.warning(
                "stage1_fail threat=%r variant=%d rule=%r error=%r",
                threat_title,
                variant_index,
                rule_name,
                err,
            )
        return result

    # -- Stage 2 --
    s2_errors = run_stage2_kb_lookup(variant, kb_actions)
    if s2_errors:
        result["validation"] = {
            "stage": "failed_stage_2",
            "errors": s2_errors,
            "stage3_audit": None,
        }
        for err in s2_errors:
            logger.warning(
                "stage2_fail threat=%r variant=%d rule=%r error=%r",
                threat_title,
                variant_index,
                rule_name,
                err,
            )
        return result

    # -- Stage 3 — phi4-mini-reasoning cognitive audit --
    audit = await run_stage3_cognitive_audit(variant, lf_span=lf_span)

    result["validation"] = {
        "stage": "passed",
        "errors": [],
        "stage3_audit": audit,
    }
    logger.info(
        "stage3_pass threat=%r variant=%d rule=%r kent_tag=%r",
        threat_title,
        variant_index,
        rule_name,
        audit.get("kent_probability_tag"),
    )
    return result


# ---------------------------------------------------------------------------
# Per-entry runner
# ---------------------------------------------------------------------------


async def validate_entry(
    entry: dict[str, Any],
    kb_actions: frozenset[str],
) -> dict[str, Any]:
    """
    Validate all variants inside one staging entry.

    Opens Langfuse Span B (step4-kent-cognitive-audit) attached to the root
    trace that was created by Step 3 (identified via `langfuse_trace_id`).
    Updates the span output with aggregated is_valid and kent_probability_tag
    values from all variants before closing.
    """
    title    = entry.get("threat_title", "unknown")
    trace_id = entry.get("langfuse_trace_id")
    raw_variants: list[dict[str, Any]] = entry.get("variants") or []

    with step4_validation_span(trace_id, entry) as span_b:
        validated_variants = await asyncio.gather(
            *[
                validate_variant(v, idx, title, kb_actions, lf_span=span_b)
                for idx, v in enumerate(raw_variants)
            ]
        )

        # Update Span B with aggregated validation outcomes
        if span_b is not None:
            try:
                kent_tags = [
                    v.get("validation", {}).get("stage3_audit", {}).get("kent_probability_tag")
                    for v in validated_variants
                    if (v.get("validation", {}).get("stage") == "passed"
                        and v.get("validation", {}).get("stage3_audit"))
                ]
                passed_count  = sum(
                    1 for v in validated_variants
                    if v.get("validation", {}).get("stage") == "passed"
                )
                s1_fail_count = sum(
                    1 for v in validated_variants
                    if v.get("validation", {}).get("stage") == "failed_stage_1"
                )
                s2_fail_count = sum(
                    1 for v in validated_variants
                    if v.get("validation", {}).get("stage") == "failed_stage_2"
                )
                span_b.update(output={
                    "variants_total":   len(validated_variants),
                    "variants_passed":  passed_count,
                    "failed_stage_1":   s1_fail_count,
                    "failed_stage_2":   s2_fail_count,
                    "kent_tags":        [t for t in kent_tags if t],
                    "triage_ready":     passed_count > 0,
                })
            except Exception:
                pass

    annotated = dict(entry)
    annotated["variants"] = list(validated_variants)
    return annotated


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


async def run_validation(
    staging_path: Path = DEFAULT_STAGING_INPUT,
    output_path: Path = DEFAULT_VALIDATED_OUTPUT,
    *,
    limit: int | None = None,
) -> int:
    # --- Load KB (once) ---
    if not KB_DIR.exists():
        logger.error("kb_dir_missing path=%s", KB_DIR)
        return 1

    logger.info("Loading knowledge base from %s …", KB_DIR)
    kb_actions = load_kb_action_set(KB_DIR, API_KB_PATH)

    # --- Load staging file (once) ---
    if not staging_path.is_file():
        logger.error("staging_file_missing path=%s", staging_path)
        return 1

    try:
        staging = json.loads(staging_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("staging_load_failed error=%s", exc)
        return 1

    entries: list[dict[str, Any]] = staging.get("entries", [])
    if limit is not None:
        entries = entries[:limit]

    total_entries = len(entries)
    logger.info("Validating %d staging entries …", total_entries)

    started = time.perf_counter()

    # --- Validate all entries asynchronously ---
    validated_entries = await asyncio.gather(
        *[validate_entry(e, kb_actions) for e in entries]
    )

    elapsed = time.perf_counter() - started

    # --- Compile statistics ---
    stats: dict[str, int] = {
        "passed": 0,
        "failed_stage_1": 0,
        "failed_stage_2": 0,
        "total_variants": 0,
    }
    # Per-threat counters for the clearer summary banner
    threats_with_variants = 0
    threats_zero_variants = 0
    threats_triage_ready = 0  # ≥1 passing variant → visible in triage dashboard

    for entry in validated_entries:
        variants = entry.get("variants", [])
        if not variants:
            threats_zero_variants += 1
            continue
        threats_with_variants += 1
        entry_passed = 0
        for variant in variants:
            stats["total_variants"] += 1
            stage = variant.get("validation", {}).get("stage", "unknown")
            if stage == "passed":
                stats["passed"] += 1
                entry_passed += 1
            elif stage == "failed_stage_1":
                stats["failed_stage_1"] += 1
            elif stage == "failed_stage_2":
                stats["failed_stage_2"] += 1
        if entry_passed > 0:
            threats_triage_ready += 1

    # --- Single write-back (only once, after all processing) ---
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "source_staging_file": str(staging_path),
        "elapsed_seconds": round(elapsed, 2),
        "kb_action_count": len(kb_actions),
        "threat_count": len(validated_entries),
        "threats_triage_ready": threats_triage_ready,
        "stats": stats,
        "entries": list(validated_entries),
    }
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    # --- Summary banner ---
    total = stats["total_variants"]
    passed = stats["passed"]
    s1_fail = stats["failed_stage_1"]
    s2_fail = stats["failed_stage_2"]

    print("\n" + "=" * 60)
    print("STEP 4 — VALIDATION REPORT")
    print("=" * 60)
    print(f"Staging file              : {staging_path}")
    print(f"KB directory              : {KB_DIR}")
    print(f"Supplementary API KB      : {API_KB_PATH}{'' if API_KB_PATH.is_file() else ' (not found — skipped)'}")
    print(f"KB actions loaded         : {len(kb_actions):,}")
    print()
    print(f"Staging entries processed : {len(validated_entries)}")
    print(f"  With variants           : {threats_with_variants}")
    print(f"  No variants (gen failed): {threats_zero_variants}  ← re-run Step 3 to fix")
    print()
    print(f"Rule VARIANTS validated   : {total}")
    print(f"  Passed all 3 stages     : {passed}  variants")
    print(f"  Failed Stage 1 (schema) : {s1_fail}  variants")
    print(f"  Failed Stage 2 (KB)     : {s2_fail}  variants")
    if total:
        print(f"  Variant pass rate       : {passed / total * 100:.1f}%")
    print()
    print(f"Threats ready for triage  : {threats_triage_ready}  (≥1 passing variant)")
    print(f"  → open app_triage.py to review these {threats_triage_ready} threat(s)")
    print()
    print(f"Stage 3 model             : {STAGE3_OLLAMA_MODEL} @ {STAGE3_OLLAMA_BASE_URL}")
    print(f"Elapsed                   : {elapsed:.1f}s")
    print(f"Output                    : {output_path}")
    print("=" * 60 + "\n")

    # Flush Langfuse telemetry before the process exits (important in Docker)
    langfuse_flush()

    return 0


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Step 4 — Deterministic rule validation (Stages 1–3)"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_STAGING_INPUT,
        help="Path to generated_rules_staging.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_VALIDATED_OUTPUT,
        help="Path to write annotated validated_rules.json",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max staging entries to process (testing)",
    )
    args = parser.parse_args()

    try:
        return asyncio.run(
            run_validation(
                staging_path=args.input,
                output_path=args.output,
                limit=args.limit,
            )
        )
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        logger.info("Validation interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
