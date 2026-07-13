#!/usr/bin/env python3
"""
Step 4: Deterministic rule validation pipeline.

Stage 1  — Python contract enforcement (7-key schema, non-empty fields, severity enum)
Stage 2  — Knowledge base action-name lookup (strict string match against all KB catalogs)
Stage 3  — phi4-mini-reasoning cognitive audit (Sherman Kent CTI analytic discipline)

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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_STAGING_INPUT = Path("data/generated_rules_staging.json")
DEFAULT_VALIDATED_OUTPUT = Path("data/validated_rules.json")
KB_DIR = Path("knowledge_base")

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

VALID_SEVERITIES: frozenset[str] = frozenset({"Low", "Medium", "High", "Critical"})

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

# ---------------------------------------------------------------------------
# Stage 3 — Sherman Kent CTI system prompt (exact, word-for-word)
# ---------------------------------------------------------------------------

STAGE3_SYSTEM_PROMPT: str = """\
You are an expert Cyber Threat Intelligence (CTI) Analyst trained rigorously in Sherman Kent's analytic discipline. Your goal is to transform the provided raw threat data, logs, or notes into a professional, transparent, and highly disciplined threat intelligence report. 

You must strictly separate hard evidence from analytical assumptions.

---

### STEP 1: ANALYTICAL DEFINITIONS
When writing the report, you must strictly adhere to these definitions for Probability and Confidence. Do not mix them up.

#### Estimative Probability Scale (How likely it is)
- Almost Certain: 90%–99% chance
- Highly Likely / Probable: 60%–85% chance
- Likely / Possible: 35%–55% chance
- Unlikely: 10%–30% chance
- Remote / Highly Unlikely: Less than 10% chance

#### Confidence Levels (Strength of our evidence)
- High Confidence: Based on high-quality, verified, first-hand data/logs with no contradictory information.
- Medium Confidence: Based on plausible data or third-party vendor reporting, but lacks direct, independent verification.
- Low Confidence: Based on fragmented, unverified, or highly perishable data.

---

### STEP 2: PROCEDURAL WORKFLOW
Analyze the source data sequentially using the following process:
1. Categorize the Evidence: Label every technical indicator or claim as either Source-observed (we saw it), Reported (someone else said it), or Inferred (we deduced it).
2. Brainstorm Alternative Hypotheses: List at least two plausible alternative explanations for the activity (e.g., false flags, shared infrastructure, tool reuse, or coincidence).
3. Identify Collection Gaps: Explicitly note what critical data is missing or what we cannot see from the current dataset.

---

### STEP 3: THE MANDATORY CONTENT CHECKLIST
Before outputting the final report, verify that you have checked every box:
- [ ] Clearly separated physical observations (logs, IPs, hashes) from analytical opinions.
- [ ] Used exact probability words from the scale in Step 1, and never used vague synonyms.
- [ ] Assigned a separate Confidence Level and explained why that level was chosen based on data quality.
- [ ] Evaluated and written down at least one alternative theory to challenge the primary conclusion.
- [ ] Included a specific section highlighting "Collection Gaps" (what data we are missing).
- [ ] Avoided over-confident attribution to threat actors without concrete, verified ties.

---

### REPORT FORMAT
Please output the report using this exact structure inside your response container:

## 1. Executive Summary
(Brief overview of the activity using precise probability language)

## 2. Technical Observations & Evidence Categorization
(Bullet points of IPs, hashes, domains, or behaviors categorized by Source-observed, Reported, or Inferred)

## 3. Core Analysis & Assessment
- Primary Hypothesis: (What we think is happening)
- Probability Assessment: (Choose from Step 1 scale)
- Confidence Assessment & Justification: (Choose from Step 1 scale and justify based on evidence quality)

## 4. Alternative Hypotheses
(Alternative theories that could explain the same technical data)

## 5. Collection Gaps
(What data or logs are missing that would help clarify this threat?)\
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

# Ordered by specificity so the first full-phrase match wins.
_KENT_TAGS: list[str] = [
    "Almost Certain",
    "Highly Likely",
    "Probable",
    "Likely",
    "Possible",
    "Unlikely",
    "Remote",
    "Highly Unlikely",
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
    """
    match = _KENT_PATTERN.search(report)
    if match:
        assessment_line = match.group(1)
        for tag in _KENT_TAGS:
            if tag.lower() in assessment_line.lower():
                return tag
    # Fallback: scan the full report for any recognised tag
    for tag in _KENT_TAGS:
        if tag.lower() in report.lower():
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


def _call_ollama_sync(rule_data: dict[str, Any]) -> dict[str, Any]:
    """
    Synchronous Ollama call — run inside asyncio.to_thread() to avoid
    blocking the event loop during concurrent variant processing.
    """
    # Lazy import: openai is only required at runtime; avoids hard startup
    # failure when the package is absent in minimal environments.
    try:
        from openai import APIConnectionError, APITimeoutError, OpenAI
    except ModuleNotFoundError as exc:
        return {**_STAGE3_FALLBACK, "model_error": f"openai package missing: {exc}"}

    user_prompt = f"### SOURCE DATA TO ANALYZE:\n{json.dumps(rule_data, indent=2)}"

    client = OpenAI(
        base_url=STAGE3_OLLAMA_BASE_URL,
        api_key="ollama",
        timeout=STAGE3_TIMEOUT_SECONDS,
    )

    try:
        response = client.chat.completions.create(
            model=STAGE3_OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": STAGE3_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
        )
        raw: str = response.choices[0].message.content or ""
    except (APIConnectionError, APITimeoutError, ConnectionError, TimeoutError) as exc:
        logger.error("stage3_ollama_timeout model=%s error=%s", STAGE3_OLLAMA_MODEL, exc)
        return {**_STAGE3_FALLBACK, "model_error": f"Ollama timeout/connection: {exc}"}
    except Exception as exc:
        logger.error("stage3_ollama_error model=%s error=%s", STAGE3_OLLAMA_MODEL, exc)
        return {**_STAGE3_FALLBACK, "model_error": f"Ollama call failed: {exc}"}

    report = _strip_thinking_tags(raw)
    if not report:
        logger.warning("stage3_empty_response model=%s", STAGE3_OLLAMA_MODEL)
        return {**_STAGE3_FALLBACK, "model_error": "Model returned empty response after stripping"}

    kent_tag = _extract_kent_tag(report)
    rationale = _extract_executive_summary(report)

    logger.info(
        "stage3_audit_complete model=%s kent_tag=%r rationale_len=%d",
        STAGE3_OLLAMA_MODEL,
        kent_tag,
        len(rationale),
    )
    return {
        "is_valid": True,
        "kent_probability_tag": kent_tag,
        "audit_rationale": rationale,
        "full_report": report,
        "model": STAGE3_OLLAMA_MODEL,
        "model_error": None,
    }


async def run_stage3_cognitive_audit(rule_data: dict[str, Any]) -> dict[str, Any]:
    """
    phi4-mini-reasoning cognitive audit using Sherman Kent's CTI analytic discipline.

    Runs the blocking Ollama call in a thread pool so the asyncio event loop
    remains free to process other variants concurrently.
    """
    return await asyncio.to_thread(_call_ollama_sync, rule_data)


# ---------------------------------------------------------------------------
# Knowledge base loader
# ---------------------------------------------------------------------------


def load_kb_action_set(kb_dir: Path = KB_DIR) -> frozenset[str]:
    """
    Walk every JSON file under kb_dir and collect all authoritative actionNames
    into a single flat frozenset for O(1) lookup.

    Raw upstream dumps (*.raw.json) are excluded — they are source artifacts,
    not the curated catalog format.
    """
    actions: set[str] = set()
    loaded_files: list[str] = []
    skipped_files: list[str] = []

    for json_path in sorted(kb_dir.rglob("*.json")):
        name = json_path.name

        # Skip raw upstream dumps
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
            actions.update(str(a) for a in raw_actions if a)
            loaded_files.append(f"{name}(+{len(actions) - count_before})")

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

    # Explicit severity enum check
    severity = rule.get("defaultSeverity", "")
    if severity and severity not in VALID_SEVERITIES:
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
    Returns a list of violation strings for actions not found (empty = pass).
    """
    rule_actions: list[str] = rule.get("actionNames") or []
    violations: list[str] = []

    for action in rule_actions:
        if not isinstance(action, str) or not action.strip():
            violations.append(f"actionName is blank or non-string: {action!r}")
            continue
        if action not in kb_actions:
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
    audit = await run_stage3_cognitive_audit(variant)

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
    Returns the entry dict with each variant's 'validation' key populated.
    """
    title = entry.get("threat_title", "unknown")
    raw_variants: list[dict[str, Any]] = entry.get("variants") or []

    validated_variants = await asyncio.gather(
        *[
            validate_variant(v, idx, title, kb_actions)
            for idx, v in enumerate(raw_variants)
        ]
    )

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
    kb_actions = load_kb_action_set(KB_DIR)

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
