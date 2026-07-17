#!/usr/bin/env python3
"""
Step 6: Gradient-free Evolutionary Prompt Adaptation (GEPA) Engine.

Uses three data assets as the optimisation signal to autonomously evolve the
Step 3 rule-generation system prompt via phi4-mini-reasoning:

  1. Current system prompt   — data/generator_system_prompt.txt
                               (falls back to SYSTEM_PROMPT_BASE in rule_engine.py)
  2. Positive reinforcement  — approved rules from data/prod_detection_rules.json
  3. Negative gradient       — rejected rules + engineer justifications from
                               data/failed_feedback_queue.json

Three sequential LLM phases
────────────────────────────
  Phase 1  Critique Generation
           Model acts as a Prompt Auditor.  Receives the current prompt plus
           approved/rejected rule samples and produces a structured markdown
           critique identifying WHY the current prompt allowed the rejections.

  Phase 2  Prompt Mutation — The Evolution Step
           Model acts as an Evolutionary Prompt Optimizer.  Receives the
           original prompt and the Phase 1 critique, then rewrites the prompt
           so future generations avoid the identified failure modes.
           Constraints: 3-strategy diversity matrix and 7-key JSON contract
           are ALWAYS preserved.

  Phase 3  Selection & Persistence
           Evolved prompt is validated for structural integrity, then written
           atomically to data/generator_system_prompt.txt so Step 3 auto-loads
           it on the next execution.

Queue state management
──────────────────────
  On success  →  rejected items archived to data/gepa_history_log.json
             →  data/failed_feedback_queue.json cleared to []
  On empty    →  log status, exit cleanly without touching any file

Usage
─────
    python main_feedback.py
    python main_feedback.py --dry-run          # print prompts; no LLM calls, no writes
    python main_feedback.py --no-archive       # skip history log; queue still cleared
    python main_feedback.py --max-approved N   # max approved rule samples (default 5)
    python main_feedback.py --max-rejected N   # max rejected rule samples (default 20)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

FEEDBACK_QUEUE       = Path("data/failed_feedback_queue.json")
PROD_RULES           = Path("data/prod_detection_rules.json")
GEPA_PROMPT_FILE     = Path("data/generator_system_prompt.txt")
GEPA_HISTORY_LOG     = Path("data/gepa_history_log.json")

# ---------------------------------------------------------------------------
# Ollama / phi4-mini-reasoning config
# ---------------------------------------------------------------------------

OLLAMA_BASE_URL: str    = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_MODEL: str       = os.environ.get("OLLAMA_PHI4_MODEL", "phi4-mini-reasoning")
TIMEOUT_SECONDS: float  = float(os.environ.get("FEEDBACK_TIMEOUT_SECONDS", "300"))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("main_feedback")

# ---------------------------------------------------------------------------
# Structural-integrity guard strings
# Every evolved prompt must contain all of these phrases so the 3-strategy
# diversity matrix and 7-key JSON contract are never silently dropped.
# ---------------------------------------------------------------------------

_INTEGRITY_CHECKS: dict[str, list[str]] = {
    "strategy_layer_1": ["Process Creation", "Command-Line", "COMMAND-LINE"],
    "strategy_layer_2": ["File", "Registry", "REGISTRY"],
    "strategy_layer_3": ["Network", "API", "NETWORK"],
    "key_name":         ['"name"'],
    "key_actions":      ['"actionNames"'],
    "key_severity":     ['"defaultSeverity"'],
    "key_remediate":    ['"remediate"'],
}

# ---------------------------------------------------------------------------
# GEPA phase system prompts
# ---------------------------------------------------------------------------

_PHASE1_SYSTEM_PROMPT = """\
You are an expert Prompt Auditor specialising in detection engineering automation \
and large-language-model reliability engineering.

You will receive three input sections:
  A. CURRENT GENERATION PROMPT — the system prompt currently driving Step 3 rule generation.
  B. APPROVED RULES             — detection rules that a security engineer accepted as
                                  production-quality.
  C. REJECTED RULES             — detection rules that a security engineer rejected, each
                                  accompanied by the engineer's written justification.

Your task is to produce a structured markdown critique that answers the following \
questions with surgical precision:

  1. WHY DID THE PROMPT FAIL?
     Identify the exact instruction gaps, ambiguous clauses, or missing constraints
     that allowed the model to generate the rejected patterns.

  2. WHAT PERMITTED THE HALLUCINATIONS OR LOW-FIDELITY LOGIC?
     Reference specific lines or sections in the current prompt that are too vague,
     too permissive, or actively misleading for the types of errors observed.

  3. WHAT IS THE DELTA BETWEEN APPROVED AND REJECTED RULES?
     Compare the structural and semantic qualities of the approved rules against
     the rejected ones.  What makes the approved rules higher-fidelity?

  4. RECOMMENDED CONSTRAINT CLASSES
     List the categories of new constraints that must be injected into the prompt to
     close the identified gaps.  Be specific — reference the exact failure patterns.

OUTPUT FORMAT
  Return ONLY a structured markdown critique using numbered sections and sub-bullets.
  Do NOT output the corrected prompt yet.
  Do NOT add any prose outside the structured critique sections.
"""

_PHASE2_SYSTEM_PROMPT = """\
You are an Evolutionary Prompt Optimizer specialising in detection engineering \
instruction design for local reasoning models.

You will receive two input sections:
  A. CURRENT GENERATION PROMPT — the active system prompt driving Step 3.
  B. PHASE 1 CRITIQUE           — a structured audit identifying the exact gaps and
                                  failure modes in the current prompt.

Your task is to produce a FULLY REWRITTEN version of the Step 3 rule generation \
system prompt that closes every gap identified in the critique.

NON-NEGOTIABLE PRESERVATION CONSTRAINTS
────────────────────────────────────────
You MUST preserve, word-for-word or equivalently, ALL of the following structural \
blocks in the evolved prompt:

1. THE 3-STRATEGY DIVERSITY MATRIX
   The evolved prompt MUST instruct the model to generate EXACTLY 3 rule variants,
   each targeting a fundamentally different telemetry layer:
     Rule 1 — PROCESS CREATION / COMMAND-LINE ARGUMENTS
     Rule 2 — FILE / REGISTRY MODIFICATIONS OR BEHAVIORAL INDICATORS
     Rule 3 — NETWORK CONNECTIONS / API / SYSTEM CALLS
   The descriptions for each strategy layer must be retained or strengthened.

2. THE 7-KEY JSON OUTPUT CONTRACT
   Every rule object in the output MUST contain all 7 keys with NO EXCEPTIONS:
     "name", "description", "actionNames", "defaultSeverity",
     "threatType", "recommend", "remediate"
   The explicit example rule object (showing all 7 keys) MUST be preserved.

3. THE HARD RULES BLOCK
   The platform-prefix requirement, the actionNames grounding constraint
   (only from LOOKUP_ARRAY), and the no-markdown-fences rule MUST be retained.

EVOLUTION CONSTRAINTS
─────────────────────
- Integrate the critique's recommended constraints as NATURAL INSTRUCTIONAL LANGUAGE.
  Do NOT paste raw rejection text, engineer quotes, or error log strings verbatim.
- Every new constraint must be expressed as a forward-looking directive
  ("DO NOT", "ALWAYS", "AVOID", "ENSURE"), not as a historical failure description.
- Do NOT weaken any existing constraint while adding new ones.
- Maintain the existing structural section separators (━━━ headers) and formatting style.

OUTPUT FORMAT
─────────────
Output ONLY the raw text of the new system prompt.
Do NOT wrap it in markdown code fences, triple backticks, or any outer container.
Do NOT add any explanatory prose before or after the prompt text.
The very first character of your output must be the first character of the new prompt.
"""

# ---------------------------------------------------------------------------
# Safe file I/O
# ---------------------------------------------------------------------------


def _load_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("load_failed path=%s error=%s", path, exc)
        return default


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def _save_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Load current system prompt
# ---------------------------------------------------------------------------


def load_current_prompt() -> tuple[str, str]:
    """
    Return (prompt_text, source_label).

    Prefers the GEPA-evolved file; falls back to the hardcoded constant in
    generators/rule_engine.py so the loop bootstraps correctly on first run.
    """
    if GEPA_PROMPT_FILE.is_file():
        try:
            content = GEPA_PROMPT_FILE.read_text(encoding="utf-8").strip()
            if content:
                logger.info("current_prompt_loaded source=%s", GEPA_PROMPT_FILE)
                return content, str(GEPA_PROMPT_FILE)
        except OSError as exc:
            logger.warning("gepa_prompt_read_failed error=%s", exc)

    # Import the hardcoded baseline directly — no file parsing required
    try:
        from generators.rule_engine import SYSTEM_PROMPT_BASE  # noqa: PLC0415
        logger.info("current_prompt_loaded source=generators/rule_engine.py (hardcoded baseline)")
        return SYSTEM_PROMPT_BASE, "generators/rule_engine.py (SYSTEM_PROMPT_BASE)"
    except ImportError as exc:
        raise RuntimeError(
            "Cannot load current system prompt: GEPA file absent and "
            "generators.rule_engine is not importable."
        ) from exc


# ---------------------------------------------------------------------------
# Build Phase 1 user message
# ---------------------------------------------------------------------------


def _format_rule_compact(rule_obj: dict[str, Any]) -> str:
    """Return a compact single-rule summary for LLM context."""
    name        = rule_obj.get("name", "unnamed")
    description = rule_obj.get("description", "")[:200]
    actions     = ", ".join(rule_obj.get("actionNames", []))
    severity    = rule_obj.get("defaultSeverity", "?")
    return (
        f"  Name          : {name}\n"
        f"  Severity      : {severity}\n"
        f"  ActionNames   : {actions or '(none)'}\n"
        f"  Description   : {description}"
    )


def _build_phase1_user_message(
    current_prompt: str,
    approved: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    *,
    max_approved: int = 5,
    max_rejected: int = 20,
) -> str:
    lines: list[str] = []

    # ── A. Current prompt ────────────────────────────────────────────────────
    lines += [
        "══ A. CURRENT GENERATION PROMPT ══",
        "The system prompt below is what the rule generator is currently using:",
        "",
        current_prompt.strip(),
        "",
    ]

    # ── B. Approved rules (positive signal) ──────────────────────────────────
    approved_sample = approved[:max_approved]
    lines += [
        "══ B. APPROVED RULES (Engineer-Validated Production Quality) ══",
        f"Total approved rules available: {len(approved)}  |  Showing: {len(approved_sample)}",
        "",
    ]
    for i, item in enumerate(approved_sample, start=1):
        rule = item.get("rule") or {}
        lines += [
            f"[APPROVED {i}]",
            _format_rule_compact(rule),
            "",
        ]

    # ── C. Rejected rules (negative gradient) ────────────────────────────────
    rejected_sample = rejected[:max_rejected]
    lines += [
        "══ C. REJECTED RULES WITH ENGINEER JUSTIFICATIONS ══",
        f"Total rejections: {len(rejected)}  |  Showing: {len(rejected_sample)}",
        "",
    ]
    for i, rec in enumerate(rejected_sample, start=1):
        rule    = rec.get("rule") or {}
        reason  = rec.get("rejection_reason", "(no reason provided)")
        rtype   = rec.get("rejection_type", "unknown")
        strat   = rec.get("detection_strategy", "unknown")
        lines += [
            f"[REJECTED {i}]  strategy={strat}  type={rtype}",
            _format_rule_compact(rule),
            f"  Engineer reason: {reason}",
            "",
        ]

    lines += [
        "══ AUDIT TASK ══",
        "Analyse the three sections above and produce a structured markdown critique",
        "that precisely explains WHY the current prompt allowed the rejected patterns.",
        "Identify all gaps, weaknesses, and missing constraints.",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Build Phase 2 user message
# ---------------------------------------------------------------------------


def _build_phase2_user_message(current_prompt: str, critique: str) -> str:
    return "\n".join([
        "══ A. CURRENT GENERATION PROMPT ══",
        "",
        current_prompt.strip(),
        "",
        "══ B. PHASE 1 CRITIQUE ══",
        "",
        critique.strip(),
        "",
        "══ EVOLUTION TASK ══",
        "Using the Phase 1 critique above, produce the complete rewritten system prompt.",
        "Output ONLY the raw new prompt text — no fences, no wrapping, no preamble.",
    ])


# ---------------------------------------------------------------------------
# Strip phi4 thinking blocks + markdown fences from text output
# ---------------------------------------------------------------------------


def _clean_text_output(raw: str) -> str:
    """Remove <thinking> blocks and markdown code fences from a free-form LLM response."""
    text = re.sub(r"<thinking>.*?</thinking>", "", raw, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"</?thinking>", "", text, flags=re.IGNORECASE)
    # Strip wrapping code fences  (``` or ```text or ```markdown etc.)
    text = re.sub(r"^```[a-zA-Z]*\s*", "", text.strip(), flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text, flags=re.IGNORECASE)
    return text.strip()


# ---------------------------------------------------------------------------
# Structural-integrity validation for evolved prompt
# ---------------------------------------------------------------------------


def _validate_evolved_prompt(prompt: str) -> list[str]:
    """
    Return a list of integrity-failure messages.  Empty list = prompt passes.

    Checks that the evolved prompt still contains all required structural
    elements (strategy layers, 7-key contract, etc.).
    """
    failures: list[str] = []
    for check_name, candidates in _INTEGRITY_CHECKS.items():
        if not any(candidate in prompt for candidate in candidates):
            failures.append(
                f"Missing structural element '{check_name}' "
                f"(expected one of: {candidates})"
            )
    return failures


# ---------------------------------------------------------------------------
# LLM call helper — wraps both phases
# ---------------------------------------------------------------------------


def _call_llm_text(
    system_prompt: str,
    user_message: str,
    phase_label: str,
    *,
    dry_run: bool = False,
    temperature: float = 0.3,
) -> str:
    """
    Call phi4-mini-reasoning for a free-form text output (Phase 1 or Phase 2).

    Returns the cleaned text response, or a placeholder string in dry-run mode.
    """
    if dry_run:
        width = 70
        print(f"\n{'=' * width}")
        print(f"DRY-RUN  {phase_label}")
        print(f"{'─' * width}")
        print("SYSTEM PROMPT (first 200 chars):")
        print(textwrap.fill(system_prompt[:200], width=width), "…")
        print(f"\nUSER MESSAGE (first 300 chars):")
        print(textwrap.fill(user_message[:300], width=width), "…")
        print("=" * width)
        return f"[DRY-RUN placeholder for {phase_label}]"

    from llm.structured_client import StructuredLLMClient  # noqa: PLC0415
    from openai import APIConnectionError, APITimeoutError  # noqa: PLC0415

    llm = StructuredLLMClient(
        base_url=OLLAMA_BASE_URL,
        model=OLLAMA_MODEL,
        api_key="ollama",
        timeout=TIMEOUT_SECONDS,
    )
    messages: list[dict[str, str]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_message},
    ]

    logger.info(
        "llm_call phase=%s model=%s provider=%s",
        phase_label,
        OLLAMA_MODEL,
        "cloud" if llm.is_cloud else "local",
    )

    try:
        raw = llm.generate_text(messages, temperature=temperature)
    except (APIConnectionError, APITimeoutError, ConnectionError, TimeoutError) as exc:
        raise RuntimeError(f"{phase_label} LLM timeout: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"{phase_label} LLM error: {exc}") from exc

    cleaned = _clean_text_output(raw)
    logger.info(
        "llm_response phase=%s len_raw=%d len_cleaned=%d",
        phase_label, len(raw), len(cleaned),
    )
    return cleaned


# ---------------------------------------------------------------------------
# Core GEPA pipeline
# ---------------------------------------------------------------------------


def run_gepa(
    *,
    dry_run: bool = False,
    no_archive: bool = False,
    max_approved: int = 5,
    max_rejected: int = 20,
) -> int:
    started = time.perf_counter()

    # ── 1. Load failure gradient ─────────────────────────────────────────────
    queue: list[dict[str, Any]] = _load_json(FEEDBACK_QUEUE, [])
    if not isinstance(queue, list):
        queue = []

    if not queue:
        logger.info(
            "No new feedback gradients to process — "
            "data/failed_feedback_queue.json is empty."
        )
        print(
            "\n[GEPA] No new feedback gradients to process. "
            "Step 6 exiting cleanly.\n"
        )
        return 0

    logger.info("feedback_queue_loaded entries=%d", len(queue))

    # ── 2. Load current system prompt ────────────────────────────────────────
    current_prompt, prompt_source = load_current_prompt()
    logger.info(
        "current_prompt_chars=%d source=%s", len(current_prompt), prompt_source
    )

    # ── 3. Load positive reinforcement signal ────────────────────────────────
    approved_raw: list[dict[str, Any]] = _load_json(PROD_RULES, [])
    if not isinstance(approved_raw, list):
        approved_raw = []
    logger.info("approved_rules_loaded count=%d", len(approved_raw))

    # ── Phase 1: Critique Generation ─────────────────────────────────────────
    print(
        f"\n[GEPA Phase 1] Generating prompt critique …\n"
        f"  Approved rule samples : {min(len(approved_raw), max_approved)}\n"
        f"  Rejection samples     : {min(len(queue), max_rejected)}\n"
    )

    phase1_user = _build_phase1_user_message(
        current_prompt,
        approved_raw,
        queue,
        max_approved=max_approved,
        max_rejected=max_rejected,
    )

    try:
        critique = _call_llm_text(
            _PHASE1_SYSTEM_PROMPT,
            phase1_user,
            "Phase 1 — Critique",
            dry_run=dry_run,
            temperature=0.2,        # crisp, analytical output
        )
    except RuntimeError as exc:
        logger.error("phase1_failed error=%s", exc)
        print(f"\n[GEPA] Phase 1 failed: {exc}")
        print("[GEPA] Aborting — no files were modified.\n")
        return 1

    logger.info("phase1_critique_generated chars=%d", len(critique))

    if not dry_run:
        print("[GEPA Phase 1] Critique generated successfully.")
        # Show first ~400 chars of critique for operator awareness
        print("\nCRITIQUE PREVIEW (first 400 chars):")
        print(critique[:400].strip(), "…\n")

    # ── Phase 2: Prompt Mutation ──────────────────────────────────────────────
    print("[GEPA Phase 2] Evolving system prompt …")

    phase2_user = _build_phase2_user_message(current_prompt, critique)

    try:
        evolved_prompt = _call_llm_text(
            _PHASE2_SYSTEM_PROMPT,
            phase2_user,
            "Phase 2 — Evolution",
            dry_run=dry_run,
            temperature=0.3,
        )
    except RuntimeError as exc:
        logger.error("phase2_failed error=%s", exc)
        print(f"\n[GEPA] Phase 2 failed: {exc}")
        print("[GEPA] Aborting — no files were modified.\n")
        return 1

    logger.info("phase2_evolved_prompt_generated chars=%d", len(evolved_prompt))

    # ── Phase 3: Structural validation & persistence ─────────────────────────
    integrity_failures = _validate_evolved_prompt(evolved_prompt)

    if integrity_failures:
        warning_block = "\n".join(f"  • {f}" for f in integrity_failures)
        logger.warning(
            "evolved_prompt_integrity_warnings count=%d warnings=\n%s",
            len(integrity_failures),
            warning_block,
        )
        print(
            f"\n[GEPA Phase 3] Integrity warnings ({len(integrity_failures)}):\n"
            + warning_block
        )
        print(
            "[GEPA] Saving evolved prompt with warnings noted — "
            "review data/generator_system_prompt.txt before next Step 3 run."
        )
    else:
        print("[GEPA Phase 3] Structural integrity check PASSED.")

    if not dry_run:
        _save_text(GEPA_PROMPT_FILE, evolved_prompt)
        logger.info(
            "evolved_prompt_saved path=%s chars=%d", GEPA_PROMPT_FILE, len(evolved_prompt)
        )
        print(f"[GEPA Phase 3] Evolved prompt saved → {GEPA_PROMPT_FILE}")
    else:
        width = 70
        print(f"\n{'=' * width}")
        print("DRY-RUN — EVOLVED PROMPT PREVIEW (first 600 chars):")
        print(evolved_prompt[:600].strip())
        print("=" * width)

    # ── Archive & queue cleanup ───────────────────────────────────────────────
    if not dry_run:
        if not no_archive:
            history: list[dict[str, Any]] = _load_json(GEPA_HISTORY_LOG, [])
            if not isinstance(history, list):
                history = []

            run_record: dict[str, Any] = {
                "gepa_run_at":        datetime.now(timezone.utc).isoformat(),
                "model":              OLLAMA_MODEL,
                "prompt_source":      prompt_source,
                "approved_sampled":   min(len(approved_raw), max_approved),
                "rejections_ingested": len(queue),
                "integrity_warnings": integrity_failures,
                "evolved_prompt_chars": len(evolved_prompt),
                "processed_rejections": queue,
            }
            history.append(run_record)
            _save_json(GEPA_HISTORY_LOG, history)
            logger.info(
                "gepa_history_archived path=%s total_runs=%d",
                GEPA_HISTORY_LOG,
                len(history),
            )
            print(f"[GEPA] Run record archived → {GEPA_HISTORY_LOG}")

        _save_json(FEEDBACK_QUEUE, [])
        logger.info("feedback_queue_cleared path=%s", FEEDBACK_QUEUE)
        print(f"[GEPA] Feedback queue cleared → {FEEDBACK_QUEUE}")

    # ── Summary banner ────────────────────────────────────────────────────────
    elapsed = time.perf_counter() - started
    print("\n" + "=" * 62)
    print("STEP 6 — GEPA EVOLUTION REPORT")
    print("=" * 62)
    print(f"Feedback rejections ingested  : {len(queue)}")
    print(f"Approved rule samples used    : {min(len(approved_raw), max_approved)}")
    print(f"Prompt source                 : {prompt_source}")
    print(f"Evolved prompt chars          : {len(evolved_prompt)}")
    print(f"Integrity checks passed       : {len(_INTEGRITY_CHECKS) - len(integrity_failures)}/{len(_INTEGRITY_CHECKS)}")
    if integrity_failures:
        print(f"Integrity warnings            : {len(integrity_failures)}")
    print(f"Model                         : {OLLAMA_MODEL} @ {OLLAMA_BASE_URL}")
    print(f"Elapsed                       : {elapsed:.1f}s")
    print(f"Output prompt file            : {GEPA_PROMPT_FILE}")
    if not no_archive and not dry_run:
        print(f"GEPA history log              : {GEPA_HISTORY_LOG}")
    print(f"Queue cleared                 : {'Yes' if not dry_run else 'No (dry-run)'}")
    print("=" * 62 + "\n")

    return 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Step 6 — GEPA: Gradient-free Evolutionary Prompt Adaptation "
            "for the phi4-mini-reasoning rule generator"
        )
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print all prompt payloads and previews without calling Ollama or writing any files",
    )
    parser.add_argument(
        "--no-archive",
        action="store_true",
        help="Skip writing the run record to data/gepa_history_log.json (queue is still cleared)",
    )
    parser.add_argument(
        "--max-approved",
        type=int,
        default=5,
        metavar="N",
        help="Maximum number of approved rules to include as positive-signal context (default: 5)",
    )
    parser.add_argument(
        "--max-rejected",
        type=int,
        default=20,
        metavar="N",
        help="Maximum number of rejected rules to include as negative-gradient context (default: 20)",
    )
    args = parser.parse_args()

    try:
        return run_gepa(
            dry_run=args.dry_run,
            no_archive=args.no_archive,
            max_approved=args.max_approved,
            max_rejected=args.max_rejected,
        )
    except KeyboardInterrupt:
        logger.info("GEPA engine interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
