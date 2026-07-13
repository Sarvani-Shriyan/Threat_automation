#!/usr/bin/env python3
"""
Step 6: Automated Feedback Loop Engine.

Reads engineer-rejected rule variants from data/failed_feedback_queue.json,
groups them by detection_strategy, and calls phi4-mini-reasoning to distil
2–3 high-fidelity Negative Constraints per strategy category.

Outputs
-------
data/negative_constraints.json   — Accumulated constraints fed back into Step 3
data/failed_feedback_history.json — Archived processed rejections (append-only)

Queue cleanup
-------------
After successful processing, data/failed_feedback_queue.json is cleared to []
so the same rejections are never reprocessed.

Usage
-----
    python main_feedback.py
    python main_feedback.py --dry-run           # print prompt payloads; no Ollama call
    python main_feedback.py --no-archive        # skip history file; still clears queue
    python main_feedback.py --min-failures 1    # override min failures per group (default 1)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

FEEDBACK_QUEUE   = Path("data/failed_feedback_queue.json")
CONSTRAINTS_OUT  = Path("data/negative_constraints.json")
HISTORY_ARCHIVE  = Path("data/failed_feedback_history.json")

# ---------------------------------------------------------------------------
# Ollama / phi4-mini-reasoning config (mirrors main_validator.py)
# ---------------------------------------------------------------------------

OLLAMA_BASE_URL: str  = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_MODEL: str     = os.environ.get("OLLAMA_PHI4_MODEL", "phi4-mini-reasoning")
TIMEOUT_SECONDS: float = float(os.environ.get("FEEDBACK_TIMEOUT_SECONDS", "300"))

# ---------------------------------------------------------------------------
# Strategy catalogue
# ---------------------------------------------------------------------------

# Canonical 3-strategy labels produced by app_triage.py.
KNOWN_STRATEGIES: list[str] = [
    "Process / CLI Args",
    "File & Registry",
    "Network / API Calls",
]

# Keyword sets used as a fallback when detection_strategy is missing from a record.
_STRATEGY_KEYWORDS: dict[str, list[str]] = {
    "Process / CLI Args": [
        "process", "command", "cmd", "exec", "spawn", "subprocess",
        "shell", "interpreter", "script", "powershell", "bash", "invocation",
        "commandline", "argument", "cli",
    ],
    "File & Registry": [
        "file", "filesystem", "registry", "write", "read", "delete",
        "path", "directory", "folder", "config", "persistence", "artifact",
        "modification", "disk", "storage",
    ],
    "Network / API Calls": [
        "network", "api", "connection", "dns", "http", "https", "socket",
        "port", "traffic", "egress", "ingress", "lateral", "outbound",
        "inbound", "endpoint", "url", "request", "webhook",
    ],
}

# ---------------------------------------------------------------------------
# Negative-constraint generation prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a senior Detection Engineering Analyst responsible for maintaining the quality and \
precision of automated SIEM detection rules.

Your task is to analyze a batch of detection rule variants that a security engineer has \
rejected, together with the engineer's written rejection justifications, and distil them into \
generalized engineering constraints that will prevent the rule generation model from repeating \
the same mistakes.

STRICT OUTPUT CONTRACT
----------------------
You MUST return a JSON object — and NOTHING ELSE.
Do NOT include markdown code fences, explanatory prose, or any text outside the JSON block.

Schema:
{
  "negative_constraints": [
    "<constraint 1>",
    "<constraint 2>",
    "<constraint 3 (optional)>"
  ]
}

CONSTRAINT WRITING RULES
------------------------
1. Generate between 2 and 3 constraints. Never fewer than 2, never more than 3.
2. Each constraint MUST start with a directive verb such as DO NOT, AVOID, NEVER, or REJECT.
3. Each constraint must be generalized — it should catch the class of mistake, not just the \
   specific rejected rule.
4. Constraints must be concise (one sentence each, max 30 words).
5. Constraints must be directly derivable from the rejection justifications provided. \
   Do not invent problems that are not evidenced in the input data.
6. Do not repeat or paraphrase the same constraint twice.

FAILURE SUMMARY FORMAT (sent as user message)
---------------------------------------------
You will receive:
  - The detection strategy category being analyzed.
  - A numbered list of rejected rules, each showing: rule name, action names, a short \
    description, and the engineer's rejection reason.
"""

_FALLBACK_CONSTRAINTS: list[str] = [
    "AVOID generating rules for this strategy — insufficient feedback data to derive reliable constraints.",
]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("main_feedback")

# ---------------------------------------------------------------------------
# Safe file I/O (matches app_triage.py atomic pattern)
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
    """Atomic write: write to .tmp, then os.replace to final path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Strategy inference (fallback for records missing the field)
# ---------------------------------------------------------------------------


def _infer_strategy(record: dict[str, Any]) -> str:
    """
    Determine strategy from a feedback record.
    Uses the stored detection_strategy field first; falls back to keyword
    matching against rule name, description, and actionNames.
    """
    stored = (record.get("detection_strategy") or "").strip()
    if stored and stored in KNOWN_STRATEGIES:
        return stored

    rule = record.get("rule") or {}
    text_blob = " ".join([
        rule.get("name", ""),
        rule.get("description", ""),
        " ".join(rule.get("actionNames", [])),
    ]).lower()

    best_strategy = "Process / CLI Args"  # sensible default
    best_score = 0
    for strategy, keywords in _STRATEGY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text_blob)
        if score > best_score:
            best_score = score
            best_strategy = strategy

    if best_score == 0:
        logger.warning(
            "strategy_inference_no_match rule=%r — defaulting to %r",
            rule.get("name", "unknown"),
            best_strategy,
        )
    return best_strategy


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


def _build_user_prompt(strategy: str, records: list[dict[str, Any]]) -> str:
    lines: list[str] = [
        f"DETECTION STRATEGY: {strategy}",
        f"NUMBER OF REJECTED RULES IN THIS BATCH: {len(records)}",
        "",
        "REJECTED RULES AND ENGINEER JUSTIFICATIONS",
        "-------------------------------------------",
    ]
    for i, rec in enumerate(records, start=1):
        rule = rec.get("rule") or {}
        reason = rec.get("rejection_reason", "(no reason provided)")
        rejection_type = rec.get("rejection_type", "unknown")
        lines += [
            f"",
            f"[{i}] Rule name: {rule.get('name', 'unnamed')}",
            f"    Rejection type : {rejection_type}",
            f"    Engineer reason: {reason}",
            f"    Action names   : {', '.join(rule.get('actionNames', [])) or '(none)'}",
            f"    Description    : {rule.get('description', '')}",
        ]
    lines += [
        "",
        "Now produce 2–3 generalized Negative Constraints for the "
        f"'{strategy}' detection strategy based solely on the patterns "
        "you observe in the rejection justifications above.",
        "Return ONLY the JSON object — no prose, no code fences.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# phi4-mini-reasoning Ollama call
# ---------------------------------------------------------------------------


def _strip_thinking_tags(text: str) -> str:
    text = re.sub(r"<thinking>.*?</thinking>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"</?thinking>", "", text, flags=re.IGNORECASE)
    return text.strip()


def _extract_json_block(text: str) -> str:
    """Pull the first {...} block from the model response."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    return match.group(0) if match else text


def _call_ollama(
    strategy: str,
    records: list[dict[str, Any]],
    *,
    dry_run: bool = False,
) -> list[str]:
    """
    Call phi4-mini-reasoning and return a list of 2–3 constraint strings.
    Falls back to _FALLBACK_CONSTRAINTS on any error.
    """
    user_prompt = _build_user_prompt(strategy, records)

    if dry_run:
        print(f"\n{'='*60}")
        print(f"DRY-RUN  strategy={strategy!r}  records={len(records)}")
        print("SYSTEM PROMPT (abbreviated):", _SYSTEM_PROMPT[:120], "…")
        print("USER PROMPT:")
        print(user_prompt)
        print("="*60)
        return [
            f"[DRY-RUN] Negative constraint placeholder for strategy: {strategy}",
            "[DRY-RUN] No Ollama call was made.",
        ]

    try:
        from openai import APIConnectionError, APITimeoutError, OpenAI
    except ModuleNotFoundError as exc:
        logger.error("openai_package_missing error=%s", exc)
        return [*_FALLBACK_CONSTRAINTS, f"ERROR: openai package missing — {exc}"]

    client = OpenAI(
        base_url=OLLAMA_BASE_URL,
        api_key="ollama",
        timeout=TIMEOUT_SECONDS,
    )

    try:
        logger.info(
            "ollama_call model=%s strategy=%r records=%d",
            OLLAMA_MODEL, strategy, len(records),
        )
        response = client.chat.completions.create(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=0.3,
        )
        raw: str = response.choices[0].message.content or ""
    except (APIConnectionError, APITimeoutError, ConnectionError, TimeoutError) as exc:
        logger.error("ollama_timeout strategy=%r error=%s", strategy, exc)
        return [*_FALLBACK_CONSTRAINTS, f"ERROR: Ollama timeout — {exc}"]
    except Exception as exc:
        logger.error("ollama_error strategy=%r error=%s", strategy, exc)
        return [*_FALLBACK_CONSTRAINTS, f"ERROR: {exc}"]

    clean = _strip_thinking_tags(raw)
    json_text = _extract_json_block(clean)

    try:
        payload = json.loads(json_text)
        constraints = payload.get("negative_constraints") or []
        if not isinstance(constraints, list) or not constraints:
            raise ValueError("negative_constraints array is missing or empty")
        # Enforce 2–3 range
        constraints = [str(c).strip() for c in constraints if str(c).strip()][:3]
        if len(constraints) < 2:
            constraints += _FALLBACK_CONSTRAINTS[: 2 - len(constraints)]
        logger.info(
            "constraints_generated strategy=%r count=%d",
            strategy, len(constraints),
        )
        return constraints
    except (json.JSONDecodeError, ValueError, KeyError) as exc:
        logger.error(
            "parse_failed strategy=%r error=%s raw_snippet=%r",
            strategy, exc, clean[:200],
        )
        return [*_FALLBACK_CONSTRAINTS, f"PARSE_ERROR: {exc}"]


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------


def run_feedback_loop(
    *,
    dry_run: bool = False,
    no_archive: bool = False,
    min_failures: int = 1,
) -> int:
    # ── Load feedback queue ───────────────────────────────────────
    queue: list[dict[str, Any]] = _load_json(FEEDBACK_QUEUE, [])
    if not isinstance(queue, list):
        queue = []

    if not queue:
        logger.info("No feedback entries to process — data/failed_feedback_queue.json is empty.")
        print("\n[Feedback Loop] No feedback entries to process. Exiting cleanly.\n")
        return 0

    logger.info("feedback_queue_loaded entries=%d", len(queue))

    # ── Group by detection strategy ───────────────────────────────
    grouped: dict[str, list[dict[str, Any]]] = {}
    for rec in queue:
        strategy = _infer_strategy(rec)
        grouped.setdefault(strategy, []).append(rec)

    logger.info(
        "strategy_groups groups=%d breakdown=%s",
        len(grouped),
        {k: len(v) for k, v in grouped.items()},
    )

    # ── Load existing constraints (additive merge) ────────────────
    existing_payload: dict[str, Any] = _load_json(CONSTRAINTS_OUT, {})
    existing_constraints: dict[str, list[str]] = existing_payload.get("constraints", {})

    new_constraints: dict[str, list[str]] = {}
    processed_count = 0

    started = time.perf_counter()

    for strategy, records in grouped.items():
        if len(records) < min_failures:
            logger.info(
                "strategy_skipped strategy=%r records=%d < min_failures=%d",
                strategy, len(records), min_failures,
            )
            continue

        print(
            f"\n[Feedback Loop] Processing strategy '{strategy}' "
            f"({len(records)} rejection{'s' if len(records) != 1 else ''}) …"
        )
        constraints = _call_ollama(strategy, records, dry_run=dry_run)
        new_constraints[strategy] = constraints
        processed_count += len(records)

        for c in constraints:
            print(f"  • {c}")

    elapsed = time.perf_counter() - started

    # ── Merge new constraints with existing ───────────────────────
    merged_constraints: dict[str, list[str]] = dict(existing_constraints)
    for strategy, new_list in new_constraints.items():
        prior = merged_constraints.get(strategy, [])
        # Deduplicate: keep existing items not already covered by the new batch
        deduped_prior = [c for c in prior if c not in new_list]
        # New constraints take precedence (prepend), capped at 6 per strategy
        merged_constraints[strategy] = (new_list + deduped_prior)[:6]

    constraints_payload: dict[str, Any] = {
        "updated_at":              datetime.now(timezone.utc).isoformat(),
        "total_failures_processed": (existing_payload.get("total_failures_processed", 0) + processed_count),
        "last_batch_size":         processed_count,
        "model":                   OLLAMA_MODEL if not dry_run else f"{OLLAMA_MODEL} (dry-run)",
        "strategy_counts":         {s: len(records) for s, records in grouped.items()},
        "constraints":             merged_constraints,
    }
    _save_json(CONSTRAINTS_OUT, constraints_payload)
    logger.info("constraints_saved path=%s", CONSTRAINTS_OUT)

    # ── Archive processed items ───────────────────────────────────
    if not no_archive and not dry_run:
        archive: list[dict[str, Any]] = _load_json(HISTORY_ARCHIVE, [])
        if not isinstance(archive, list):
            archive = []
        archive.extend(queue)
        _save_json(HISTORY_ARCHIVE, archive)
        logger.info("history_archived entries=%d path=%s", len(queue), HISTORY_ARCHIVE)

    # ── Clear the active feedback queue ──────────────────────────
    if not dry_run:
        _save_json(FEEDBACK_QUEUE, [])
        logger.info("feedback_queue_cleared path=%s", FEEDBACK_QUEUE)
    else:
        logger.info("dry_run=True — feedback queue NOT cleared")

    # ── Summary banner ─────────────────────────────────────────────
    total_new = sum(len(v) for v in new_constraints.values())
    print("\n" + "=" * 60)
    print("STEP 6 — FEEDBACK LOOP REPORT")
    print("=" * 60)
    print(f"Failures ingested        : {len(queue)}")
    print(f"Strategy groups          : {len(grouped)}")
    print(f"Failures processed       : {processed_count}")
    print(f"New constraints written  : {total_new}")
    print(f"Model                    : {OLLAMA_MODEL} @ {OLLAMA_BASE_URL}")
    print(f"Elapsed                  : {elapsed:.1f}s")
    print(f"Constraints output       : {CONSTRAINTS_OUT}")
    if not no_archive and not dry_run:
        print(f"History archive          : {HISTORY_ARCHIVE}")
    print(f"Queue cleared            : {'Yes' if not dry_run else 'No (dry-run)'}")
    print("=" * 60 + "\n")

    return 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Step 6 — Automated Feedback Loop: distil rejection patterns into negative constraints"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print prompt payloads to stdout without calling Ollama or modifying any files",
    )
    parser.add_argument(
        "--no-archive",
        action="store_true",
        help="Skip writing to failed_feedback_history.json (queue is still cleared)",
    )
    parser.add_argument(
        "--min-failures",
        type=int,
        default=1,
        metavar="N",
        help="Minimum number of rejections required to trigger a constraint generation call for a strategy (default: 1)",
    )
    args = parser.parse_args()

    try:
        return run_feedback_loop(
            dry_run=args.dry_run,
            no_archive=args.no_archive,
            min_failures=args.min_failures,
        )
    except KeyboardInterrupt:
        logger.info("Feedback loop interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
