#!/usr/bin/env python3
# pip install openai pydantic cvss
"""
Step 3: Grounded streaming rule generation with knowledge-base retrieval.
"""

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Any

# Ensure src/ is importable when running as a script from the project root.
_SRC_DIR = Path(__file__).resolve().parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from threat_pipeline.utils.cvss_severity import apply_official_severity  # noqa: E402

from generators.io import (
    DEFAULT_FILTERED_INPUT,
    DEFAULT_STAGING_OUTPUT,
    StagingStore,
    load_filtered_threats,
)
from generators.knowledge_base import GroundingResult, KnowledgeBase
from generators.rule_engine import DEFAULT_API_KB_PATH, RuleEngine
from ingestion.config import KNOWLEDGE_BASE_DIR, KNOWLEDGE_BASE_MAX_ACTIONS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("main_generator")


def _print_kb_banner(kb: KnowledgeBase, api_kb_path: Path) -> None:
    print("\n" + "=" * 60)
    print("KNOWLEDGE BASE — GROUNDED RETRIEVAL")
    print("=" * 60)
    print(f"Catalog path              : {kb.base_dir.resolve()}")
    print(f"Catalogs loaded           : {kb.catalog_count}")
    print(f"Max actions per threat    : {kb.max_actions}")
    print(f"Status                    : {'READY' if kb.is_loaded else 'EMPTY — run scripts/sync_knowledge_base.py'}")
    for entry in kb.entries:
        tag = f" [{entry.source}]" if entry.source else ""
        print(f"  - {entry.platform}: {len(entry.action_names)} actions ({entry.source_file}){tag}")
    api_kb_status = (
        f"LOADED ({api_kb_path})" if api_kb_path.is_file()
        else f"NOT FOUND — using KB-directory grounding only ({api_kb_path})"
    )
    print(f"Supplementary API KB      : {api_kb_status}")
    print("=" * 60 + "\n")
    logger.info("kb_init %s", kb.summary())


def _print_queue_banner(total: int, output_path: Path, already_staged: int) -> None:
    print("=" * 60)
    print("PHI4-MINI-REASONING — THREAT-CENTRIC MULTI-VARIANT RULES")
    print("=" * 60)
    print(f"Threats queued this run     : {total}")
    print(f"Already in staging file     : {already_staged}")
    print(f"Incremental output          : {output_path}")
    print("=" * 60 + "\n")


def _on_before(
    index: int,
    total: int,
    threat: dict[str, Any],
    grounding: GroundingResult,
) -> None:
    title = threat.get("title", "Untitled")
    platforms = ", ".join(grounding.matched_platforms) or "none"
    print(f"[Processing Threat {index}/{total}] Analyzing: {title}...")
    profiles = ", ".join(grounding.routed_profiles) or "default"
    print(
        f"[Grounding] Platforms=[{platforms}] | Profiles=[{profiles}] | "
        f"Injected {grounding.action_count} verified actionNames | "
        f"Sources={grounding.source_files or ['n/a']}"
    )
    if grounding.allowed_actions:
        preview = ", ".join(grounding.allowed_actions[:5])
        if grounding.action_count > 5:
            preview += ", ..."
        print(f"[Grounding] Vocabulary sample: {preview}")
    logger.info(
        "kb_grounding threat=%s platforms=%s actions=%d sources=%s",
        title,
        platforms,
        grounding.action_count,
        grounding.source_files,
    )


def _make_on_after(store: StagingStore):
    def _on_after(
        index: int,
        total: int,
        threat: dict[str, Any],
        entry: dict[str, Any],
        elapsed: float,
    ) -> None:
        title = threat.get("title", "Untitled")

        # Apply official CVSS severity override for every generated variant.
        # If the threat advisory carries a CVSS vector, its qualitative text
        # label ("Low" / "Medium" / "High" / "Critical") replaces the AI's
        # estimated severity.  When no vector is present the AI's value is
        # retained after capitalisation/validation.
        variants = entry.get("variants") or []
        if variants:
            entry["variants"] = [
                apply_official_severity(v, threat) for v in variants
            ]

        store.append_entry(entry)
        grounded = entry.get("grounding_context", {})
        injected = grounded.get("injected_action_count", 0)

        if entry.get("generation_status") == "success":
            count = entry.get("variant_count", 0)
            print(
                f"[Success] Generated {count} variants for {title} in {elapsed:.1f}s "
                f"(grounded with {injected} actionNames)."
            )
        else:
            err = entry.get("error", "unknown error")
            print(
                f"[Failed] Threat {index}/{total} — {title} — {elapsed:.1f}s — {err}"
            )

    return _on_after


def print_final_report(
    *,
    queued: int,
    processed_this_run: int,
    skipped: int,
    success: int,
    failed: int,
    total_variants: int,
    elapsed: float,
    output_path: Path,
    kb: KnowledgeBase,
) -> None:
    print("\n" + "=" * 60)
    print("RULE GENERATION REPORT")
    print("=" * 60)
    print(f"Knowledge Base Catalogs   : {kb.catalog_count}")
    print(f"Threats Queued            : {queued}")
    print(f"Processed This Run        : {processed_this_run}")
    print(f"Skipped (already staged)  : {skipped}")
    print(f"Successful                : {success}")
    print(f"Failed                    : {failed}")
    print(f"Variants This Run         : {total_variants}")
    print(f"Total Elapsed             : {elapsed:.1f}s")
    print(f"Staging Output            : {output_path}")
    print("=" * 60 + "\n")


def run_generation(
    input_path: Path = DEFAULT_FILTERED_INPUT,
    output_path: Path = DEFAULT_STAGING_OUTPUT,
    kb_dir: Path | None = None,
    api_kb_path: Path | None = None,
    *,
    limit: int | None = None,
    resume: bool = True,
    force: bool = False,
    platforms: list[str] | None = None,
) -> int:
    _api_kb_path = api_kb_path if api_kb_path is not None else DEFAULT_API_KB_PATH

    kb = KnowledgeBase(
        base_dir=kb_dir or Path(KNOWLEDGE_BASE_DIR),
        max_actions=KNOWLEDGE_BASE_MAX_ACTIONS,
        platforms=platforms,
    )
    _print_kb_banner(kb, _api_kb_path)

    threats = load_filtered_threats(input_path)
    if limit is not None:
        threats = threats[:limit]
    queued = len(threats)

    store = StagingStore(output_path)
    if force and store.path.exists():
        store.path.unlink()
        store = StagingStore(output_path)

    skip_ids = store.processed_threat_ids() if resume else set()
    already_staged = len(skip_ids)

    _print_queue_banner(queued, store.path, already_staged)

    engine = RuleEngine(knowledge_base=kb, api_kb_path=_api_kb_path)
    on_after = _make_on_after(store)
    run_started = time.perf_counter()

    entries = engine.process_threat_stream(
        threats,
        on_before=_on_before,
        on_after=on_after,
        skip_ids=skip_ids,
    )

    run_elapsed = time.perf_counter() - run_started
    success = sum(1 for e in entries if e.get("generation_status") == "success")
    failed = len(entries) - success
    total_variants = sum(e.get("variant_count", 0) for e in entries)
    skipped = queued - len(entries)

    store.update_run_stats(
        {
            "knowledge_base_dir": str(kb.base_dir.resolve()),
            "knowledge_base_catalogs": kb.catalog_count,
            "input_threats": queued,
            "processed_this_run": len(entries),
            "skipped_resume": skipped,
            "successful_generations": success,
            "failed_generations": failed,
            "total_rule_variants_this_run": total_variants,
            "elapsed_seconds": round(run_elapsed, 1),
        }
    )

    print_final_report(
        queued=queued,
        processed_this_run=len(entries),
        skipped=skipped,
        success=success,
        failed=failed,
        total_variants=total_variants,
        elapsed=run_elapsed,
        output_path=store.path,
        kb=kb,
    )
    print(f"Staging file updated: {store.path} ({len(store.load_entries())} total entries)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Threat pipeline Step 3 — grounded streaming rule generation"
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_FILTERED_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_STAGING_OUTPUT)
    parser.add_argument(
        "--kb-dir",
        type=Path,
        default=Path(KNOWLEDGE_BASE_DIR),
        help="Directory of authoritative JSON event/action schemas",
    )
    parser.add_argument(
        "--api-kb",
        type=Path,
        default=DEFAULT_API_KB_PATH,
        help="Supplementary flat per-platform API knowledge base JSON (default: data/api_knowledge_base.json)",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--platforms",
        type=str,
        default=None,
        help="Comma-separated KB platforms only (e.g. aws,gcp)",
    )
    args = parser.parse_args()
    platform_list = None
    if args.platforms:
        platform_list = [p.strip().lower() for p in args.platforms.split(",") if p.strip()]

    try:
        return run_generation(
            args.input,
            args.output,
            kb_dir=args.kb_dir,
            api_kb_path=args.api_kb,
            limit=args.limit,
            resume=not args.no_resume,
            force=args.force,
            platforms=platform_list,
        )
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        print("\n[Interrupted] Progress saved incrementally to staging file.")
        logger.info("Rule generation interrupted — partial staging preserved")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
