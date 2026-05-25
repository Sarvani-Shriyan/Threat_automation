#!/usr/bin/env python3
# pip install openai pydantic
"""
Step 2: Platform keyword gate -> CVE patch gate -> parallel Gemma 4 verification.
"""

import argparse
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from filters.gemma_verifier import GemmaVerifier
from filters.keyword_matcher import CvePatchFilter, KeywordMatcher, load_threat_queue

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("main_filter")

DEFAULT_INPUT = Path("data/threat_queue.json")
DEFAULT_OUTPUT = Path("data/filtered_threat_queue.json")


def export_filtered_queue(articles: list[dict], *, output_path: Path, stats: dict) -> None:
    os.makedirs(output_path.parent, exist_ok=True)
    payload = {
        "filtered_at": datetime.now(timezone.utc).isoformat(),
        "stats": stats,
        "article_count": len(articles),
        "articles": articles,
    }
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def print_reduction_log(
    *,
    total_inputs: int,
    passed_keywords: int,
    survived_cve: int,
    confirmed_gemma: int,
    output_path: Path,
) -> None:
    print("\n" + "=" * 60)
    print("PIPELINE REDUCTION LOG")
    print("=" * 60)
    print(f"Total Inputs                 : {total_inputs}")
    print(f"Passed Keywords              : {passed_keywords}")
    print(f"Survived CVE Patch Filter    : {survived_cve}")
    print(f"Confirmed by Gemma 4         : {confirmed_gemma}")
    print(f"Final Queue Size             : {confirmed_gemma}")
    print(f"Output File                  : {output_path}")
    print("=" * 60 + "\n")


async def run_filter_async(
    input_path: Path = DEFAULT_INPUT,
    output_path: Path = DEFAULT_OUTPUT,
    *,
    limit: int | None = None,
    skip_gemma: bool = False,
    max_workers: int | None = None,
) -> int:
    all_articles = load_threat_queue(input_path)
    articles = all_articles[:limit] if limit is not None else all_articles
    total_inputs = len(articles)

    keyword_matcher = KeywordMatcher()
    keyword_passed, keyword_dropped = keyword_matcher.filter_articles(articles)
    passed_keywords = len(keyword_passed)

    cve_filter = CvePatchFilter()
    cve_survived, cve_dropped = cve_filter.filter_articles(keyword_passed)
    survived_cve = len(cve_survived)

    if skip_gemma:
        confirmed = []
        for a in cve_survived:
            enriched = dict(a)
            enriched["gemma_verdict"] = {
                "relevant": True,
                "justification": "Gemma skipped (--skip-gemma)",
                "mitre_tactic_hint": "",
            }
            confirmed.append(enriched)
        gemma_rejected = 0
    else:
        verifier = GemmaVerifier(max_workers=max_workers or 4)
        confirmed, gemma_rejected = await verifier.verify_batch_async(cve_survived)

    stats = {
        "total_in_file": len(all_articles),
        "total_inputs": total_inputs,
        "keyword_dropped": keyword_dropped,
        "passed_keywords": passed_keywords,
        "cve_patch_dropped": cve_dropped,
        "survived_cve_patch_filter": survived_cve,
        "gemma_rejected": gemma_rejected,
        "confirmed_gemma": len(confirmed),
        "final_queue_size": len(confirmed),
    }
    export_filtered_queue(confirmed, output_path=output_path, stats=stats)
    print_reduction_log(
        total_inputs=total_inputs,
        passed_keywords=passed_keywords,
        survived_cve=survived_cve,
        confirmed_gemma=len(confirmed),
        output_path=output_path,
    )
    print(f"Successfully exported {len(confirmed)} articles to {output_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Threat pipeline Step 2")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--skip-gemma", action="store_true")
    parser.add_argument("--workers", type=int, default=None, help="Parallel Gemma workers")
    args = parser.parse_args()

    try:
        return asyncio.run(
            run_filter_async(
                args.input,
                args.output,
                limit=args.limit,
                skip_gemma=args.skip_gemma,
                max_workers=args.workers,
            )
        )
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        logger.info("Filter pipeline interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
