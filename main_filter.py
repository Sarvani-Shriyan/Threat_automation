#!/usr/bin/env python3
"""
Step 2: 4-gate threat filtering pipeline.

Gate 1  Platform keyword match        (KeywordMatcher)
Gate 2  CVE / patch-bulletin drop     (CvePatchFilter)
Gate 3  Tiered semantic deduplication (SemanticDeduplicator)
          Tier 1 — SimHash Hamming near-duplicate check
          Tier 2 — LanceDB cosine-distance vector similarity check
Gate 4  Dynamic semantic relevance    (GemmaVerifier via Ollama)

After Gate 4 confirms an article, its SimHash fingerprint and dense embedding
are atomically registered into the local dedup stores so all subsequent runs
can measure against it.
"""

import argparse
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from filters.gemma_verifier import MIN_CONFIDENCE_SCORE, GemmaVerifier
from filters.keyword_matcher import CvePatchFilter, KeywordMatcher, extract_cve_ids, load_threat_queue
from filters.semantic_dedup import SemanticDeduplicator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("main_filter")

DEFAULT_INPUT = Path("data/threat_queue.json")
DEFAULT_OUTPUT = Path("data/filtered_threat_queue.json")
MAX_FILTERED_QUEUE_SIZE = 50


# ---------------------------------------------------------------------------
# Timestamp / priority helpers (unchanged)
# ---------------------------------------------------------------------------


def _parse_timestamp(article: dict) -> datetime:
    for field in ("timestamp", "published_at", "fetched_at"):
        raw = article.get(field)
        if not raw:
            continue
        try:
            text = raw.replace("Z", "+00:00") if isinstance(raw, str) else str(raw)
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except (ValueError, TypeError):
            continue
    return datetime.min.replace(tzinfo=timezone.utc)


def _confidence_score(article: dict) -> int:
    verdict = article.get("gemma_verdict")
    if not isinstance(verdict, dict):
        return 0
    raw = verdict.get("confidence_score", 0)
    try:
        return max(0, min(10, int(raw)))
    except (TypeError, ValueError):
        return 0


def _article_priority_key(article: dict) -> tuple[int, float]:
    """Higher confidence and newer timestamps rank first."""
    return (_confidence_score(article), _parse_timestamp(article).timestamp())


def _article_dedup_key(article: dict) -> str:
    url = article.get("url")
    if isinstance(url, str) and url.strip():
        return url.strip()
    title = article.get("title")
    if isinstance(title, str) and title.strip():
        return f"title:{title.strip()}"
    return json.dumps(article, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Output queue management (unchanged)
# ---------------------------------------------------------------------------


def load_existing_filtered_articles(output_path: Path) -> list[dict]:
    if not output_path.is_file():
        return []
    try:
        payload = json.loads(output_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not load existing filtered queue (%s); starting fresh", exc)
        return []
    articles = payload.get("articles")
    if not isinstance(articles, list):
        return []
    return [a for a in articles if isinstance(a, dict)]


def merge_and_cap_filtered_articles(
    existing: list[dict],
    new_articles: list[dict],
    *,
    cap: int = MAX_FILTERED_QUEUE_SIZE,
) -> tuple[list[dict], dict]:
    merged_by_key: dict[str, dict] = {}
    for article in existing + new_articles:
        merged_by_key[_article_dedup_key(article)] = article

    threat_list = list(merged_by_key.values())
    threat_list.sort(key=_article_priority_key, reverse=True)
    trimmed = threat_list[:cap]

    return trimmed, {
        "existing_loaded": len(existing),
        "new_confirmed_this_run": len(new_articles),
        "merged_before_cap": len(threat_list),
        "trimmed_count": max(0, len(threat_list) - len(trimmed)),
        "max_queue_size": cap,
        "min_confidence_score": MIN_CONFIDENCE_SCORE,
    }


def export_filtered_queue(
    articles: list[dict],
    *,
    output_path: Path,
    stats: dict,
) -> list[dict]:
    existing = load_existing_filtered_articles(output_path)
    capped_articles, cap_stats = merge_and_cap_filtered_articles(existing, articles)

    os.makedirs(output_path.parent, exist_ok=True)
    merged_stats = {
        **stats,
        **cap_stats,
        "confirmed_gemma_this_run": stats.get("confirmed_gemma", len(articles)),
        "final_queue_size": len(capped_articles),
    }
    payload = {
        "filtered_at": datetime.now(timezone.utc).isoformat(),
        "stats": merged_stats,
        "article_count": len(capped_articles),
        "articles": capped_articles,
    }
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    if cap_stats["trimmed_count"]:
        logger.info(
            "Capped filtered queue to %d items (trimmed %d)",
            len(capped_articles),
            cap_stats["trimmed_count"],
        )
    return capped_articles


# ---------------------------------------------------------------------------
# Console banner
# ---------------------------------------------------------------------------


def print_reduction_log(
    *,
    total_inputs: int,
    passed_keywords: int,
    survived_cve: int,
    tier1_dropped: int,
    tier2_dropped: int,
    dedup_passed: int,
    confirmed_gemma: int,
    final_queue_size: int,
    output_path: Path,
    dedup_available: tuple[bool, bool],
) -> None:
    tier1_label = "SimHash" if dedup_available[0] else "SimHash [SKIPPED — pkg missing]"
    tier2_label = (
        "LanceDB Vector" if dedup_available[1] else "LanceDB Vector [SKIPPED — pkg missing]"
    )
    print("\n" + "=" * 60)
    print("PIPELINE REDUCTION LOG")
    print("=" * 60)
    print(f"Total Inputs                   : {total_inputs}")
    print(f"Passed Keyword Gate            : {passed_keywords}")
    print(f"Survived CVE / Patch Gate      : {survived_cve}")
    print(f"  Tier 1 dropped ({tier1_label}): {tier1_dropped}")
    print(f"  Tier 2 dropped ({tier2_label}): {tier2_dropped}")
    print(f"  Passed Dedup Gate            : {dedup_passed}")
    print(
        f"Confirmed by Dynamic Filter    : {confirmed_gemma} "
        f"(is_relevant=true, score>={MIN_CONFIDENCE_SCORE})"
    )
    print(f"Final Queue Size (cap {MAX_FILTERED_QUEUE_SIZE})   : {final_queue_size}")
    print(f"Output File                    : {output_path}")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Gemma bypass (--skip-gemma mode)
# ---------------------------------------------------------------------------


def _build_skip_gemma_verdict(article: dict) -> dict:
    """Deterministic bypass payload for offline / test runs."""
    text = f"{article.get('title', '')}\n{article.get('content', '')}".lower()
    platform = "Unknown"
    for candidate in ("AWS", "Azure", "GCP", "GitHub", "Okta"):
        if candidate.lower() in text:
            platform = candidate
            break
    domain = (
        "Cloud"
        if platform in {"AWS", "Azure", "GCP"}
        else "SaaS"
        if platform == "GitHub"
        else "Identity"
        if platform == "Okta"
        else "Unrelated"
    )
    return {
        "is_relevant": True,
        "confidence_score": 8,
        "primary_domain": domain,
        "primary_platform": platform,
        "reasoning_summary": "Gemma skipped (--skip-gemma)",
    }


# ---------------------------------------------------------------------------
# Main async pipeline
# ---------------------------------------------------------------------------


async def run_filter_async(
    input_path: Path = DEFAULT_INPUT,
    output_path: Path = DEFAULT_OUTPUT,
    *,
    limit: int | None = None,
    skip_gemma: bool = False,
    max_workers: int | None = None,
    skip_dedup: bool = False,
) -> int:
    # ── Load input ───────────────────────────────────────────────────────────
    all_articles = load_threat_queue(input_path)
    articles = all_articles[:limit] if limit is not None else all_articles
    total_inputs = len(articles)

    # ── Gate 1: Platform keyword match ───────────────────────────────────────
    keyword_matcher = KeywordMatcher()
    keyword_passed, keyword_dropped = keyword_matcher.filter_articles(articles)
    passed_keywords = len(keyword_passed)

    # ── Gate 2: CVE / patch-bulletin drop ────────────────────────────────────
    cve_filter = CvePatchFilter()
    cve_survived, cve_dropped = cve_filter.filter_articles(keyword_passed)
    # Tag each surviving article with its CVE IDs for downstream NVD lookup.
    for article in cve_survived:
        article.setdefault("cve_ids", extract_cve_ids(article))
    survived_cve = len(cve_survived)

    # ── Gate 3: Tiered semantic deduplication ─────────────────────────────────
    tier1_dropped = 0
    tier2_dropped = 0
    dedup_passed_articles = cve_survived
    dedup: SemanticDeduplicator | None = None
    dedup_available = (False, False)

    if not skip_dedup:
        dedup = SemanticDeduplicator()

        # Probe which tiers are actually available (lazy pkg check)
        _t1_available = dedup._compute_simhash("probe") is not None
        _t2_available = (
            dedup._get_embedding_model() is not None
            and dedup._get_lancedb_table() is not None
        )
        dedup_available = (_t1_available, _t2_available)

        dedup_passed_articles, tier1_dropped, tier2_dropped = dedup.filter_articles(
            cve_survived
        )
        logger.info(
            "dedup_gate passed=%d t1_dropped=%d t2_dropped=%d",
            len(dedup_passed_articles),
            tier1_dropped,
            tier2_dropped,
        )
    else:
        logger.info("dedup_gate skipped (--skip-dedup flag)")

    dedup_passed = len(dedup_passed_articles)

    # ── Gate 4: Gemma dynamic semantic relevance filter ───────────────────────
    if skip_gemma:
        confirmed = []
        for article in dedup_passed_articles:
            verdict = _build_skip_gemma_verdict(article)
            title = (article.get("title") or "Untitled").strip()
            print(
                f"[Dynamic Filter] Title: {title} | "
                f"Domain: {verdict['primary_domain']} | "
                f"Score: {verdict['confidence_score']}/10"
            )
            enriched = dict(article)
            enriched["gemma_verdict"] = verdict
            confirmed.append(enriched)
        gemma_rejected = 0
    else:
        verifier = GemmaVerifier(max_workers=max_workers or 4)
        confirmed, gemma_rejected = await verifier.verify_batch_async(
            dedup_passed_articles
        )

    # ── Register confirmed articles into dedup stores ─────────────────────────
    # This runs synchronously after Gemma so that only high-signal confirmed
    # threats are stored in the SimHash state and LanceDB vector table.
    if dedup is not None and confirmed:
        logger.info(
            "dedup_register_confirmed count=%d", len(confirmed)
        )
        dedup.register_confirmed_batch(confirmed)
        logger.info(
            "dedup_stores_updated simhash_entries=%d lancedb_rows=%d",
            dedup.simhash_entry_count,
            dedup.lancedb_row_count(),
        )

    # ── Compile stats and write output ────────────────────────────────────────
    stats = {
        "total_in_file": len(all_articles),
        "total_inputs": total_inputs,
        "keyword_dropped": keyword_dropped,
        "passed_keywords": passed_keywords,
        "cve_patch_dropped": cve_dropped,
        "survived_cve_patch_filter": survived_cve,
        "tier1_simhash_dropped": tier1_dropped,
        "tier2_vector_dropped": tier2_dropped,
        "passed_dedup_gate": dedup_passed,
        "gemma_rejected": gemma_rejected,
        "confirmed_gemma": len(confirmed),
        "min_confidence_score": MIN_CONFIDENCE_SCORE,
    }
    capped_articles = export_filtered_queue(
        confirmed, output_path=output_path, stats=stats
    )
    print_reduction_log(
        total_inputs=total_inputs,
        passed_keywords=passed_keywords,
        survived_cve=survived_cve,
        tier1_dropped=tier1_dropped,
        tier2_dropped=tier2_dropped,
        dedup_passed=dedup_passed,
        confirmed_gemma=len(confirmed),
        final_queue_size=len(capped_articles),
        output_path=output_path,
        dedup_available=dedup_available,
    )
    print(f"Successfully exported {len(capped_articles)} articles to {output_path}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Threat pipeline Step 2 — 4-gate semantic filter"
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--skip-gemma", action="store_true")
    parser.add_argument(
        "--skip-dedup",
        action="store_true",
        help="Bypass Tier 1 + Tier 2 semantic deduplication gates",
    )
    parser.add_argument("--workers", type=int, default=None, help="Parallel Gemma workers")
    args = parser.parse_args()

    try:
        return asyncio.run(
            run_filter_async(
                args.input,
                args.output,
                limit=args.limit,
                skip_gemma=args.skip_gemma,
                skip_dedup=args.skip_dedup,
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
