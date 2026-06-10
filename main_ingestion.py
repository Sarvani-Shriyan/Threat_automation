#!/usr/bin/env python3
# pip install aiohttp feedparser pydantic
"""
Ingestion orchestrator: async crawl -> dedupe -> Threat Queue -> summary.
"""

import asyncio
import logging
import sys
from pathlib import Path

from ingestion.config import INGESTION_MAX_AGE_DAYS, RSS_FEED_LINKS
from ingestion.crawler import FeedCrawler
from ingestion.queue_manager import (
    DEFAULT_QUEUE_EXPORT,
    DEFAULT_STATE_FILE,
    QueueManager,
    export_queue_to_disk,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("main_ingestion")


def _print_summary(
    *,
    feeds_total: int,
    fetched: int,
    enqueued: int,
    duplicates: int,
    exported: int,
    pruned_on_export: int,
    queue: list,
    feed_errors: dict[str, int] | None = None,
    max_age_days: int = INGESTION_MAX_AGE_DAYS,
) -> None:
    print("\n" + "=" * 60)
    print("INGESTION SUMMARY")
    print("=" * 60)
    print(f"Feeds configured     : {feeds_total}")
    print(f"Ingestion window     : last {max_age_days} days (UTC)")
    print(f"Articles fetched     : {fetched}")
    print(f"Unique enqueued      : {enqueued}")
    print(f"Duplicates dropped   : {duplicates}")
    print(f"Threat Queue size    : {len(queue)}")
    print(f"On disk (merged)     : {exported}")
    print(f"Pruned (stale/undated on export): {pruned_on_export}")
    if feed_errors:
        err_parts = [f"{k}={v}" for k, v in feed_errors.items() if v]
        if err_parts:
            print(f"Feed issues          : {', '.join(err_parts)}")
        stale = feed_errors.get("stale_dropped", 0)
        undated = feed_errors.get("undated_dropped", 0)
        if stale or undated:
            print(
                f"Recency filter       : {stale} older than {max_age_days}d, "
                f"{undated} missing publish date"
            )
    if fetched == 0:
        print("-" * 60)
        print(
            "WARNING: 0 articles fetched. Common causes: network/VPN, all feeds "
            "timed out (see feed_timeout in logs), or stale RSS URLs. Re-run after "
            "fix; use a fresh export only if data/threat_queue.json should be rebuilt."
        )
    print("-" * 60)
    print("Sample unique items (up to 5):")
    for i, article in enumerate(queue[:5], start=1):
        print(f"\n[{i}] {article.title}")
        print(f"    Source : {article.source}")
        published = (
            article.published_at.strftime("%Y-%m-%d %H:%M UTC")
            if article.published_at
            else "N/A"
        )
        print(f"    Published : {published}")
        print(f"    URL    : {article.url or 'N/A'}")
        preview = article.raw_content[:120] + ("..." if len(article.raw_content) > 120 else "")
        print(f"    Preview: {preview}")
    if len(queue) > 5:
        print(f"\n... and {len(queue) - 5} more item(s) in queue.")
    print("=" * 60 + "\n")


async def run_ingestion(state_file: Path = DEFAULT_STATE_FILE) -> list:
    crawler = FeedCrawler(feed_urls=RSS_FEED_LINKS)
    queue_mgr = QueueManager(state_file=state_file)

    logger.info(
        "Starting crawl of %d feeds (window=%d days)",
        len(RSS_FEED_LINKS),
        INGESTION_MAX_AGE_DAYS,
    )
    articles = await crawler.crawl_all()
    logger.info("Fetched %d articles within ingestion window", len(articles))

    enqueued, duplicates = queue_mgr.ingest_batch(articles)
    threat_queue = queue_mgr.get_queue()

    exported_count, pruned_count = export_queue_to_disk(
        articles,
        file_path=DEFAULT_QUEUE_EXPORT,
    )
    print(
        f"Successfully exported {exported_count} articles to {DEFAULT_QUEUE_EXPORT} "
        f"(pruned {pruned_count} stale/undated)"
    )

    _print_summary(
        feeds_total=len(RSS_FEED_LINKS),
        fetched=len(articles),
        enqueued=enqueued,
        duplicates=duplicates,
        exported=exported_count,
        pruned_on_export=pruned_count,
        queue=threat_queue,
        feed_errors=crawler.feed_errors,
        max_age_days=INGESTION_MAX_AGE_DAYS,
    )
    return threat_queue


def main() -> int:
    state_path = Path("data/ingestion_dedup_state.json")
    if len(sys.argv) > 1:
        state_path = Path(sys.argv[1])

    try:
        asyncio.run(run_ingestion(state_file=state_path))
    except KeyboardInterrupt:
        logger.info("Ingestion interrupted by user")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
