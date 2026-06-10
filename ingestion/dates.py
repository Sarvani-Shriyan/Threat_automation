# pip install feedparser

import time
from datetime import datetime, timedelta, timezone
from typing import Any

from ingestion.config import INGESTION_MAX_AGE_DAYS


def ingestion_cutoff(*, max_age_days: int | None = None) -> datetime:
    days = INGESTION_MAX_AGE_DAYS if max_age_days is None else max_age_days
    return datetime.now(timezone.utc) - timedelta(days=days)


def parse_feed_entry_published(entry: dict[str, Any]) -> datetime | None:
    """Extract publication time from a feedparser entry, normalized to UTC."""
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        parsed = entry.get(key)
        if not parsed:
            continue
        try:
            return datetime.fromtimestamp(time.mktime(parsed), tz=timezone.utc)
        except (OverflowError, OSError, ValueError, TypeError):
            continue
    return None


def parse_article_published(raw: Any) -> datetime | None:
    """Parse published_at / timestamp from a queue export dict."""
    if not raw:
        return None
    try:
        text = raw.replace("Z", "+00:00") if isinstance(raw, str) else str(raw)
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def is_within_ingestion_window(
    article: dict[str, Any],
    cutoff: datetime,
) -> bool:
    """
    True if the article has a known publication time within the ingestion window.
    Items without published_at are excluded (legacy export timestamps are not trusted).
    """
    published = parse_article_published(article.get("published_at"))
    if published is None:
        return False
    return published >= cutoff
