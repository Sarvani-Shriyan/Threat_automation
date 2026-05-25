import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import feedparser
import httpx
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class RawFeedEntry:
    source: str
    title: str
    url: str | None
    published_at: datetime | None
    raw_html: str | None
    raw_text: str | None
    metadata: dict[str, Any]


class FeedFetcher:
    def __init__(self, timeout_seconds: float = 30.0) -> None:
        self._timeout = timeout_seconds

    def fetch_all(self, feed_urls: list[str]) -> list[RawFeedEntry]:
        entries: list[RawFeedEntry] = []
        for url in feed_urls:
            entries.extend(self._fetch_feed(url))
        return entries

    def _fetch_feed(self, feed_url: str) -> list[RawFeedEntry]:
        logger.info("fetching_feed", url=feed_url)
        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            response = client.get(feed_url)
            response.raise_for_status()
            parsed = feedparser.parse(response.text)

        source = parsed.feed.get("title", feed_url)
        results: list[RawFeedEntry] = []
        for entry in parsed.entries:
            published = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                published = datetime(*entry.published_parsed[:6])
            raw_html = entry.get("summary", "") or entry.get("description", "")
            results.append(
                RawFeedEntry(
                    source=source,
                    title=entry.get("title", "Untitled"),
                    url=entry.get("link"),
                    published_at=published,
                    raw_html=raw_html,
                    raw_text=entry.get("content", [{}])[0].get("value") if entry.get("content") else None,
                    metadata={"feed_url": feed_url, "entry_id": entry.get("id")},
                )
            )
        return results


class MockStreamFetcher:
    def __init__(self, path: Path) -> None:
        self._path = path

    def fetch_all(self) -> list[RawFeedEntry]:
        data = json.loads(self._path.read_text(encoding="utf-8"))
        entries: list[RawFeedEntry] = []
        for doc in data:
            published = None
            if doc.get("published_at"):
                published = datetime.fromisoformat(doc["published_at"].replace("Z", "+00:00"))
            entries.append(
                RawFeedEntry(
                    source=doc["source"],
                    title=doc["title"],
                    url=doc.get("url"),
                    published_at=published,
                    raw_html=doc.get("raw_html"),
                    raw_text=doc.get("raw_text"),
                    metadata=doc.get("metadata", {}),
                )
            )
        return entries
