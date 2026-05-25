# pip install aiohttp feedparser pydantic

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ingestion.crawler import NormalizedArticle

logger = logging.getLogger(__name__)

DEFAULT_STATE_FILE = Path("data/ingestion_dedup_state.json")
DEFAULT_QUEUE_EXPORT = Path("data/threat_queue.json")


def _article_export_key(article: NormalizedArticle | dict[str, Any]) -> str:
    if isinstance(article, NormalizedArticle):
        title = article.title
        url = article.url or ""
    else:
        title = article.get("title", "")
        url = article.get("url") or ""
    return f"{title.strip().lower()}|{str(url).strip().lower()}"


def _article_to_export_dict(article: NormalizedArticle, timestamp: str) -> dict[str, Any]:
    return {
        "source": article.source,
        "title": article.title,
        "url": article.url,
        "content": article.raw_content,
        "timestamp": timestamp,
    }


def export_queue_to_disk(
    queue: list[NormalizedArticle],
    file_path: str | Path = DEFAULT_QUEUE_EXPORT,
) -> int:
    """
    Persist the full Threat Queue to JSON on disk.

    Merges with an existing export file so re-runs do not wipe prior articles.
    Returns the number of articles written to the file.
    """
    path = Path(file_path)
    os.makedirs(path.parent, exist_ok=True)

    exported_at = datetime.now(timezone.utc).isoformat()
    merged: dict[str, dict[str, Any]] = {}

    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            for item in existing.get("articles", []):
                key = _article_export_key(item)
                merged[key] = item
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("queue_export_load_failed", extra={"error": str(exc)})

    for article in queue:
        key = _article_export_key(article)
        merged[key] = _article_to_export_dict(article, exported_at)

    articles = list(merged.values())
    payload = {
        "exported_at": exported_at,
        "article_count": len(articles),
        "articles": articles,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("queue_exported", extra={"path": str(path), "count": len(articles)})
    return len(articles)


class QueueManager:
    """
    SHA-256 deduplication (title + URL) and thread-safe Threat Queue.

    Persists seen hashes to a local JSON file for stateful runs across restarts.
    """

    def __init__(self, state_file: Path | str = DEFAULT_STATE_FILE) -> None:
        self._state_file = Path(state_file)
        self._lock = threading.Lock()
        self._seen_hashes: set[str] = set()
        self._threat_queue: list[NormalizedArticle] = []
        self._load_state()

    def _content_hash(self, article: NormalizedArticle) -> str:
        key = f"{article.title.strip().lower()}|{(article.url or '').strip().lower()}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def _load_state(self) -> None:
        if not self._state_file.exists():
            return
        try:
            data = json.loads(self._state_file.read_text(encoding="utf-8"))
            self._seen_hashes = set(data.get("hashes", []))
            logger.info("dedup_state_loaded", extra={"count": len(self._seen_hashes)})
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("dedup_state_load_failed", extra={"error": str(exc)})

    def _save_state(self) -> None:
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {"hashes": sorted(self._seen_hashes)}
        self._state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def is_duplicate(self, article: NormalizedArticle) -> bool:
        digest = self._content_hash(article)
        with self._lock:
            return digest in self._seen_hashes

    def enqueue_unique(self, article: NormalizedArticle) -> bool:
        """
        Return True if article was new and appended; False if duplicate.
        """
        digest = self._content_hash(article)
        with self._lock:
            if digest in self._seen_hashes:
                return False
            self._seen_hashes.add(digest)
            self._threat_queue.append(article)
        return True

    def ingest_batch(self, articles: list[NormalizedArticle]) -> tuple[int, int]:
        """Process articles; returns (enqueued_count, duplicate_count)."""
        enqueued = 0
        duplicates = 0
        for article in articles:
            if self.enqueue_unique(article):
                enqueued += 1
            else:
                duplicates += 1
        self._save_state()
        return enqueued, duplicates

    def get_queue(self) -> list[NormalizedArticle]:
        with self._lock:
            return list(self._threat_queue)

    def queue_size(self) -> int:
        with self._lock:
            return len(self._threat_queue)

    def seen_count(self) -> int:
        with self._lock:
            return len(self._seen_hashes)

    def export_to_disk(self, file_path: str | Path = DEFAULT_QUEUE_EXPORT) -> int:
        """Export the current in-memory Threat Queue to JSON."""
        return export_queue_to_disk(self.get_queue(), file_path=file_path)
