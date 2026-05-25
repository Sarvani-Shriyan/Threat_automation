import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator

from threat_pipeline.models.ingestion import NormalizedArticle, QueueItem, QueueStatus


class ThreatQueue:
    """SQLite-backed stateful queue — source of truth for pipeline stages."""

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self._db_path = str(db_path)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS dedup_cache (
                    content_hash TEXT PRIMARY KEY,
                    simhash INTEGER,
                    title TEXT,
                    article_url TEXT,
                    first_seen_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS threat_queue (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    article_json TEXT NOT NULL,
                    dropped_reason TEXT,
                    retry_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_queue_status ON threat_queue(status);
                """
            )

    def has_exact_hash(self, content_hash: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM dedup_cache WHERE content_hash = ?",
                (content_hash,),
            ).fetchone()
        return row is not None

    def has_near_duplicate(self, simhash: int, threshold: int) -> bool:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT simhash FROM dedup_cache WHERE simhash IS NOT NULL"
            ).fetchall()
        for row in rows:
            stored = row["simhash"]
            distance = bin(simhash ^ stored).count("1")
            if distance <= threshold:
                return True
        return False

    def register_dedup(self, content_hash: str, simhash: int | None, title: str, url: str | None) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO dedup_cache
                (content_hash, simhash, title, article_url, first_seen_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (content_hash, simhash, title, url, datetime.utcnow().isoformat()),
            )

    def enqueue(self, article: NormalizedArticle, content_hash: str) -> QueueItem:
        item_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        item = QueueItem(
            id=item_id,
            article=article,
            status=QueueStatus.PENDING,
            content_hash=content_hash,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
        )
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO threat_queue
                (id, status, content_hash, article_json, retry_count, created_at, updated_at)
                VALUES (?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    item.id,
                    item.status.value,
                    content_hash,
                    article.model_dump_json(),
                    now,
                    now,
                ),
            )
        return item

    def dequeue_next(self, status: QueueStatus = QueueStatus.PENDING) -> QueueItem | None:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM threat_queue
                WHERE status = ?
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (status.value,),
            ).fetchone()
        return self._row_to_item(row) if row else None

    def list_by_status(self, status: QueueStatus) -> list[QueueItem]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM threat_queue WHERE status = ? ORDER BY created_at ASC",
                (status.value,),
            ).fetchall()
        return [self._row_to_item(r) for r in rows]

    def update_status(
        self,
        item_id: str,
        status: QueueStatus,
        *,
        dropped_reason: str | None = None,
        increment_retry: bool = False,
    ) -> None:
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            if increment_retry:
                conn.execute(
                    """
                    UPDATE threat_queue
                    SET status = ?, dropped_reason = COALESCE(?, dropped_reason),
                        retry_count = retry_count + 1, updated_at = ?
                    WHERE id = ?
                    """,
                    (status.value, dropped_reason, now, item_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE threat_queue
                    SET status = ?, dropped_reason = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (status.value, dropped_reason, now, item_id),
                )

    def get_by_id(self, item_id: str) -> QueueItem | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM threat_queue WHERE id = ?", (item_id,)
            ).fetchone()
        return self._row_to_item(row) if row else None

    def pending_count(self) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM threat_queue WHERE status = ?",
                (QueueStatus.PENDING.value,),
            ).fetchone()
        return int(row["c"])

    @staticmethod
    def _row_to_item(row: sqlite3.Row) -> QueueItem:
        article = NormalizedArticle.model_validate_json(row["article_json"])
        return QueueItem(
            id=row["id"],
            article=article,
            status=QueueStatus(row["status"]),
            content_hash=row["content_hash"],
            dropped_reason=row["dropped_reason"],
            retry_count=row["retry_count"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
