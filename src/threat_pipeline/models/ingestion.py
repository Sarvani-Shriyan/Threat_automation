from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class QueueStatus(str, Enum):
    PENDING = "pending"
    FILTERED = "filtered"
    CONFIRMED = "confirmed"
    RULES_GENERATED = "rules_generated"
    VALIDATED = "validated"
    HITL_READY = "hitl_ready"
    COMPLETED = "completed"
    FAILED = "failed"


class NormalizedArticle(BaseModel):
    source: str
    title: str
    published_at: datetime | None = None
    url: str | None = None
    content_markdown: str
    content_plain: str
    fetched_at: datetime = Field(default_factory=datetime.utcnow)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class DedupRecord(BaseModel):
    content_hash: str
    simhash: int | None = None
    article_url: str | None = None
    title: str
    first_seen_at: datetime = Field(default_factory=datetime.utcnow)


class QueueItem(BaseModel):
    id: str
    article: NormalizedArticle
    status: QueueStatus = QueueStatus.PENDING
    content_hash: str
    dropped_reason: str | None = None
    retry_count: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
