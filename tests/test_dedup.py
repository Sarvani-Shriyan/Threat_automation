import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from threat_pipeline.ingestion.deduplication import DeduplicationEngine
from threat_pipeline.ingestion.threat_queue import ThreatQueue
from threat_pipeline.models.ingestion import NormalizedArticle


@pytest.fixture
def queue() -> ThreatQueue:
    return ThreatQueue(":memory:")


@pytest.fixture
def dedup(queue: ThreatQueue) -> DeduplicationEngine:
    return DeduplicationEngine(queue, hamming_threshold=3)


def _article(title: str, url: str, body: str) -> NormalizedArticle:
    return NormalizedArticle(
        source="test",
        title=title,
        url=url,
        content_markdown=body,
        content_plain=body,
        published_at=datetime.utcnow(),
    )


def test_exact_duplicate_dropped(dedup: DeduplicationEngine, queue: ThreatQueue) -> None:
    a = _article("AWS Alert", "https://x/1", "CloudTrail logging disabled")
    is_dup, reason, record = dedup.is_duplicate(a)
    assert not is_dup
    queue.register_dedup(record.content_hash, record.simhash, a.title, a.url)
    queue.enqueue(a, record.content_hash)

    b = _article("AWS Alert", "https://x/1", "Different body but same title/url")
    is_dup2, reason2, _ = dedup.is_duplicate(b)
    assert is_dup2
    assert reason2 == "exact_hash"


def test_unique_articles_enqueued(dedup: DeduplicationEngine, queue: ThreatQueue) -> None:
    articles = [
        _article("Okta Bypass", "https://x/2", "Okta MFA fatigue attack"),
        _article("CloudTrail Gap", "https://x/3", "AWS CloudTrail gaps in eu-west-1"),
    ]
    for art in articles:
        is_dup, _, rec = dedup.is_duplicate(art)
        assert not is_dup
        queue.register_dedup(rec.content_hash, rec.simhash, art.title, art.url)
        queue.enqueue(art, rec.content_hash)
    assert queue.pending_count() == 2
