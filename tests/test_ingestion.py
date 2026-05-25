import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from threat_pipeline.ingestion.fetcher import RawFeedEntry
from threat_pipeline.ingestion.normalizer import ContentNormalizer


@pytest.fixture
def normalizer() -> ContentNormalizer:
    return ContentNormalizer()


def test_strip_scripts_and_ads(normalizer: ContentNormalizer) -> None:
    entry = RawFeedEntry(
        source="test.example",
        title="CloudTrail Alert",
        url="https://example.com/1",
        published_at=datetime.utcnow(),
        raw_html=(
            "<article><h1>AWS CloudTrail</h1>"
            "<script>evil()</script>"
            "<div class='ad-banner'>Buy now</motion-div>"
            "<p>CloudTrail disabled in production.</p></article>"
        ),
        raw_text=None,
        metadata={},
    )
    article = normalizer.normalize(entry)
    assert "evil" not in article.content_plain
    assert "Buy now" not in article.content_plain
    assert "CloudTrail" in article.content_plain
    assert article.source == "test.example"
    assert article.title == "CloudTrail Alert"


def test_plain_text_input(normalizer: ContentNormalizer) -> None:
    entry = RawFeedEntry(
        source="plain.example",
        title="Okta Issue",
        url=None,
        published_at=None,
        raw_html=None,
        raw_text="Okta MFA bypass reported alongside AWS federation abuse.",
        metadata={},
    )
    article = normalizer.normalize(entry)
    assert "Okta" in article.content_plain
    assert article.content_markdown
