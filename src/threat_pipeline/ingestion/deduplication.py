import hashlib
import re
from typing import TYPE_CHECKING

from simhash import Simhash

from threat_pipeline.models.ingestion import DedupRecord, NormalizedArticle

if TYPE_CHECKING:
    from threat_pipeline.ingestion.threat_queue import ThreatQueue


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.lower().strip())


class DeduplicationEngine:
    """Exact hash dedup + optional near-duplicate via SimHash."""

    def __init__(
        self,
        queue: "ThreatQueue",
        hamming_threshold: int = 3,
    ) -> None:
        self._queue = queue
        self._hamming_threshold = hamming_threshold

    def content_hash(self, article: NormalizedArticle) -> str:
        key = "|".join(
            [
                _normalize_text(article.title),
                (article.url or "").lower().strip(),
            ]
        )
        return hashlib.sha256(key.encode()).hexdigest()

    def simhash_value(self, article: NormalizedArticle) -> int:
        sample = article.content_plain[:2000]
        return Simhash(sample.split()).value

    def is_duplicate(self, article: NormalizedArticle) -> tuple[bool, str, DedupRecord]:
        content_hash = self.content_hash(article)
        simhash = self.simhash_value(article)

        if self._queue.has_exact_hash(content_hash):
            return True, "exact_hash", DedupRecord(
                content_hash=content_hash,
                simhash=simhash,
                article_url=article.url,
                title=article.title,
            )

        if self._queue.has_near_duplicate(simhash, self._hamming_threshold):
            return True, "near_duplicate", DedupRecord(
                content_hash=content_hash,
                simhash=simhash,
                article_url=article.url,
                title=article.title,
            )

        return False, "", DedupRecord(
            content_hash=content_hash,
            simhash=simhash,
            article_url=article.url,
            title=article.title,
        )
