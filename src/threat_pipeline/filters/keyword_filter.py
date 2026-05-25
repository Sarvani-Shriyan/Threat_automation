import structlog

from config.settings import Settings
from threat_pipeline.ingestion.threat_queue import ThreatQueue
from threat_pipeline.llm.client_factory import LLMClientFactory
from threat_pipeline.llm.prompts import RELEVANCE_SYSTEM, RELEVANCE_USER_TEMPLATE
from threat_pipeline.models.ingestion import QueueStatus
from threat_pipeline.models.pipeline import RelevanceVerdict

logger = structlog.get_logger(__name__)


class KeywordFilterStage:
    """Programmatic keyword match + SLM binary relevance confirmation."""

    def __init__(
        self,
        queue: ThreatQueue,
        llm: LLMClientFactory,
        settings: Settings,
    ) -> None:
        self._queue = queue
        self._llm = llm
        self._settings = settings
        self._keywords = [k.lower() for k in settings.keywords]

    def run(self) -> list[str]:
        confirmed_ids: list[str] = []
        while True:
            item = self._queue.dequeue_next(QueueStatus.PENDING)
            if not item:
                break

            text = f"{item.article.title}\n{item.article.content_plain}".lower()
            if not any(kw in text for kw in self._keywords):
                self._queue.update_status(
                    item.id,
                    QueueStatus.FILTERED,
                    dropped_reason="keyword_miss",
                )
                logger.info("keyword_miss", threat_id=item.id)
                continue

            verdict = self._confirm_relevance(item.article.title, item.article.source, item.article.content_plain[:1500])
            if not verdict.is_threat:
                self._queue.update_status(
                    item.id,
                    QueueStatus.FILTERED,
                    dropped_reason="slm_rejected",
                )
                logger.info("slm_rejected", threat_id=item.id, rationale=verdict.rationale)
                continue

            self._queue.update_status(item.id, QueueStatus.CONFIRMED)
            confirmed_ids.append(item.id)
            logger.info("threat_confirmed", threat_id=item.id)

        return confirmed_ids

    def _confirm_relevance(self, title: str, source: str, excerpt: str) -> RelevanceVerdict:
        user_msg = RELEVANCE_USER_TEMPLATE.format(title=title, source=source, excerpt=excerpt)
        return self._llm.complete_structured(
            model=self._settings.slm_model,
            messages=[
                {"role": "system", "content": RELEVANCE_SYSTEM},
                {"role": "user", "content": user_msg},
            ],
            response_model=RelevanceVerdict,
        )
