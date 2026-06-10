import structlog

from config.settings import Settings
from threat_pipeline.feedback.correction_loop import FeedbackCorrectionLoop
from threat_pipeline.filters.keyword_filter import KeywordFilterStage
from threat_pipeline.generators.rule_generator import RuleGeneratorStage
from threat_pipeline.hitl.payload_builder import HITLPayloadBuilder
from threat_pipeline.ingestion.deduplication import DeduplicationEngine
from threat_pipeline.ingestion.fetcher import FeedFetcher, MockStreamFetcher
from threat_pipeline.ingestion.normalizer import ContentNormalizer
from threat_pipeline.ingestion.threat_queue import ThreatQueue
from threat_pipeline.llm.client_factory import LLMClientFactory
from threat_pipeline.models.ingestion import QueueStatus
from threat_pipeline.models.pipeline import FeedbackBundle, HITLPayload

logger = structlog.get_logger(__name__)


class PipelineOrchestrator:
    """Coordinates multi-stage threat research automation workflow."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()
        self.queue = ThreatQueue(self.settings.threat_queue_db)
        self.llm = LLMClientFactory(self.settings)
        self.normalizer = ContentNormalizer()
        self.dedup = DeduplicationEngine(
            self.queue,
            hamming_threshold=self.settings.near_duplicate_hamming_threshold,
        )
        self.keyword_filter = KeywordFilterStage(self.queue, self.llm, self.settings)
        self.rule_generator = RuleGeneratorStage(self.queue, self.llm, self.settings)
        self.hitl_builder = HITLPayloadBuilder(self.settings)
        self.feedback_loop = FeedbackCorrectionLoop(
            self.queue, self.rule_generator, self.settings
        )

    def run_ingestion(
        self,
        *,
        feed_urls: list[str] | None = None,
        mock_path: str | None = None,
    ) -> int:
        if mock_path:
            fetcher = MockStreamFetcher(__import__("pathlib").Path(mock_path))
            raw_entries = fetcher.fetch_all()
        else:
            urls = feed_urls or self.settings.feed_urls
            if not urls:
                raise ValueError("Provide feed_urls or mock_path for ingestion")
            fetcher = FeedFetcher(timeout_seconds=self.settings.fetch_timeout_seconds)
            raw_entries = fetcher.fetch_all(urls)

        enqueued = 0
        for entry in raw_entries:
            article = self.normalizer.normalize(entry)
            is_dup, reason, record = self.dedup.is_duplicate(article)
            if is_dup:
                logger.info("duplicate_dropped", reason=reason, title=article.title)
                continue
            self.queue.register_dedup(
                record.content_hash,
                record.simhash,
                record.title,
                record.article_url,
            )
            self.queue.enqueue(article, record.content_hash)
            enqueued += 1

        logger.info("ingestion_complete", enqueued=enqueued, pending=self.queue.pending_count())
        return enqueued

    def run_filter_stage(self) -> list[str]:
        return self.keyword_filter.run()

    def run_generation_stage(self, feedback: FeedbackBundle | None = None) -> dict:
        return self.rule_generator.run(feedback=feedback)

    def build_hitl_payloads(self, rules_by_threat: dict) -> list[HITLPayload]:
        payloads: list[HITLPayload] = []
        for threat_id, variants in rules_by_threat.items():
            item = self.queue.get_by_id(threat_id)
            if not item:
                continue
            payload = self.hitl_builder.build_from_rules(item, variants)
            payloads.append(payload)
            self.queue.update_status(threat_id, QueueStatus.HITL_READY)
        return payloads

    def run_full_pipeline(
        self,
        *,
        feed_urls: list[str] | None = None,
        mock_path: str | None = None,
    ) -> list[HITLPayload]:
        self.run_ingestion(feed_urls=feed_urls, mock_path=mock_path)
        self.run_filter_stage()

        rules = self.run_generation_stage()
        if not rules:
            confirmed = self.queue.list_by_status(QueueStatus.CONFIRMED)
            if confirmed:
                rules = {
                    item.id: self.rule_generator.run_for_item(item)
                    for item in confirmed
                }

        return self.build_hitl_payloads(rules)

    def apply_feedback(self, bundle: FeedbackBundle) -> list[HITLPayload]:
        variants, _ = self.feedback_loop.process_feedback(bundle)
        item = self.queue.get_by_id(bundle.threat_id)
        if not item:
            return []
        payload = self.hitl_builder.build_from_rules(item, variants)
        self.queue.update_status(bundle.threat_id, QueueStatus.HITL_READY)
        return [payload]
