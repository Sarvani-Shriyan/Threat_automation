import structlog

from config.settings import Settings
from threat_pipeline.generators.rule_generator import RuleGeneratorStage
from threat_pipeline.ingestion.threat_queue import ThreatQueue
from threat_pipeline.models.ingestion import QueueStatus
from threat_pipeline.models.pipeline import FeedbackBundle, HITLPayload
from threat_pipeline.models.rules import ThreatRule

logger = structlog.get_logger(__name__)


class FeedbackCorrectionLoop:
    """Route rejected rules back to generation (max 3 retries)."""

    def __init__(
        self,
        queue: ThreatQueue,
        generator: RuleGeneratorStage,
        settings: Settings,
    ) -> None:
        self._queue = queue
        self._generator = generator
        self._max_retries = settings.max_feedback_retries

    def process_feedback(
        self,
        bundle: FeedbackBundle,
        hitl_payload: HITLPayload | None = None,
    ) -> tuple[list[ThreatRule], bool]:
        item = self._queue.get_by_id(bundle.threat_id)
        if not item:
            raise ValueError(f"Unknown threat_id: {bundle.threat_id}")

        if item.retry_count >= self._max_retries:
            self._queue.update_status(item.id, QueueStatus.FAILED, dropped_reason="max_retries_exceeded")
            logger.warning("max_retries_exceeded", threat_id=item.id)
            return [], False

        self._queue.update_status(
            item.id,
            QueueStatus.CONFIRMED,
            increment_retry=True,
        )
        item = self._queue.get_by_id(bundle.threat_id)
        assert item is not None

        variants = self._generator.run_for_item(item, feedback=bundle)
        self._queue.update_status(item.id, QueueStatus.RULES_GENERATED)

        exhausted = item.retry_count + 1 >= self._max_retries
        if exhausted and not variants:
            self._queue.update_status(item.id, QueueStatus.FAILED, dropped_reason="generation_failed_after_retries")

        logger.info(
            "feedback_retry_complete",
            threat_id=item.id,
            retry_count=item.retry_count + 1,
            variant_count=len(variants),
        )
        return variants, not exhausted

    def build_bundle_from_hitl(
        self,
        payload: HITLPayload,
        rejected_valid_rules: list | None = None,
        human_notes: str | None = None,
    ) -> FeedbackBundle:
        rejected: list[ThreatRule] = list(rejected_valid_rules or [])
        return FeedbackBundle(
            threat_id=payload.threat_id,
            threat_context=payload.threat_context,
            rejected_rules=rejected,
            validation_results=[],
            human_notes=human_notes,
        )
