import structlog

from config.settings import Settings
from threat_pipeline.ingestion.threat_queue import ThreatQueue
from threat_pipeline.llm.client_factory import LLMClientFactory
from threat_pipeline.llm.prompts import (
    FEEDBACK_SECTION_TEMPLATE,
    RULE_GENERATION_SYSTEM,
    RULE_GENERATION_USER_TEMPLATE,
)
from threat_pipeline.models.ingestion import QueueItem, QueueStatus
from threat_pipeline.models.pipeline import FeedbackBundle, RuleGenerationBatch
from threat_pipeline.models.rules import ThreatRule

logger = structlog.get_logger(__name__)


class RuleGeneratorStage:
    """Phi-4 (configurable) generates 5-6 JSON rule variants."""

    def __init__(
        self,
        queue: ThreatQueue,
        llm: LLMClientFactory,
        settings: Settings,
    ) -> None:
        self._queue = queue
        self._llm = llm
        self._settings = settings

    def run(self, feedback: FeedbackBundle | None = None) -> dict[str, list[ThreatRule]]:
        results: dict[str, list[ThreatRule]] = {}
        items = self._queue.list_by_status(QueueStatus.CONFIRMED)
        for item in items:
            if feedback and feedback.threat_id != item.id:
                continue
            variants = self._generate(item, feedback if feedback and feedback.threat_id == item.id else None)
            results[item.id] = variants
            self._queue.update_status(item.id, QueueStatus.RULES_GENERATED)
        return results

    def run_for_item(self, item: QueueItem, feedback: FeedbackBundle | None = None) -> list[ThreatRule]:
        variants = self._generate(item, feedback)
        self._queue.update_status(item.id, QueueStatus.RULES_GENERATED)
        return variants

    def _generate(self, item: QueueItem, feedback: FeedbackBundle | None) -> list[ThreatRule]:
        feedback_section = ""
        if feedback:
            errors = []
            for vr in feedback.validation_results:
                for err in vr.errors:
                    errors.append(f"[{err.code}] {err.field}: {err.message}")
            for note in [feedback.human_notes] if feedback.human_notes else []:
                errors.append(f"[HUMAN] {note}")
            feedback_section = FEEDBACK_SECTION_TEMPLATE.format(errors="\n".join(errors))

        system = RULE_GENERATION_SYSTEM.format(
            actions=", ".join(self._settings.valid_action_names),
            severities=", ".join(self._settings.valid_severities),
        )
        user = RULE_GENERATION_USER_TEMPLATE.format(
            title=item.article.title,
            source=item.article.source,
            url=item.article.url or "N/A",
            content=item.article.content_markdown[:4000],
            feedback_section=feedback_section,
        )

        batch = self._llm.complete_structured(
            model=self._settings.reasoning_model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_model=RuleGenerationBatch,
        )
        batch.threat_id = item.id
        logger.info("rules_generated", threat_id=item.id, count=len(batch.variants))
        return batch.variants
