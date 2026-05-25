from datetime import datetime

from config.settings import Settings
from threat_pipeline.models.ingestion import QueueItem
from threat_pipeline.models.pipeline import HITLPayload, InvalidRuleEntry, ThreatContext
from threat_pipeline.models.rules import ThreatRule, ValidationResult, ValidationStatus


class HITLPayloadBuilder:
    """Package threat context + 2-3 valid rules + invalid rules with error logs."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def build(
        self,
        item: QueueItem,
        validation_results: list[ValidationResult],
    ) -> HITLPayload:
        valid_rules: list[ThreatRule] = []
        invalid_entries: list[InvalidRuleEntry] = []

        for vr in validation_results:
            if vr.status == ValidationStatus.VALID and vr.rule:
                valid_rules.append(vr.rule)
            elif vr.rule:
                invalid_entries.append(
                    InvalidRuleEntry(rule=vr.rule, errors=vr.errors)
                )

        validated_sample = valid_rules[:3]
        if len(validated_sample) < 2 and len(valid_rules) >= 2:
            validated_sample = valid_rules[:2]

        context = ThreatContext(
            threat_id=item.id,
            title=item.article.title,
            source=item.article.source,
            url=item.article.url,
            published_at=item.article.published_at,
            excerpt=item.article.content_plain[:500],
        )

        return HITLPayload(
            threat_id=item.id,
            threat_context=context,
            validated_rules=validated_sample,
            invalid_rules=invalid_entries,
            metadata={
                "pipeline_version": self._settings.pipeline_version,
                "generated_at": datetime.utcnow().isoformat(),
            },
        )
