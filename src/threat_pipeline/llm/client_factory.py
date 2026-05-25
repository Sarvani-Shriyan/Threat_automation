import json
from typing import TypeVar

import structlog
from pydantic import BaseModel

from config.settings import Settings

logger = structlog.get_logger(__name__)

T = TypeVar("T", bound=BaseModel)


class LLMClientFactory:
    """Model-agnostic completion client via LiteLLM; hot-swappable models."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def complete_structured(
        self,
        model: str,
        messages: list[dict[str, str]],
        response_model: type[T],
    ) -> T:
        if self._settings.llm_mock:
            return self._mock_response(response_model)

        try:
            import litellm
        except ImportError as exc:
            raise RuntimeError("litellm is required when LLM_MOCK=false") from exc

        response = litellm.completion(
            model=model,
            messages=messages,
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content
        logger.debug("llm_response", model=model, length=len(raw or ""))
        payload = json.loads(raw or "{}")
        return response_model.model_validate(payload)

    def _mock_response(self, response_model: type[T]) -> T:
        from threat_pipeline.models.pipeline import RelevanceVerdict, RuleGenerationBatch
        from threat_pipeline.models.rules import ThreatRule

        if response_model is RelevanceVerdict:
            return response_model(is_threat=True, rationale="Mock: confirmed threat relevance.")  # type: ignore[return-value]

        if response_model is RuleGenerationBatch:
            base = ThreatRule(
                name="Mock CloudTrail Anomaly",
                description="Detects anomalous CloudTrail API activity",
                actionNames=["alert_soc", "collect_forensics"],
                defaultSeverity="high",
                threatType="cloud_misconfiguration",
                recommend="Enable CloudTrail in all regions and ship to SIEM",
                remediate="Revoke compromised credentials and rotate keys",
            )
            variants = []
            for i in range(5):
                variants.append(
                    base.model_copy(
                        update={"name": f"{base.name} Variant {i + 1}"}
                    )
                )
            return response_model(threat_id="mock", variants=variants)  # type: ignore[return-value]

        return response_model.model_validate({})  # type: ignore[return-value]
