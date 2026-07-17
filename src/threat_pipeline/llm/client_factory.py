"""
LLMClientFactory — prototype-layer wrapper around the root-level
StructuredLLMClient.

This module is part of the src/threat_pipeline package (prototype layer).
The active pipeline uses the root-level `llm.structured_client.StructuredLLMClient`
directly.  This class delegates its structured completion calls to that
factory so both layers share the same hybrid routing logic.

When StructuredLLMClient is not importable (isolated package environments
without the project root on sys.path), the factory falls back to the
original LiteLLM path to remain backward-compatible.
"""

from __future__ import annotations

import json
from typing import Any, TypeVar

import structlog
from pydantic import BaseModel

from config.settings import Settings

logger = structlog.get_logger(__name__)

T = TypeVar("T", bound=BaseModel)

# Attempt to import the root-level hybrid factory.
# In a standard project-root run this always succeeds.
try:
    from llm.structured_client import StructuredLLMClient  # type: ignore[import]
    from llm.schemas import (  # type: ignore[import]
        GEMMA_VERDICT_SCHEMA,
        RULE_BATCH_SCHEMA,
    )
    _HAS_STRUCTURED_CLIENT = True
except ImportError:
    _HAS_STRUCTURED_CLIENT = False


class LLMClientFactory:
    """
    Model-agnostic completion client.

    Routing
    ───────
    • LLM_MOCK = true  → returns deterministic mock payloads (no network call).
    • LLM_MOCK = false + StructuredLLMClient available
                       → delegates to StructuredLLMClient for hybrid routing:
                           - OpenAI cloud  → strict json_schema enforcement
                           - Local Ollama  → json_object mode + Pydantic backstop
    • LLM_MOCK = false + StructuredLLMClient unavailable
                       → legacy LiteLLM path (backward-compat fallback).
    """

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

        if _HAS_STRUCTURED_CLIENT:
            return self._complete_via_structured_client(model, messages, response_model)

        return self._complete_via_litellm(model, messages, response_model)

    # ------------------------------------------------------------------
    # StructuredLLMClient path (preferred)
    # ------------------------------------------------------------------

    def _complete_via_structured_client(
        self,
        model: str,
        messages: list[dict[str, str]],
        response_model: type[T],
    ) -> T:
        """
        Delegate to the hybrid factory.

        Chooses the most appropriate schema by inspecting response_model.__name__.
        Falls back to a minimal permissive schema for unrecognised models.
        """
        from llm.structured_client import StructuredLLMClient  # noqa: PLC0415

        # Infer the base_url from the model string when it contains "ollama/"
        if model.startswith("ollama/"):
            base_url = "http://localhost:11434/v1"
            bare_model = model[len("ollama/"):]
        else:
            base_url = "https://api.openai.com/v1"
            bare_model = model

        client = StructuredLLMClient(
            base_url=base_url,
            model=bare_model,
            api_key=self._settings.model_fields.get("api_key", "ollama"),  # type: ignore[arg-type]
        )

        schema = self._schema_for(response_model)
        schema_name = response_model.__name__.lower()
        raw_dict = client.generate_structured_output(
            messages, schema, schema_name
        )
        logger.debug(
            "structured_client_complete",
            model=bare_model,
            response_model=response_model.__name__,
            is_cloud=client.is_cloud,
        )
        return response_model.model_validate(raw_dict)

    @staticmethod
    def _schema_for(response_model: type[BaseModel]) -> dict[str, Any]:
        """Return the most specific JSON Schema available for the given model."""
        name = response_model.__name__
        if name == "RelevanceVerdict":
            return GEMMA_VERDICT_SCHEMA
        if name in ("RuleGenerationBatch", "ThreatRuleBatch"):
            return RULE_BATCH_SCHEMA
        # Generic fallback: accept any JSON object
        return {"type": "object", "additionalProperties": True}

    # ------------------------------------------------------------------
    # Legacy LiteLLM path (fallback)
    # ------------------------------------------------------------------

    def _complete_via_litellm(
        self,
        model: str,
        messages: list[dict[str, str]],
        response_model: type[T],
    ) -> T:
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
        logger.debug("litellm_response", model=model, length=len(raw or ""))
        payload = json.loads(raw or "{}")
        return response_model.model_validate(payload)

    # ------------------------------------------------------------------
    # Mock path
    # ------------------------------------------------------------------

    def _mock_response(self, response_model: type[T]) -> T:
        from threat_pipeline.models.pipeline import RelevanceVerdict, RuleGenerationBatch
        from threat_pipeline.models.rules import ThreatRule

        if response_model is RelevanceVerdict:
            return response_model(  # type: ignore[return-value]
                is_threat=True,
                rationale="Mock: confirmed threat relevance.",
            )

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
            variants = [
                base.model_copy(update={"name": f"{base.name} Variant {i + 1}"})
                for i in range(5)
            ]
            return response_model(threat_id="mock", variants=variants)  # type: ignore[return-value]

        return response_model.model_validate({})  # type: ignore[return-value]
