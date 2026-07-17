"""
Hybrid LLM structured-output client.

Transparently routes every completion call to the correct format enforcement
layer based on the runtime endpoint:

  OpenAI cloud (api.openai.com / Azure OpenAI)
  ─────────────────────────────────────────────
  response_format = {
      "type": "json_schema",
      "json_schema": {
          "name":   <schema_name>,
          "strict": True,
          "schema": <caller-supplied JSON Schema dict>,
      },
  }
  The API enforces the schema server-side; the returned string is guaranteed
  to be valid JSON that matches the schema.

  Local Ollama / LiteLLM node
  ────────────────────────────
  response_format = {"type": "json_object"}
  The model is instructed to emit JSON but without schema-level enforcement.
  The returned dict is passed through an artifact-stripping + fallback-parse
  pipeline so downstream Pydantic validators receive a clean native dict.

Public API
──────────
  client = StructuredLLMClient(base_url=..., model=...)

  # Returns a plain Python dict (both cloud and local paths)
  result = client.generate_structured_output(messages, schema, schema_name)

  # Returns plain text (used for free-form tasks like the Stage 3 CTI report)
  text = client.generate_text(messages)

Provider detection
──────────────────
  Detection is dynamic and does NOT rely on hardcoded model strings.
  It checks the base_url hostname and the model name prefix:
    • URL contains "api.openai.com" or "openai.azure.com"  → cloud
    • Model starts with gpt-, o1-, o2-, o3-, o4-, text-davinci  → cloud
    • Everything else (localhost, 11434, host.docker.internal …)  → local
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI

from llm.observability import get_langfuse_openai_class

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provider detection constants
# ---------------------------------------------------------------------------

_CLOUD_URL_SIGNALS: frozenset[str] = frozenset(
    {"api.openai.com", "openai.azure.com"}
)

_CLOUD_MODEL_PREFIXES: tuple[str, ...] = (
    "gpt-",
    "o1-",
    "o2-",
    "o3-",
    "o4-",
    "text-davinci",
)


def is_openai_cloud(base_url: str, model: str) -> bool:
    """
    Return True when the target endpoint is the OpenAI cloud API or Azure OpenAI.

    Detection is URL-first (hostname match) with a model-name fallback so that
    cloud-routed requests are identified even if the base_url is a proxy that
    forwards to OpenAI.

    Parameters
    ----------
    base_url : str
        The API base URL (e.g. "http://localhost:11434/v1" or
        "https://api.openai.com/v1").
    model : str
        The model identifier (e.g. "gpt-4o-mini" or "phi4-mini-reasoning").
    """
    try:
        host = urlparse(base_url).hostname or ""
    except Exception:
        host = base_url.lower()

    url_is_cloud = any(signal in host for signal in _CLOUD_URL_SIGNALS)
    model_is_cloud = model.startswith(_CLOUD_MODEL_PREFIXES)
    return url_is_cloud or model_is_cloud


# ---------------------------------------------------------------------------
# Core client
# ---------------------------------------------------------------------------


class StructuredLLMClient:
    """
    Provider-transparent completion client.

    The same call site works unchanged regardless of whether the runtime
    routes to an OpenAI cloud model or a local Ollama instance.

    Usage
    -----
    from llm.structured_client import StructuredLLMClient
    from llm.schemas import RULE_BATCH_SCHEMA

    client = StructuredLLMClient(base_url=OLLAMA_BASE_URL, model=PHI4_MODEL)
    result = client.generate_structured_output(messages, RULE_BATCH_SCHEMA)
    # result is always a plain Python dict

    # Free-form text (Stage 3 CTI report on the Ollama path):
    text = client.generate_text(messages)
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "ollama",
        timeout: float = 300.0,
    ) -> None:
        self._base_url = base_url
        self._model = model
        self._is_cloud = is_openai_cloud(base_url, model)

        # Prefer the Langfuse OpenAI drop-in when observability is configured.
        # It auto-captures model name, latency, and token usage for every
        # completion call without any payload changes.  Falls back to the
        # standard openai.OpenAI when Langfuse is absent or unconfigured.
        LfOpenAI = get_langfuse_openai_class()
        if LfOpenAI is not None:
            self._client = LfOpenAI(
                base_url=base_url,
                api_key=api_key,
                timeout=timeout,
            )
            self._langfuse_enabled = True
        else:
            self._client = OpenAI(
                base_url=base_url,
                api_key=api_key,
                timeout=timeout,
            )
            self._langfuse_enabled = False

        logger.info(
            "llm_client_init model=%s provider=%s base_url=%s observability=%s",
            model,
            "openai-cloud" if self._is_cloud else "local-ollama",
            base_url,
            "langfuse" if self._langfuse_enabled else "disabled",
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def generate_structured_output(
        self,
        messages: list[dict[str, str]],
        response_schema: dict[str, Any],
        schema_name: str = "pipeline_output",
        *,
        temperature: float = 0.3,
        parent_observation: Any = None,
    ) -> dict[str, Any]:
        """
        Return a validated Python dict from the model.

        OpenAI cloud path
        ─────────────────
        Enforces the caller-supplied JSON Schema at the API level via
        `response_format.type = "json_schema"` with `strict = True`.

        Ollama / LiteLLM local path
        ────────────────────────────
        Requests `response_format = {"type": "json_object"}` and runs the
        raw model output through the shared `_safe_parse` helper.

        Observability
        ─────────────
        When `parent_observation` is a Langfuse span or trace and the
        `langfuse.openai` wrapper is active, the completion call is linked
        as a child generation — token usage, latency, and the model name are
        captured automatically by the wrapper.

        Parameters
        ----------
        messages : list[dict[str, str]]
        response_schema : dict[str, Any]
        schema_name : str
        temperature : float
        parent_observation : Any
            Optional Langfuse StatefulSpanClient / StatefulTraceClient.
            Pass the span created by observability.step3_generation_span()
            or observability.step4_validation_span() here.
        """
        if self._is_cloud:
            return self._call_openai_strict(
                messages, response_schema, schema_name,
                temperature=temperature,
                parent_observation=parent_observation,
            )
        return self._call_ollama_json(
            messages,
            temperature=temperature,
            parent_observation=parent_observation,
        )

    def generate_text(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        parent_observation: Any = None,
    ) -> str:
        """
        Return a plain-text completion string.

        Used for free-form generation tasks — primarily Stage 3's Sherman Kent
        CTI audit report and GEPA phase calls.

        OpenAI cloud path  → `response_format = {"type": "text"}`
        Ollama local path  → no `response_format` parameter (default text)

        Pass `parent_observation` to attach this generation as a child of a
        Langfuse span when observability is active.
        """
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
        }
        if self._is_cloud:
            kwargs["response_format"] = {"type": "text"}

        # Attach to Langfuse parent span/trace when wrapper is active
        if self._langfuse_enabled and parent_observation is not None:
            kwargs["langfuse_parent"] = parent_observation

        response = self._client.chat.completions.create(**kwargs)
        raw = response.choices[0].message.content or ""
        logger.debug(
            "llm_text_response model=%s provider=%s len=%d",
            self._model,
            "cloud" if self._is_cloud else "local",
            len(raw),
        )
        return raw

    # ------------------------------------------------------------------
    # Provider-specific internal calls
    # ------------------------------------------------------------------

    def _call_openai_strict(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        schema_name: str,
        *,
        temperature: float,
        parent_observation: Any = None,
    ) -> dict[str, Any]:
        """
        OpenAI strict JSON Schema mode.

        The `strict: True` flag instructs the API to enforce the schema
        server-side.  When the Langfuse wrapper is active, the optional
        `langfuse_parent` kwarg links this generation to the caller's span.
        """
        call_kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": schema_name,
                    "strict": True,
                    "schema": schema,
                },
            },
        }
        if self._langfuse_enabled and parent_observation is not None:
            call_kwargs["langfuse_parent"] = parent_observation

        response = self._client.chat.completions.create(**call_kwargs)
        raw = response.choices[0].message.content or "{}"
        logger.debug(
            "openai_strict_response model=%s schema=%s len=%d",
            self._model, schema_name, len(raw),
        )
        return json.loads(raw)

    def _call_ollama_json(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float,
        parent_observation: Any = None,
    ) -> dict[str, Any]:
        """
        Ollama / LiteLLM JSON object mode.

        Requests `{"type": "json_object"}` for JSON mode without strict schema
        enforcement.  When the Langfuse wrapper is active, the optional
        `langfuse_parent` kwarg links the generation to the caller's span —
        token usage and latency are captured automatically.
        """
        call_kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
            "response_format": {"type": "json_object"},
        }
        if self._langfuse_enabled and parent_observation is not None:
            call_kwargs["langfuse_parent"] = parent_observation

        response = self._client.chat.completions.create(**call_kwargs)
        raw = response.choices[0].message.content or "{}"
        logger.debug(
            "ollama_json_response model=%s len=%d", self._model, len(raw),
        )
        return self._safe_parse(raw)

    # ------------------------------------------------------------------
    # Shared artifact-stripping parser
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_parse(raw: str) -> dict[str, Any]:
        """
        Best-effort JSON extraction with multi-layer fallback.

        Stripping order
        ───────────────
        1. phi4-mini-reasoning <thinking>…</thinking> chain-of-thought blocks.
        2. Markdown ``` / ```json code fences.
        3. Direct `json.loads` on cleaned text.
        4. Greedy `{…}` extraction from surrounding prose.
        5. Return `{}` if all attempts fail (never raises).
        """
        text = raw.strip()

        # 1. Strip phi4 thinking blocks (complete + stray tags)
        text = re.sub(
            r"<thinking>.*?</thinking>", "", text, flags=re.DOTALL | re.IGNORECASE
        )
        text = re.sub(r"</?thinking>", "", text, flags=re.IGNORECASE)

        # 2. Strip markdown fences
        if text.lstrip().startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text.lstrip(), flags=re.IGNORECASE)
            text = re.sub(r"\s*```$", "", text, flags=re.IGNORECASE)
        text = text.strip()

        # 3. Direct parse
        try:
            payload = json.loads(text)
            if isinstance(payload, dict):
                return payload
            if isinstance(payload, list):
                return {"_list": payload}
        except json.JSONDecodeError:
            pass

        # 4. Extract first {...} block from surrounding prose
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                payload = json.loads(match.group())
                if isinstance(payload, dict):
                    return payload
            except json.JSONDecodeError:
                pass

        logger.warning(
            "llm_client_parse_failed raw_preview=%r", raw[:300]
        )
        return {}

    # ------------------------------------------------------------------
    # Introspection helpers (useful for callers and tests)
    # ------------------------------------------------------------------

    @property
    def is_cloud(self) -> bool:
        """True when the client targets an OpenAI cloud or Azure OpenAI endpoint."""
        return self._is_cloud

    @property
    def model(self) -> str:
        return self._model

    @property
    def base_url(self) -> str:
        return self._base_url
