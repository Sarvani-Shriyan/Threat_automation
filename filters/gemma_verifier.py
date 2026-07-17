import asyncio
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Literal

from openai import APIConnectionError, APITimeoutError
from pydantic import BaseModel, Field, field_validator

from ingestion.config import (
    OLLAMA_BASE_URL,
    OLLAMA_MAX_WORKERS,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT_SECONDS,
)
from llm.schemas import GEMMA_VERDICT_SCHEMA
from llm.structured_client import StructuredLLMClient

logger = logging.getLogger(__name__)

MIN_CONFIDENCE_SCORE = 6

SYSTEM_PROMPT = """You are a deterministic, zero-prose automated Security Log Categorization Router. Your input is an isolated cyber threat intelligence summary. Your output must strictly be a raw, un-markdowned, valid JSON object.

CRITICAL SAFETY GUARDRAILS:
- You are forbidden from adding introductory text, pleasantries, formatting backticks (```json), or conversational footnotes.
- You are strictly forbidden from inventing, estimating, or guessing platforms, actions, or details not inferred from the input text.
- If the threat text does not explicitly fall into our core domains, you must output a confidence_score of 1 and set is_relevant to false.

CORE LANDSCAPE DOMAINS (IF INDUCTIVELY PRESENT, HIGHER CONFIDENCE IS TRIGGERED):
1. Identity Security: MFA fatigue, session hijacking, token theft, account recovery abuse, unauthorized privilege elevation, identity providers (Okta, Entra ID, IAM).
2. Cloud Infrastructure Security: Malicious modifications or resource destructions within AWS, GCP, Azure, or ARM templates.
3. SaaS Security: Continuous integration or enterprise configuration flaws (GitHub Actions, pipeline hijacking, runner takeovers).

EXCLUSION BOUNDARIES (SET 'is_relevant': false IMMEDIATELY):
- Broad endpoint malware, local Windows/Mac desktop OS exploits, browser exploits, generic compliance overviews, or simple company security press releases.

EXPLICIT DETERMINISTIC SCORING MATRIX:
- 9-10: Contains a concrete proof-of-concept exploit vector directly matching Cloud, Identity, or SaaS boundaries.
- 7-8: High probability behavioral match explicitly referencing our core domains but missing granular exploit payload metrics.
- 6: Baseline relevance cutoff. Mentions resource mutations or core identifiers but focuses on architecture or policy.
- 1-5: Collateral coverage, generic IT news, or entirely excluded operating system platforms.

Your absolute output contract format is strictly this structural JSON payload:
{
  "is_relevant": true/false,
  "confidence_score": 1-10,
  "primary_domain": "Identity" | "Cloud" | "SaaS" | "Unrelated",
  "primary_platform": "AWS" | "GCP" | "GitHub" | "Okta" | "Azure" | "Unknown",
  "reasoning_summary": "One sentence stating the exact keywords or semantic reasons from the text that triggered this classification logic."
}"""

MALFORMED_JSON_FALLBACK: dict[str, Any] = {
    "is_relevant": False,
    "confidence_score": 1,
    "primary_domain": "Unrelated",
    "primary_platform": "Unknown",
    "reasoning_summary": "MALFORMED_JSON_FALLBACK",
}

VALID_DOMAINS = frozenset({"Identity", "Cloud", "SaaS", "Unrelated"})
VALID_PLATFORMS = frozenset({"AWS", "GCP", "GitHub", "Okta", "Azure", "Unknown"})


class GemmaVerdict(BaseModel):
    is_relevant: bool = False
    confidence_score: int = Field(default=1, ge=1, le=10)
    primary_domain: Literal["Identity", "Cloud", "SaaS", "Unrelated"] = "Unrelated"
    primary_platform: Literal["AWS", "GCP", "GitHub", "Okta", "Azure", "Unknown"] = "Unknown"
    reasoning_summary: str = ""

    @field_validator("confidence_score", mode="before")
    @classmethod
    def coerce_confidence(cls, value: Any) -> int:
        try:
            score = int(float(value))
        except (TypeError, ValueError):
            return 1
        return max(1, min(10, score))

    @field_validator("primary_domain", mode="before")
    @classmethod
    def coerce_domain(cls, value: Any) -> str:
        if not isinstance(value, str):
            return "Unrelated"
        normalized = value.strip().title()
        if normalized == "Saas":
            return "SaaS"
        return normalized if normalized in VALID_DOMAINS else "Unrelated"

    @field_validator("primary_platform", mode="before")
    @classmethod
    def coerce_platform(cls, value: Any) -> str:
        if not isinstance(value, str):
            return "Unknown"
        candidate = value.strip()
        if candidate.upper() == candidate and len(candidate) <= 5:
            candidate = candidate.upper() if candidate != "GITHUB" else "GitHub"
        for platform in VALID_PLATFORMS:
            if candidate.lower() == platform.lower():
                return platform
        return "Unknown"

    @field_validator("reasoning_summary", mode="before")
    @classmethod
    def coerce_reasoning(cls, value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def passes_dynamic_filter(self, min_score: int = MIN_CONFIDENCE_SCORE) -> bool:
        return self.is_relevant and self.confidence_score >= min_score

    @classmethod
    def safe_default(cls, *, reasoning_summary: str = "MALFORMED_JSON_FALLBACK") -> "GemmaVerdict":
        payload = {**MALFORMED_JSON_FALLBACK, "reasoning_summary": reasoning_summary}
        return cls.model_validate(payload)


class GemmaVerifier:
    """
    Local Gemma 4 dynamic semantic filter via the hybrid StructuredLLMClient.

    Routes to:
      • OpenAI cloud  → strict JSON schema enforcement (GEMMA_VERDICT_SCHEMA)
      • Local Ollama  → json_object mode + existing Pydantic validation backstop
    """

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        model: str = OLLAMA_MODEL,
        timeout_seconds: float = OLLAMA_TIMEOUT_SECONDS,
        max_workers: int = OLLAMA_MAX_WORKERS,
        min_confidence_score: int = MIN_CONFIDENCE_SCORE,
    ) -> None:
        self._model = model
        self._max_workers = max_workers
        self._min_confidence_score = min_confidence_score
        self._llm = StructuredLLMClient(
            base_url=base_url,
            model=model,
            api_key="ollama",
            timeout=timeout_seconds,
        )

    def verify_article(self, article: dict[str, Any]) -> GemmaVerdict:
        messages: list[dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": self._build_user_prompt(article)},
        ]
        try:
            raw_dict = self._llm.generate_structured_output(
                messages,
                GEMMA_VERDICT_SCHEMA,
                "gemma_verdict",
                temperature=0.0,
            )
            return GemmaVerdict.model_validate(normalize_verdict_payload(raw_dict))
        except (APIConnectionError, APITimeoutError, ConnectionError, TimeoutError) as exc:
            logger.error("gemma_offline_or_timeout error=%s title=%s", exc, article.get("title"))
            return GemmaVerdict.safe_default(reasoning_summary=f"GEMMA_UNAVAILABLE: {exc}")
        except Exception as exc:
            logger.error("gemma_verification_failed error=%s title=%s", exc, article.get("title"))
            return GemmaVerdict.safe_default(reasoning_summary=f"GEMMA_INFERENCE_ERROR: {exc}")

    async def verify_batch_async(
        self, articles: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int]:
        """Parallel local inference using a thread pool (OpenAI client is sync)."""
        if not articles:
            return [], 0

        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            tasks = [
                loop.run_in_executor(pool, self._verify_and_enrich, article, i, len(articles))
                for i, article in enumerate(articles, start=1)
            ]
            results = await asyncio.gather(*tasks)

        confirmed: list[dict[str, Any]] = []
        rejected = 0
        for enriched, _verdict in results:
            if enriched is not None:
                confirmed.append(enriched)
            else:
                rejected += 1
        return confirmed, rejected

    def _verify_and_enrich(
        self, article: dict[str, Any], index: int, total: int
    ) -> tuple[dict[str, Any] | None, GemmaVerdict]:
        title = (article.get("title") or "Untitled").strip()
        logger.info("gemma_verify_progress %d/%d title=%s", index, total, title)
        verdict = self.verify_article(article)

        print(
            f"[Dynamic Filter] Title: {title} | "
            f"Domain: {verdict.primary_domain} | "
            f"Score: {verdict.confidence_score}/10"
        )

        if verdict.passes_dynamic_filter(self._min_confidence_score):
            enriched = dict(article)
            enriched["gemma_verdict"] = verdict.model_dump()
            return enriched, verdict
        return None, verdict

    @staticmethod
    def _build_user_prompt(article: dict[str, Any]) -> str:
        return (
            f"Source: {article.get('source', '')}\n"
            f"Title: {article.get('title', '')}\n"
            f"URL: {article.get('url', 'N/A')}\n\n"
            f"Content:\n{(article.get('content') or '')[:4000]}"
        )


def sanitize_model_json(raw: str) -> str:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text, flags=re.IGNORECASE)
    text = text.strip().strip("`")
    return text


def normalize_verdict_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Map legacy keys and coerce types before Pydantic validation."""
    normalized = dict(data)
    if "is_relevant" not in normalized and "relevant" in normalized:
        normalized["is_relevant"] = normalized.pop("relevant")
    if "reasoning_summary" not in normalized:
        for legacy_key in ("justification", "rationale"):
            if legacy_key in normalized:
                normalized["reasoning_summary"] = normalized.pop(legacy_key)
                break
    return normalized


def parse_semantic_verdict(raw: str) -> GemmaVerdict:
    """
    Parse model output with markdown cleanup and safe fallback on any failure.
    """
    try:
        text = sanitize_model_json(raw)
        if not text:
            logger.warning("gemma_empty_response")
            return GemmaVerdict.safe_default()

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if not match:
                raise
            payload = json.loads(match.group())

        if not isinstance(payload, dict):
            logger.warning("gemma_non_object_json type=%s", type(payload).__name__)
            return GemmaVerdict.safe_default()

        return GemmaVerdict.model_validate(normalize_verdict_payload(payload))
    except (json.JSONDecodeError, ValueError, TypeError, KeyError) as exc:
        logger.warning("gemma_malformed_json error=%s raw_preview=%s", exc, raw[:200])
        return GemmaVerdict.safe_default()
