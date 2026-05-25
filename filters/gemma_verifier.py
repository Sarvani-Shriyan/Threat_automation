# pip install openai pydantic

import asyncio
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from openai import APIConnectionError, APITimeoutError, OpenAI
from pydantic import BaseModel

from ingestion.config import (
    OLLAMA_BASE_URL,
    OLLAMA_MAX_WORKERS,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert detection engineering analyst.

Determine if the article describes ANY of the following high-priority threat classes:
1) Active Exploitation — attacks actively occurring in the wild or confirmed in-progress campaigns.
2) New Threat Actor Bypass — novel TTPs, authentication bypasses, or evasion against identity/cloud controls.
3) Critical Architectural Misconfiguration — dangerous default configs, exposed services, or control-plane gaps.
4) Unpatched Zero-Day Risk — vulnerabilities without available fix or under active abuse before patch.

Respond ONLY with valid JSON (no markdown):
{"relevant": true, "justification": "one sentence tied to exploitation/misconfiguration/zero-day criteria", "mitre_tactic_hint": "Tactic name or empty string"}

Set relevant=false for: patched-only advisories, general tutorials, product announcements, or threats unrelated to the criteria above."""


class GemmaVerdict(BaseModel):
    relevant: bool
    justification: str = ""
    mitre_tactic_hint: str = ""


class GemmaVerifier:
    """Local Gemma 4 semantic verifier via Ollama (OpenAI-compatible API)."""

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        model: str = OLLAMA_MODEL,
        timeout_seconds: float = OLLAMA_TIMEOUT_SECONDS,
        max_workers: int = OLLAMA_MAX_WORKERS,
    ) -> None:
        self._model = model
        self._max_workers = max_workers
        self._client = OpenAI(
            base_url=base_url,
            api_key="ollama",
            timeout=timeout_seconds,
        )

    def verify_article(self, article: dict[str, Any]) -> GemmaVerdict:
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": self._build_user_prompt(article)},
                ],
                temperature=0.1,
                response_format={"type": "json_object"},
            )
            raw = response.choices[0].message.content or "{}"
            return self._parse_verdict(raw)
        except (APIConnectionError, APITimeoutError, ConnectionError, TimeoutError) as exc:
            logger.error("gemma_offline_or_timeout error=%s title=%s", exc, article.get("title"))
            return GemmaVerdict(
                relevant=False,
                justification=f"Gemma unavailable: {exc}",
                mitre_tactic_hint="",
            )
        except Exception as exc:
            logger.error("gemma_verification_failed error=%s title=%s", exc, article.get("title"))
            return GemmaVerdict(
                relevant=False,
                justification=f"Verification error: {exc}",
                mitre_tactic_hint="",
            )

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
        for enriched, verdict in results:
            if verdict.relevant and enriched is not None:
                confirmed.append(enriched)
            else:
                rejected += 1
        return confirmed, rejected

    def _verify_and_enrich(
        self, article: dict[str, Any], index: int, total: int
    ) -> tuple[dict[str, Any] | None, GemmaVerdict]:
        logger.info("gemma_verify_progress %d/%d title=%s", index, total, article.get("title"))
        verdict = self.verify_article(article)
        if verdict.relevant:
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

    @staticmethod
    def _parse_verdict(raw: str) -> GemmaVerdict:
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
        try:
            return GemmaVerdict.model_validate(json.loads(text))
        except (json.JSONDecodeError, ValueError):
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                try:
                    return GemmaVerdict.model_validate(json.loads(match.group()))
                except (json.JSONDecodeError, ValueError):
                    pass
            return GemmaVerdict(
                relevant=False,
                justification="Failed to parse model JSON response",
                mitre_tactic_hint="",
            )
