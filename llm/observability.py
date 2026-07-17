"""
Langfuse LLM Observability — centralized singleton and pipeline helpers.

Architecture
────────────
One singleton `Langfuse` client is created lazily on first use.  All helper
functions fail silently and return None / no-op objects when:
  • LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY are absent from the environment
  • the `langfuse` package is not installed
  • the remote host is temporarily unreachable

This guarantees that a Langfuse outage or misconfiguration never interrupts
the core threat-intelligence pipeline.

Hierarchical trace model
────────────────────────
  Root trace  — one per threat (keyed by threat_id)
    Span A  step3-rule-generation       generators/rule_engine.py
    Span B  step4-kent-cognitive-audit  main_validator.py
  Score       engineer-approval / engineer-rejection  app_triage.py

The `langfuse_trace_id` string is persisted inside every staging/validated
entry so Span B (Step 4) and feedback scores (Step 5) can be attached to the
same root trace as Span A (Step 3), even across separate process invocations.

Environment variables
─────────────────────
  LANGFUSE_PUBLIC_KEY   — required to enable observability
  LANGFUSE_SECRET_KEY   — required to enable observability
  LANGFUSE_HOST         — optional, defaults to https://cloud.langfuse.com
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Any, Generator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Singleton client
# ---------------------------------------------------------------------------

_client: Any = None          # Langfuse instance or None
_langfuse_openai: Any = None # langfuse.openai module or None
_init_done: bool = False


def _get_client() -> Any:
    """
    Lazy singleton factory.

    Returns a `Langfuse` client when valid credentials are present and the
    package is installed.  Returns None otherwise — all callers must guard
    against a None return.
    """
    global _client, _init_done
    if _init_done:
        return _client
    _init_done = True

    pk   = os.environ.get("LANGFUSE_PUBLIC_KEY", "").strip()
    sk   = os.environ.get("LANGFUSE_SECRET_KEY", "").strip()
    host = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com").strip()

    if not pk or not sk:
        logger.info(
            "langfuse_disabled — set LANGFUSE_PUBLIC_KEY + LANGFUSE_SECRET_KEY "
            "to enable LLM observability"
        )
        return None

    try:
        from langfuse import Langfuse  # noqa: PLC0415

        _client = Langfuse(public_key=pk, secret_key=sk, host=host)
        logger.info("langfuse_initialized host=%s", host)
    except ImportError:
        logger.warning(
            "langfuse_package_missing — run `uv sync` to install the langfuse SDK"
        )
    except Exception as exc:
        logger.warning("langfuse_init_failed error=%s", exc)

    return _client


def get_langfuse_openai_class() -> Any:
    """
    Return the `langfuse.openai.OpenAI` drop-in class when observability is
    active, or None to fall back to the standard `openai.OpenAI`.

    The class is cached module-globally after the first call.
    """
    global _langfuse_openai
    if _langfuse_openai is not None:
        return _langfuse_openai

    if _get_client() is None:
        return None  # observability disabled — use plain openai

    try:
        from langfuse.openai import OpenAI as _LfOpenAI  # noqa: PLC0415

        _langfuse_openai = _LfOpenAI
        logger.info("langfuse_openai_wrapper_active")
    except ImportError:
        logger.warning("langfuse_openai_wrapper_unavailable — falling back to openai.OpenAI")

    return _langfuse_openai


# ---------------------------------------------------------------------------
# Root trace
# ---------------------------------------------------------------------------


def create_threat_trace(
    threat_id: str,
    threat_title: str,
    *,
    metadata: dict[str, Any] | None = None,
) -> Any:
    """
    Create (or upsert) a root Langfuse trace for one threat processing run.

    The trace ID is deterministic: `"threat-{threat_id}"` so that Span B
    (validation) and score events from app_triage.py can attach themselves
    to the same trace even when running in a separate process or container.

    Returns the `StatefulTraceClient` object or None when observability is
    disabled / unavailable.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        trace = client.trace(
            id=f"threat-{threat_id}",
            name=f"Threat: {threat_title[:80]}",
            input={"threat_id": threat_id, "threat_title": threat_title},
            metadata=metadata or {},
        )
        logger.debug(
            "langfuse_trace_created id=threat-%s title=%r",
            threat_id,
            threat_title[:60],
        )
        return trace
    except Exception as exc:
        logger.warning("langfuse_trace_create_failed error=%s", exc)
        return None


# ---------------------------------------------------------------------------
# Span A — Step 3 rule generation
# ---------------------------------------------------------------------------


@contextmanager
def step3_generation_span(
    trace: Any,
    threat: dict[str, Any],
) -> Generator[Any, None, None]:
    """
    Context manager that wraps Step 3 rule generation in a Langfuse span.

    Usage
    ─────
    with step3_generation_span(lf_trace, threat) as span:
        rules, error, grounding = engine.generate_for_threat(
            threat, grounding=grounding, parent_observation=span
        )
        if span is not None:
            span.update(output={"rules_generated": len(rules), "status": ...})

    The span is automatically closed in the context __exit__ regardless of
    whether an exception was raised.  Errors inside the with-block are re-raised
    normally; Langfuse errors in span creation/teardown are swallowed.
    """
    span = None
    if trace is not None:
        try:
            span = trace.span(
                name="step3-rule-generation",
                input={
                    "threat_title": threat.get("title"),
                    "source":       threat.get("source"),
                    "url":          threat.get("url"),
                    "gemma_score":  (threat.get("gemma_verdict") or {}).get("confidence_score"),
                },
            )
        except Exception as exc:
            logger.warning("langfuse_step3_span_create_failed error=%s", exc)
            span = None
    try:
        yield span
    finally:
        if span is not None:
            try:
                span.end()
            except Exception as exc:
                logger.warning("langfuse_step3_span_end_failed error=%s", exc)


# ---------------------------------------------------------------------------
# Span B — Step 4 Kent cognitive validation
# ---------------------------------------------------------------------------


@contextmanager
def step4_validation_span(
    trace_id: str | None,
    entry: dict[str, Any],
) -> Generator[Any, None, None]:
    """
    Context manager that wraps Step 4 validation in a Langfuse span.

    Attaches to an existing root trace identified by `trace_id` (the value
    stored as `langfuse_trace_id` in the staging/validated entry).  When
    `trace_id` is None (Step 3 ran without Langfuse, or pre-existing entries)
    the span is silently skipped and None is yielded.

    Usage
    ─────
    async def validate_entry(entry, kb_actions):
        trace_id = entry.get("langfuse_trace_id")
        with step4_validation_span(trace_id, entry) as span_b:
            results = await asyncio.gather(
                *[validate_variant(v, ..., lf_span=span_b) for v in variants]
            )
            if span_b is not None:
                span_b.update(output={"kent_tags": [...], "passed": N})
    """
    client = _get_client()
    span = None
    if client is not None and trace_id:
        try:
            span = client.span(
                trace_id=trace_id,
                name="step4-kent-cognitive-audit",
                input={
                    "threat_title":   entry.get("threat_title"),
                    "variant_count":  len(entry.get("variants", [])),
                    "threat_id":      entry.get("threat_id"),
                },
            )
            logger.debug(
                "langfuse_step4_span_created trace_id=%s threat=%r",
                trace_id,
                entry.get("threat_title", "")[:60],
            )
        except Exception as exc:
            logger.warning("langfuse_step4_span_create_failed error=%s", exc)
            span = None
    try:
        yield span
    finally:
        if span is not None:
            try:
                span.end()
            except Exception as exc:
                logger.warning("langfuse_step4_span_end_failed error=%s", exc)


# ---------------------------------------------------------------------------
# Human feedback scores (Step 5 triage dashboard)
# ---------------------------------------------------------------------------


def log_approval_score(trace_id: str | None, rule_name: str = "") -> None:
    """
    Log a positive feedback score (1.0) for an engineer-approved rule.

    Called by app_triage.py → action_approve().
    """
    _log_score(
        trace_id,
        value=1.0,
        name="engineer-feedback",
        comment=f"Approved for production: {rule_name}".strip(),
    )


def log_rejection_score(
    trace_id: str | None,
    rejection_reason: str,
    rule_name: str = "",
) -> None:
    """
    Log a negative feedback score (0.0) for an engineer-rejected rule.

    Called by app_triage.py → action_explicit_reject().
    The full `rejection_reason` string is passed as the Langfuse score comment.
    """
    comment_parts = []
    if rule_name:
        comment_parts.append(f"Rejected: {rule_name}")
    if rejection_reason:
        comment_parts.append(rejection_reason)
    _log_score(
        trace_id,
        value=0.0,
        name="engineer-feedback",
        comment=" — ".join(comment_parts) if comment_parts else rejection_reason,
    )


def _log_score(
    trace_id: str | None,
    *,
    value: float,
    name: str,
    comment: str | None = None,
) -> None:
    """Core score-logging helper; silently drops when observability is disabled."""
    if not trace_id:
        return
    client = _get_client()
    if client is None:
        return
    try:
        kwargs: dict[str, Any] = {
            "trace_id": trace_id,
            "name":     name,
            "value":    value,
        }
        if comment:
            kwargs["comment"] = comment[:500]   # cap to avoid oversized payloads
        client.score(**kwargs)
        logger.debug(
            "langfuse_score_logged trace_id=%s name=%s value=%s",
            trace_id, name, value,
        )
    except Exception as exc:
        logger.warning(
            "langfuse_score_failed trace_id=%s name=%s error=%s",
            trace_id, name, exc,
        )


# ---------------------------------------------------------------------------
# Graceful shutdown helper
# ---------------------------------------------------------------------------


def flush() -> None:
    """
    Flush any buffered Langfuse events.

    Call this at the end of CLI pipeline scripts (main_generator.py,
    main_validator.py) to ensure all telemetry is shipped before the
    process exits, especially important inside short-lived Docker containers.
    """
    client = _get_client()
    if client is None:
        return
    try:
        client.flush()
        logger.debug("langfuse_flushed")
    except Exception as exc:
        logger.warning("langfuse_flush_failed error=%s", exc)
