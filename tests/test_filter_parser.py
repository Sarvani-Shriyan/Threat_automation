"""
Unit tests — Step 2 filter parsing helpers (no LLM, no network).

Functions under test (all in filters.gemma_verifier):
  sanitize_model_json        — strips markdown code fences from raw LLM output
  normalize_verdict_payload  — maps legacy keys to canonical schema names
  parse_semantic_verdict     — full parse+validate pipeline with graceful fallback
  GemmaVerdict               — Pydantic model coercions and passes_dynamic_filter

Covered behaviours
------------------
sanitize_model_json
  - Strips ```json … ``` fences.
  - Strips plain ``` … ``` fences.
  - Leaves clean JSON untouched.
  - Handles stray backtick-only delimiters.

normalize_verdict_payload
  - Maps "relevant" → "is_relevant".
  - Maps "justification" → "reasoning_summary".
  - Maps "rationale" → "reasoning_summary".
  - Leaves canonical keys unchanged.

parse_semantic_verdict
  - Parses a clean JSON string and returns a valid GemmaVerdict.
  - Parses JSON wrapped in markdown fences.
  - Extracts embedded JSON from surrounding prose.
  - Returns the safe_default fallback on completely malformed input.
  - Returns the safe_default fallback on an empty string.
  - Coerces is_relevant from a string ("true") to bool.

GemmaVerdict.passes_dynamic_filter
  - Returns True when is_relevant=True and confidence_score >= 6.
  - Returns False when confidence_score < 6 (even if is_relevant=True).
  - Returns False when is_relevant=False (even if confidence_score = 10).
"""

from __future__ import annotations

import json

import pytest

from filters.gemma_verifier import (
    GemmaVerdict,
    normalize_verdict_payload,
    parse_semantic_verdict,
    sanitize_model_json,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CLEAN_PAYLOAD = {
    "is_relevant": True,
    "confidence_score": 8,
    "primary_domain": "CloudSecurity",
    "primary_platform": "AWS",
    "reasoning_summary": "Clear indication of lateral movement via AssumeRole.",
}


# ---------------------------------------------------------------------------
# sanitize_model_json
# ---------------------------------------------------------------------------


class TestSanitizeModelJson:
    def test_strips_json_fenced_block(self) -> None:
        raw = "```json\n{\"key\": \"value\"}\n```"
        result = sanitize_model_json(raw)
        assert result == '{"key": "value"}'

    def test_strips_plain_fenced_block(self) -> None:
        raw = "```\n{\"key\": \"value\"}\n```"
        result = sanitize_model_json(raw)
        assert result == '{"key": "value"}'

    def test_clean_json_untouched(self) -> None:
        raw = '{"is_relevant": true}'
        assert sanitize_model_json(raw) == raw

    def test_stray_trailing_backticks_stripped(self) -> None:
        raw = '{"a": 1}```'
        result = sanitize_model_json(raw)
        # The trailing backticks should not appear in the result
        assert "```" not in result

    def test_strips_whitespace_around_fences(self) -> None:
        raw = "  ```json\n{\"x\": 1}\n```  "
        result = sanitize_model_json(raw)
        assert result == '{"x": 1}'

    def test_empty_string_returns_empty(self) -> None:
        assert sanitize_model_json("") == ""


# ---------------------------------------------------------------------------
# normalize_verdict_payload
# ---------------------------------------------------------------------------


class TestNormalizeVerdictPayload:
    def test_canonical_keys_unchanged(self) -> None:
        data = dict(_CLEAN_PAYLOAD)
        result = normalize_verdict_payload(data)
        assert result["is_relevant"] == data["is_relevant"]
        assert result["reasoning_summary"] == data["reasoning_summary"]

    def test_maps_relevant_to_is_relevant(self) -> None:
        data = {"relevant": True, "confidence_score": 7}
        result = normalize_verdict_payload(data)
        assert "is_relevant" in result
        assert result["is_relevant"] is True
        assert "relevant" not in result

    def test_maps_justification_to_reasoning_summary(self) -> None:
        data = {"is_relevant": True, "justification": "Explains everything."}
        result = normalize_verdict_payload(data)
        assert "reasoning_summary" in result
        assert result["reasoning_summary"] == "Explains everything."
        assert "justification" not in result

    def test_maps_rationale_to_reasoning_summary(self) -> None:
        data = {"is_relevant": False, "rationale": "Not in scope."}
        result = normalize_verdict_payload(data)
        assert result["reasoning_summary"] == "Not in scope."
        assert "rationale" not in result

    def test_does_not_clobber_existing_reasoning_summary(self) -> None:
        """If reasoning_summary already exists, legacy keys must not overwrite it."""
        data = {
            "is_relevant": True,
            "reasoning_summary": "Authoritative value.",
            "justification": "Should be ignored.",
        }
        result = normalize_verdict_payload(data)
        assert result["reasoning_summary"] == "Authoritative value."


# ---------------------------------------------------------------------------
# parse_semantic_verdict
# ---------------------------------------------------------------------------


class TestParseSemanticVerdict:
    def test_parses_clean_json(self) -> None:
        raw = json.dumps(_CLEAN_PAYLOAD)
        verdict = parse_semantic_verdict(raw)
        assert verdict.is_relevant is True
        assert verdict.confidence_score == 8
        assert verdict.primary_platform == "AWS"

    def test_parses_fenced_json(self) -> None:
        raw = "```json\n" + json.dumps(_CLEAN_PAYLOAD) + "\n```"
        verdict = parse_semantic_verdict(raw)
        assert verdict.is_relevant is True
        assert verdict.confidence_score == 8

    def test_extracts_json_embedded_in_prose(self) -> None:
        payload = json.dumps({"is_relevant": True, "confidence_score": 7})
        raw = f"Here is my analysis:\n{payload}\nEnd of response."
        verdict = parse_semantic_verdict(raw)
        assert verdict.is_relevant is True
        assert verdict.confidence_score == 7

    def test_returns_safe_default_on_malformed_json(self) -> None:
        raw = "This is just plain prose with no JSON at all."
        verdict = parse_semantic_verdict(raw)
        assert verdict.is_relevant is False
        assert verdict.confidence_score == 1
        assert verdict.reasoning_summary == "MALFORMED_JSON_FALLBACK"

    def test_returns_safe_default_on_empty_string(self) -> None:
        verdict = parse_semantic_verdict("")
        assert verdict.is_relevant is False
        assert verdict.reasoning_summary == "MALFORMED_JSON_FALLBACK"

    def test_handles_is_relevant_as_string_true(self) -> None:
        """Model may return "true" (string) instead of true (bool)."""
        raw = json.dumps({"is_relevant": "true", "confidence_score": 9})
        verdict = parse_semantic_verdict(raw)
        assert isinstance(verdict.is_relevant, bool)
        assert verdict.is_relevant is True

    def test_handles_is_relevant_as_string_false(self) -> None:
        raw = json.dumps({"is_relevant": "false", "confidence_score": 2})
        verdict = parse_semantic_verdict(raw)
        assert verdict.is_relevant is False

    def test_clamps_confidence_score_below_min(self) -> None:
        """Scores below 1 must be coerced to the minimum allowed value."""
        raw = json.dumps({"is_relevant": False, "confidence_score": -5})
        verdict = parse_semantic_verdict(raw)
        assert verdict.confidence_score >= 1

    def test_clamps_confidence_score_above_max(self) -> None:
        """Scores above 10 must be coerced to the maximum allowed value."""
        raw = json.dumps({"is_relevant": True, "confidence_score": 99})
        verdict = parse_semantic_verdict(raw)
        assert verdict.confidence_score <= 10

    def test_legacy_relevant_key_resolved(self) -> None:
        """The older 'relevant' key must be normalised before validation."""
        raw = json.dumps(
            {
                "relevant": True,
                "confidence_score": 7,
                "primary_domain": "CloudSecurity",
                "primary_platform": "AWS",
                "reasoning_summary": "Mapped from legacy key.",
            }
        )
        verdict = parse_semantic_verdict(raw)
        assert verdict.is_relevant is True


# ---------------------------------------------------------------------------
# GemmaVerdict.passes_dynamic_filter
# ---------------------------------------------------------------------------


class TestPassesDynamicFilter:
    @pytest.mark.parametrize("score", [6, 7, 8, 9, 10])
    def test_passes_when_relevant_and_score_at_or_above_threshold(
        self, score: int
    ) -> None:
        verdict = GemmaVerdict(
            is_relevant=True,
            confidence_score=score,
            primary_domain="CloudSecurity",
            primary_platform="AWS",
            reasoning_summary="Test.",
        )
        assert verdict.passes_dynamic_filter() is True

    @pytest.mark.parametrize("score", [1, 2, 3, 4, 5])
    def test_fails_when_score_below_threshold(self, score: int) -> None:
        verdict = GemmaVerdict(
            is_relevant=True,
            confidence_score=score,
            primary_domain="CloudSecurity",
            primary_platform="AWS",
            reasoning_summary="Low-confidence.",
        )
        assert verdict.passes_dynamic_filter() is False

    def test_fails_when_not_relevant_regardless_of_score(self) -> None:
        verdict = GemmaVerdict(
            is_relevant=False,
            confidence_score=10,
            primary_domain="Unrelated",
            primary_platform="Unknown",
            reasoning_summary="Not in scope.",
        )
        assert verdict.passes_dynamic_filter() is False

    def test_custom_min_score_respected(self) -> None:
        """Callers may pass a custom threshold — the filter must honour it."""
        verdict = GemmaVerdict(
            is_relevant=True,
            confidence_score=8,
            primary_domain="CloudSecurity",
            primary_platform="AWS",
            reasoning_summary="Test.",
        )
        assert verdict.passes_dynamic_filter(min_score=9) is False
        assert verdict.passes_dynamic_filter(min_score=8) is True
        assert verdict.passes_dynamic_filter(min_score=7) is True
