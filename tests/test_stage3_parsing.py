"""
Unit tests — Stage 3 pure-Python parsing helpers (no LLM, no network).

Functions under test (all in main_validator):
  _strip_thinking_tags       — removes <thinking>…</thinking> chain-of-thought blocks
  _extract_kent_tag          — maps a CTI report to a Sherman Kent probability tag
  _extract_executive_summary — pulls the '## 1. Executive Summary' section text

Covered behaviours
------------------
_strip_thinking_tags
  - Removes complete <thinking>…</thinking> block (case-insensitive, multi-line).
  - Strips stray opening <thinking> tag that was never closed.
  - Strips stray closing </thinking> tag.
  - Leaves text without any thinking tags completely untouched.
  - Returns an empty string when the entire input is a thinking block.

_extract_kent_tag
  - Returns the correct tag when the Probability Assessment line names it exactly.
  - Matches tags case-insensitively on the assessment line.
  - Falls back to full-report scan when the assessment line is absent.
  - Returns 'Unknown' when no recognised tag appears anywhere.
  - Respects tag priority order: "Almost Certain" > "Highly Likely" > "Likely" etc.

_extract_executive_summary
  - Returns the text under '## 1. Executive Summary' trimmed to ≤600 chars.
  - Stops at the next section header.
  - Falls back to the first 400 chars when the section is absent.
"""

from __future__ import annotations

import pytest

from main_validator import (
    _KENT_TAGS,
    _extract_executive_summary,
    _extract_kent_tag,
    _strip_thinking_tags,
)


# ---------------------------------------------------------------------------
# _strip_thinking_tags
# ---------------------------------------------------------------------------


class TestStripThinkingTags:
    def test_removes_complete_thinking_block(self) -> None:
        raw = "<thinking>\nLet me think about this...\n</thinking>\nActual content."
        result = _strip_thinking_tags(raw)
        assert "<thinking>" not in result
        assert "</thinking>" not in result
        assert "Actual content." in result

    def test_case_insensitive_removal(self) -> None:
        raw = "<THINKING>internal thoughts</THINKING> visible text"
        result = _strip_thinking_tags(raw)
        assert "internal thoughts" not in result
        assert "visible text" in result

    def test_strips_stray_opening_tag(self) -> None:
        raw = "<thinking> visible part"
        result = _strip_thinking_tags(raw)
        assert "<thinking>" not in result
        # Remaining text must survive
        assert "visible part" in result

    def test_strips_stray_closing_tag(self) -> None:
        raw = "content here </thinking> more content"
        result = _strip_thinking_tags(raw)
        assert "</thinking>" not in result
        assert "content here" in result

    def test_no_tags_untouched(self) -> None:
        text = "This report has no thinking tags at all."
        assert _strip_thinking_tags(text) == text

    def test_entire_input_is_thinking_block_returns_empty(self) -> None:
        raw = "<thinking>everything is internal</thinking>"
        result = _strip_thinking_tags(raw)
        assert result == ""

    def test_multiple_thinking_blocks_all_removed(self) -> None:
        raw = "<thinking>block 1</thinking> middle <thinking>block 2</thinking> end"
        result = _strip_thinking_tags(raw)
        assert "<thinking>" not in result
        assert "block 1" not in result
        assert "block 2" not in result
        assert "middle" in result
        assert "end" in result

    def test_mock_cti_report_strips_correctly(self, mock_cti_report: str) -> None:
        """The fixture report must lose its thinking block but keep the five sections."""
        result = _strip_thinking_tags(mock_cti_report)
        assert "<thinking>" not in result
        assert "## 1. Executive Summary" in result
        assert "## 5. Collection Gaps" in result


# ---------------------------------------------------------------------------
# _extract_kent_tag
# ---------------------------------------------------------------------------


class TestExtractKentTag:
    def test_extracts_highly_likely_from_assessment_line(self) -> None:
        report = (
            "## 3. Core Analysis & Assessment\n"
            "- Probability Assessment: Highly Likely — consistent with known patterns.\n"
        )
        assert _extract_kent_tag(report) == "Highly Likely"

    def test_extracts_almost_certain(self) -> None:
        report = "- Probability Assessment: Almost Certain (>95% probability).\n"
        assert _extract_kent_tag(report) == "Almost Certain"

    def test_extracts_unlikely(self) -> None:
        report = "Probability Assessment: Unlikely given limited telemetry.\n"
        assert _extract_kent_tag(report) == "Unlikely"

    def test_extracts_remote(self) -> None:
        report = "Probability Assessment: Remote — less than 5% chance.\n"
        assert _extract_kent_tag(report) == "Remote"

    def test_case_insensitive_assessment_label(self) -> None:
        report = "PROBABILITY ASSESSMENT: Likely based on the evidence.\n"
        assert _extract_kent_tag(report) == "Likely"

    def test_fallback_full_scan_finds_tag(self) -> None:
        """No assessment line, but the tag appears elsewhere in the report."""
        report = "This activity is Probable based on third-party feeds."
        result = _extract_kent_tag(report)
        assert result == "Probable"

    def test_returns_unknown_when_no_tag_present(self) -> None:
        report = "The analysis is inconclusive and we cannot determine probability."
        assert _extract_kent_tag(report) == "Unknown"

    def test_priority_order_almost_certain_beats_likely(self) -> None:
        """When multiple tags appear, the highest-priority match wins."""
        report = "Probability Assessment: Almost Certain — also likely to recur."
        assert _extract_kent_tag(report) == "Almost Certain"

    def test_highly_likely_beats_likely(self) -> None:
        """'Highly Likely' must match before the bare 'Likely' tag does."""
        report = "Probability Assessment: Highly Likely pattern observed."
        assert _extract_kent_tag(report) == "Highly Likely"

    @pytest.mark.parametrize("tag", _KENT_TAGS)
    def test_all_kent_tags_are_detectable(self, tag: str) -> None:
        """Every tag in the canonical list must be extractable."""
        report = f"Probability Assessment: {tag} — supporting evidence present.\n"
        assert _extract_kent_tag(report) == tag

    def test_real_mock_report_extracts_highly_likely(
        self, mock_cti_report: str
    ) -> None:
        """The shared fixture report contains 'Highly Likely' on the assessment line."""
        cleaned = _strip_thinking_tags(mock_cti_report)
        assert _extract_kent_tag(cleaned) == "Highly Likely"


# ---------------------------------------------------------------------------
# _extract_executive_summary
# ---------------------------------------------------------------------------


class TestExtractExecutiveSummary:
    def test_extracts_section_1_text(self) -> None:
        report = (
            "## 1. Executive Summary\n"
            "The activity is Highly Likely malicious.\n"
            "\n"
            "## 2. Technical Observations & Evidence Categorization\n"
            "- Some evidence here.\n"
        )
        result = _extract_executive_summary(report)
        assert "Highly Likely malicious" in result
        # Must not bleed into section 2
        assert "Technical Observations" not in result

    def test_fallback_to_first_400_chars_when_no_section(self) -> None:
        report = "A" * 500
        result = _extract_executive_summary(report)
        assert len(result) == 400

    def test_trims_to_600_chars_max(self) -> None:
        long_summary = "X" * 1000
        report = f"## 1. Executive Summary\n{long_summary}\n\n## 2. Next Section\n"
        result = _extract_executive_summary(report)
        assert len(result) <= 600

    def test_strips_leading_trailing_whitespace(self) -> None:
        report = "## 1. Executive Summary\n   \n  The threat is active.  \n\n## 2.\n"
        result = _extract_executive_summary(report)
        assert result == "The threat is active."

    def test_case_insensitive_section_header(self) -> None:
        report = "## 1. EXECUTIVE SUMMARY\nContent here.\n\n## 2. Something\n"
        result = _extract_executive_summary(report)
        assert "Content here." in result

    def test_real_mock_report_extracts_correctly(self, mock_cti_report: str) -> None:
        """The fixture report's summary section must be extracted, not section 2+."""
        cleaned = _strip_thinking_tags(mock_cti_report)
        result = _extract_executive_summary(cleaned)
        assert "Highly Likely" in result
        assert len(result) > 0
        assert len(result) <= 600
        # Must not contain section 2 headers
        assert "Technical Observations" not in result
