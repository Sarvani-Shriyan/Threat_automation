"""
Unit tests for src/threat_pipeline/utils/cvss_severity.py

Covered behaviours
------------------
- CVSS 4.0 vectors produce correct capitalised text labels.
- CVSS 3.x vectors at each score boundary band produce the correct label.
- Score boundaries: 0.1–3.9 → "Low", 4.0–6.9 → "Medium",
                   7.0–8.9 → "High", 9.0–10.0 → "Critical".
- apply_official_severity overrides AI severity with official CVSS label.
- apply_official_severity falls back to normalised AI severity with no vector.
- apply_official_severity searches nested threat advisory fields.
- Malformed / unrecognised vectors fall back gracefully.
- Numeric / decimal / punctuation AI severities are normalised to "Medium".
- All valid word-string severities are accepted as-is.
- VALID_SEVERITIES contains exactly the four allowed labels.
"""

from __future__ import annotations

import copy
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from threat_pipeline.utils.cvss_severity import (
    VALID_SEVERITIES,
    _extract_cvss_vector,
    _normalise_fallback_severity,
    _parse_severity_from_vector,
    apply_official_severity,
    enrich_threat_with_nvd_cvss,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def base_rule() -> dict[str, Any]:
    return {
        "name": "[AWS]: Suspicious AssumeRole",
        "description": "Detects unusual cross-account role assumptions.",
        "actionNames": ["AssumeRole"],
        "defaultSeverity": "High",
        "threatType": "PrivilegeEscalation",
        "recommend": "Restrict trust policies.",
        "remediate": "Revoke session tokens.",
    }


# ---------------------------------------------------------------------------
# VALID_SEVERITIES contract
# ---------------------------------------------------------------------------


class TestValidSeveritiesSet:
    def test_contains_exactly_four_labels(self) -> None:
        assert VALID_SEVERITIES == {"Low", "Medium", "High", "Critical"}

    def test_no_numeric_values(self) -> None:
        for s in VALID_SEVERITIES:
            assert s.isalpha(), f"Severity '{s}' contains non-alpha characters"

    def test_all_title_case(self) -> None:
        for s in VALID_SEVERITIES:
            assert s == s.title() or s == "Critical", (
                f"Severity '{s}' is not title-cased"
            )


# ---------------------------------------------------------------------------
# _parse_severity_from_vector — CVSS 4.0
# ---------------------------------------------------------------------------


class TestCVSS4Parsing:
    @pytest.mark.parametrize(
        "vector,expected",
        [
            # Critical: base score 10.0 equivalent
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "Critical",
            ),
            # High: high impact but with some mitigation
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                "High",
            ),
            # Medium
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
                "Medium",
            ),
        ],
    )
    def test_cvss4_returns_text_severity(self, vector: str, expected: str) -> None:
        result = _parse_severity_from_vector(vector)
        assert result == expected, (
            f"CVSS4 vector {vector!r}: expected {expected!r}, got {result!r}"
        )

    def test_cvss4_severity_is_word_string(self) -> None:
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        result = _parse_severity_from_vector(vector)
        assert result is not None
        assert result.isalpha(), f"Severity must be word-only, got {result!r}"
        assert result in VALID_SEVERITIES

    def test_cvss4_never_returns_numeric(self) -> None:
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        result = _parse_severity_from_vector(vector)
        assert result is not None
        assert not any(ch.isdigit() for ch in result), (
            f"Severity must not contain digits, got {result!r}"
        )


# ---------------------------------------------------------------------------
# _parse_severity_from_vector — CVSS 3.x score boundaries
# ---------------------------------------------------------------------------


class TestCVSS3ScoreBoundaries:
    """
    Verify that CVSS 3.x vectors whose base scores fall within each band
    produce the correct qualitative text label.

    Bands (CVSS v3 specification):
      None    : 0.0
      Low     : 0.1 – 3.9
      Medium  : 4.0 – 6.9
      High    : 7.0 – 8.9
      Critical: 9.0 – 10.0
    """

    @pytest.mark.parametrize(
        "vector,expected_severity",
        [
            # Low band — base score ~3.7
            (
                "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
                "Low",
            ),
            # Medium band — base score ~5.4
            (
                "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                "Medium",
            ),
            # High band — base score ~7.5
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "High",
            ),
            # Critical band — base score 9.0
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "Critical",
            ),
            # Critical band — base score 10.0
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "Critical",
            ),
        ],
    )
    def test_score_band_maps_to_correct_text(
        self, vector: str, expected_severity: str
    ) -> None:
        result = _parse_severity_from_vector(vector)
        assert result == expected_severity, (
            f"Vector {vector!r}: expected {expected_severity!r}, got {result!r}"
        )

    def test_cvss3_result_in_valid_set(self) -> None:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        result = _parse_severity_from_vector(vector)
        assert result in VALID_SEVERITIES

    def test_cvss3_result_is_word_only(self) -> None:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        result = _parse_severity_from_vector(vector)
        assert result is not None
        assert result.isalpha()


# ---------------------------------------------------------------------------
# _parse_severity_from_vector — CVSS 3.0 (legacy prefix)
# ---------------------------------------------------------------------------


class TestCVSS30Parsing:
    def test_cvss30_prefix_parsed_as_v3(self) -> None:
        vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = _parse_severity_from_vector(vector)
        assert result in VALID_SEVERITIES

    def test_cvss30_returns_text_not_number(self) -> None:
        vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = _parse_severity_from_vector(vector)
        assert result is not None
        assert not any(ch.isdigit() for ch in result)


# ---------------------------------------------------------------------------
# _parse_severity_from_vector — malformed / invalid inputs
# ---------------------------------------------------------------------------


class TestMalformedVectors:
    @pytest.mark.parametrize(
        "bad_vector",
        [
            "invalid",
            "7.5",
            "High",
            "",
            "AV:N/AC:L/PR:N",           # no CVSS: prefix
            "CVSS:99.0/NONSENSE",        # unknown version
        ],
    )
    def test_bad_vector_returns_none(self, bad_vector: str) -> None:
        result = _parse_severity_from_vector(bad_vector)
        assert result is None, (
            f"Expected None for {bad_vector!r}, got {result!r}"
        )


# ---------------------------------------------------------------------------
# _extract_cvss_vector — field discovery
# ---------------------------------------------------------------------------


class TestExtractCvssVector:
    def test_finds_top_level_cvss_vector_field(self) -> None:
        advisory = {"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        assert _extract_cvss_vector(advisory) is not None

    def test_finds_vector_string_field(self) -> None:
        advisory = {"vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
        assert _extract_cvss_vector(advisory) is not None

    def test_finds_nested_cvss_vector(self) -> None:
        advisory = {
            "cve": {
                "impact": {
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            }
        }
        assert _extract_cvss_vector(advisory) is not None

    def test_finds_vector_in_list(self) -> None:
        advisory = {
            "scores": [
                {"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ]
        }
        assert _extract_cvss_vector(advisory) is not None

    def test_returns_none_when_absent(self) -> None:
        advisory = {"title": "No CVSS here", "content": "Some text"}
        assert _extract_cvss_vector(advisory) is None

    def test_returns_none_for_empty_dict(self) -> None:
        assert _extract_cvss_vector({}) is None

    def test_cvss4_vector_discovered(self) -> None:
        advisory = {
            "cvss_v4_vector": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            )
        }
        vec = _extract_cvss_vector(advisory)
        assert vec is not None
        assert vec.upper().startswith("CVSS:4.0/")


# ---------------------------------------------------------------------------
# _normalise_fallback_severity
# ---------------------------------------------------------------------------


class TestNormaliseFallbackSeverity:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("Low", "Low"),
            ("low", "Low"),
            ("LOW", "Low"),
            ("Medium", "Medium"),
            ("medium", "Medium"),
            ("High", "High"),
            ("high", "High"),
            ("Critical", "Critical"),
            ("critical", "Critical"),
            ("CRITICAL", "Critical"),
        ],
    )
    def test_valid_case_insensitive_inputs(self, raw: str, expected: str) -> None:
        assert _normalise_fallback_severity(raw) == expected

    @pytest.mark.parametrize(
        "bad_input",
        ["7.5", "9.8", "Info", "Warning", "unknown", "None", "3", ""],
    )
    def test_invalid_inputs_default_to_medium(self, bad_input: str) -> None:
        result = _normalise_fallback_severity(bad_input)
        assert result == "Medium", (
            f"Expected 'Medium' for {bad_input!r}, got {result!r}"
        )

    def test_non_string_defaults_to_medium(self) -> None:
        assert _normalise_fallback_severity(7.5) == "Medium"  # type: ignore[arg-type]
        assert _normalise_fallback_severity(None) == "Medium"  # type: ignore[arg-type]

    def test_result_is_always_word_string(self) -> None:
        for val in ["7.5", "critical", "UNKNOWN", 42]:  # type: ignore[list-item]
            result = _normalise_fallback_severity(val)  # type: ignore[arg-type]
            assert result.isalpha(), f"Result {result!r} is not word-only"


# ---------------------------------------------------------------------------
# apply_official_severity — CVSS override
# ---------------------------------------------------------------------------


class TestApplyOfficialSeverityWithCVSSVector:
    def test_cvss4_overrides_ai_severity(
        self, base_rule: dict[str, Any]
    ) -> None:
        advisory = {
            "cvss_vector": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            )
        }
        result = apply_official_severity(base_rule, advisory)
        assert result["defaultSeverity"] in VALID_SEVERITIES
        assert result["defaultSeverity"].isalpha()

    def test_cvss3_critical_overrides_low_ai(
        self, base_rule: dict[str, Any]
    ) -> None:
        base_rule["defaultSeverity"] = "Low"
        advisory = {
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        }
        result = apply_official_severity(base_rule, advisory)
        assert result["defaultSeverity"] == "Critical"

    def test_cvss3_low_overrides_critical_ai(
        self, base_rule: dict[str, Any]
    ) -> None:
        base_rule["defaultSeverity"] = "Critical"
        advisory = {
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"
        }
        result = apply_official_severity(base_rule, advisory)
        assert result["defaultSeverity"] == "Low"

    def test_override_result_is_word_only(
        self, base_rule: dict[str, Any]
    ) -> None:
        advisory = {
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        }
        result = apply_official_severity(base_rule, advisory)
        sev = result["defaultSeverity"]
        assert sev.isalpha(), f"Severity {sev!r} must be word-only"
        assert not any(ch.isdigit() for ch in sev)

    def test_original_rule_is_not_mutated(
        self, base_rule: dict[str, Any]
    ) -> None:
        original_severity = base_rule["defaultSeverity"]
        advisory = {
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        }
        apply_official_severity(base_rule, advisory)
        assert base_rule["defaultSeverity"] == original_severity

    def test_nested_advisory_vector_used(
        self, base_rule: dict[str, Any]
    ) -> None:
        advisory = {
            "cve": {
                "metrics": {
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            }
        }
        result = apply_official_severity(base_rule, advisory)
        assert result["defaultSeverity"] in VALID_SEVERITIES


# ---------------------------------------------------------------------------
# apply_official_severity — fallback (no CVSS vector)
# ---------------------------------------------------------------------------


class TestApplyOfficialSeverityFallback:
    def test_valid_ai_severity_preserved(
        self, base_rule: dict[str, Any]
    ) -> None:
        base_rule["defaultSeverity"] = "High"
        result = apply_official_severity(base_rule, {})
        assert result["defaultSeverity"] == "High"

    @pytest.mark.parametrize("valid_sev", ["Low", "Medium", "High", "Critical"])
    def test_all_valid_ai_severities_preserved(
        self, base_rule: dict[str, Any], valid_sev: str
    ) -> None:
        base_rule["defaultSeverity"] = valid_sev
        result = apply_official_severity(base_rule, {"title": "No vector here"})
        assert result["defaultSeverity"] == valid_sev

    def test_lowercase_ai_severity_capitalised(
        self, base_rule: dict[str, Any]
    ) -> None:
        base_rule["defaultSeverity"] = "high"
        result = apply_official_severity(base_rule, {})
        assert result["defaultSeverity"] == "High"

    def test_numeric_ai_severity_replaced_with_medium(
        self, base_rule: dict[str, Any]
    ) -> None:
        base_rule["defaultSeverity"] = "7.5"
        result = apply_official_severity(base_rule, {})
        assert result["defaultSeverity"] == "Medium"

    def test_decimal_ai_severity_replaced_with_medium(
        self, base_rule: dict[str, Any]
    ) -> None:
        base_rule["defaultSeverity"] = "9.8"
        result = apply_official_severity(base_rule, {})
        assert result["defaultSeverity"] == "Medium"

    def test_unknown_string_replaced_with_medium(
        self, base_rule: dict[str, Any]
    ) -> None:
        base_rule["defaultSeverity"] = "Warning"
        result = apply_official_severity(base_rule, {})
        assert result["defaultSeverity"] == "Medium"

    def test_result_severity_always_word_only(
        self, base_rule: dict[str, Any]
    ) -> None:
        for bad in ["7.5", "CRITICAL", "info", "3", "none"]:
            base_rule_copy = copy.deepcopy(base_rule)
            base_rule_copy["defaultSeverity"] = bad
            result = apply_official_severity(base_rule_copy, {})
            sev = result["defaultSeverity"]
            assert sev.isalpha(), f"Severity {sev!r} must be alpha-only for input {bad!r}"
            assert sev in VALID_SEVERITIES

    def test_empty_advisory_uses_fallback(
        self, base_rule: dict[str, Any]
    ) -> None:
        result = apply_official_severity(base_rule, {})
        assert result["defaultSeverity"] in VALID_SEVERITIES

    def test_malformed_vector_falls_back_to_ai_severity(
        self, base_rule: dict[str, Any]
    ) -> None:
        base_rule["defaultSeverity"] = "High"
        advisory = {"cvss_vector": "NOTAVALIDVECTOR"}
        result = apply_official_severity(base_rule, advisory)
        assert result["defaultSeverity"] == "High"


# ---------------------------------------------------------------------------
# apply_official_severity — other keys are preserved unchanged
# ---------------------------------------------------------------------------


class TestApplyOfficialSeverityPreservesKeys:
    def test_all_other_keys_unchanged(self, base_rule: dict[str, Any]) -> None:
        advisory = {
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        }
        result = apply_official_severity(base_rule, advisory)
        for key in ("name", "description", "actionNames", "threatType",
                    "recommend", "remediate"):
            assert result[key] == base_rule[key], (
                f"Key '{key}' was modified unexpectedly"
            )


# ---------------------------------------------------------------------------
# apply_official_severity — cvss_score + severity_source (Task 3 & 4)
# ---------------------------------------------------------------------------


class TestApplyOfficialSeverityCvssScore:
    """Verify that apply_official_severity now sets cvss_score and severity_source."""

    def test_cvss3_critical_sets_score(self, base_rule: dict[str, Any]) -> None:
        advisory = {"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        result = apply_official_severity(base_rule, advisory)
        assert result.get("cvss_score") is not None
        assert isinstance(result["cvss_score"], float)
        assert 9.0 <= result["cvss_score"] <= 10.0

    def test_cvss3_high_sets_score_in_range(self, base_rule: dict[str, Any]) -> None:
        advisory = {"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
        result = apply_official_severity(base_rule, advisory)
        assert result.get("cvss_score") is not None
        assert 7.0 <= result["cvss_score"] <= 8.9

    def test_cvss4_sets_score(self, base_rule: dict[str, Any]) -> None:
        advisory = {
            "cvss_vector": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            )
        }
        result = apply_official_severity(base_rule, advisory)
        assert result.get("cvss_score") is not None
        assert isinstance(result["cvss_score"], float)

    def test_no_vector_score_absent(self, base_rule: dict[str, Any]) -> None:
        result = apply_official_severity(base_rule, {})
        assert result.get("cvss_score") is None

    def test_severity_source_cvss_when_vector_used(self, base_rule: dict[str, Any]) -> None:
        advisory = {"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}
        result = apply_official_severity(base_rule, advisory)
        assert result.get("severity_source") == "cvss"

    def test_severity_source_not_cvss_without_vector(self, base_rule: dict[str, Any]) -> None:
        result = apply_official_severity(base_rule, {"title": "No CVSS here"})
        assert result.get("severity_source") != "cvss"

    def test_malformed_vector_leaves_score_absent(self, base_rule: dict[str, Any]) -> None:
        advisory = {"cvss_vector": "NOTAVALIDVECTOR"}
        result = apply_official_severity(base_rule, advisory)
        assert result.get("cvss_score") is None
        assert result.get("severity_source") != "cvss"

    def test_cvss_score_is_float_not_decimal(self, base_rule: dict[str, Any]) -> None:
        advisory = {"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        result = apply_official_severity(base_rule, advisory)
        assert type(result["cvss_score"]) is float  # not Decimal


# ---------------------------------------------------------------------------
# enrich_threat_with_nvd_cvss — NVD API lookup (Task 2) — mocked HTTP
# ---------------------------------------------------------------------------

_NVD_V31_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-12345",
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "vectorString": (
                                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                )
                            }
                        }
                    ]
                },
            }
        }
    ]
}

_NVD_V40_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2025-99999",
                "metrics": {
                    "cvssMetricV40": [
                        {
                            "cvssData": {
                                "vectorString": (
                                    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"
                                    "/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                                )
                            }
                        }
                    ]
                },
            }
        }
    ]
}

_NVD_EMPTY_RESPONSE: dict = {"vulnerabilities": []}


def _mock_nvd_response(payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


class TestEnrichThreatWithNvdCvss:
    """All HTTP calls are mocked — no live network requests."""

    def _clear_cache(self) -> None:
        from threat_pipeline.utils.cvss_severity import _fetch_nvd_cvss_vector
        _fetch_nvd_cvss_vector.cache_clear()

    def test_enriches_threat_with_v31_vector(self) -> None:
        self._clear_cache()
        threat = {"title": "Test vuln", "cve_ids": ["CVE-2024-12345"]}
        with patch(
            "threat_pipeline.utils.cvss_severity.httpx.get",
            return_value=_mock_nvd_response(_NVD_V31_RESPONSE),
        ):
            enrich_threat_with_nvd_cvss(threat)
        assert threat["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_enriches_threat_with_v40_vector(self) -> None:
        self._clear_cache()
        threat = {"title": "AI vuln", "cve_ids": ["CVE-2025-99999"]}
        with patch(
            "threat_pipeline.utils.cvss_severity.httpx.get",
            return_value=_mock_nvd_response(_NVD_V40_RESPONSE),
        ):
            enrich_threat_with_nvd_cvss(threat)
        assert threat.get("cvss_vector", "").startswith("CVSS:4.0/")

    def test_no_cve_ids_leaves_threat_unchanged(self) -> None:
        threat: dict = {"title": "No CVEs anywhere"}
        enrich_threat_with_nvd_cvss(threat)
        assert "cvss_vector" not in threat

    def test_empty_cve_ids_list_leaves_threat_unchanged(self) -> None:
        threat: dict = {"title": "No CVEs", "cve_ids": []}
        enrich_threat_with_nvd_cvss(threat)
        assert "cvss_vector" not in threat

    def test_existing_vector_not_overwritten(self) -> None:
        original = "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N"
        threat = {"title": "Test", "cve_ids": ["CVE-2024-12345"], "cvss_vector": original}
        enrich_threat_with_nvd_cvss(threat)
        assert threat["cvss_vector"] == original

    def test_network_error_does_not_raise(self) -> None:
        self._clear_cache()
        threat = {"title": "Unreachable", "cve_ids": ["CVE-2024-88888"]}
        with patch(
            "threat_pipeline.utils.cvss_severity.httpx.get",
            side_effect=Exception("connection timeout"),
        ):
            enrich_threat_with_nvd_cvss(threat)  # must not raise
        assert threat.get("cvss_vector") is None

    def test_empty_vulnerabilities_leaves_no_vector(self) -> None:
        self._clear_cache()
        threat = {"title": "Not in NVD", "cve_ids": ["CVE-2024-00001"]}
        with patch(
            "threat_pipeline.utils.cvss_severity.httpx.get",
            return_value=_mock_nvd_response(_NVD_EMPTY_RESPONSE),
        ):
            enrich_threat_with_nvd_cvss(threat)
        assert threat.get("cvss_vector") is None

    def test_http_error_status_does_not_raise(self) -> None:
        self._clear_cache()
        threat = {"title": "Rate limited", "cve_ids": ["CVE-2024-77777"]}
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("HTTP 429")
        with patch(
            "threat_pipeline.utils.cvss_severity.httpx.get",
            return_value=mock_resp,
        ):
            enrich_threat_with_nvd_cvss(threat)  # must not raise
        assert threat.get("cvss_vector") is None

    def test_nvd_vector_flows_through_apply_official_severity(
        self, base_rule: dict[str, Any]
    ) -> None:
        """End-to-end: NVD vector enrichment → apply_official_severity → cvss_score set."""
        self._clear_cache()
        threat = {"title": "E2E test", "cve_ids": ["CVE-2024-12345"]}
        with patch(
            "threat_pipeline.utils.cvss_severity.httpx.get",
            return_value=_mock_nvd_response(_NVD_V31_RESPONSE),
        ):
            enrich_threat_with_nvd_cvss(threat)
        result = apply_official_severity(base_rule, threat)
        assert result["defaultSeverity"] == "Critical"
        assert result.get("severity_source") == "cvss"
        assert result.get("cvss_score") is not None
        assert isinstance(result["cvss_score"], float)
