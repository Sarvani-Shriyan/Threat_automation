"""
Unit tests — Stage 1: Python contract enforcement (main_validator.run_stage1_contract).

All tests are pure Python, no LLM calls, no filesystem I/O.

Covered behaviours
------------------
- A fully-populated 7-key rule returns zero violations.
- Every one of the 7 mandatory keys, when absent, produces a distinct violation.
- Empty string values are treated as violations.
- An empty actionNames list is a violation.
- All four accepted severity values are valid; any other value is rejected.
- Multiple missing keys accumulate — none are silently swallowed.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from main_validator import REQUIRED_RULE_KEYS, VALID_SEVERITIES, run_stage1_contract


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _drop_key(base: dict[str, Any], key: str) -> dict[str, Any]:
    rule = copy.deepcopy(base)
    del rule[key]
    return rule


def _empty_key(base: dict[str, Any], key: str, empty_value: Any = "") -> dict[str, Any]:
    rule = copy.deepcopy(base)
    rule[key] = empty_value
    return rule


# ---------------------------------------------------------------------------
# Happy-path
# ---------------------------------------------------------------------------


class TestStage1HappyPath:
    def test_complete_rule_passes(self, valid_rule: dict[str, Any]) -> None:
        """A fully-populated 7-key rule must produce zero violations."""
        violations = run_stage1_contract(valid_rule)
        assert violations == [], f"Unexpected violations: {violations}"

    @pytest.mark.parametrize("severity", sorted(VALID_SEVERITIES))
    def test_all_valid_severities_pass(
        self, valid_rule: dict[str, Any], severity: str
    ) -> None:
        """Each of the four accepted severity strings must not generate a violation."""
        rule = copy.deepcopy(valid_rule)
        rule["defaultSeverity"] = severity
        violations = run_stage1_contract(rule)
        # Filter to only severity-related violations
        sev_violations = [v for v in violations if "severity" in v.lower()]
        assert sev_violations == [], f"Severity '{severity}' was incorrectly rejected: {sev_violations}"

    def test_multi_action_names_passes(self, valid_rule: dict[str, Any]) -> None:
        """A list with several valid action names must not raise a violation."""
        rule = copy.deepcopy(valid_rule)
        rule["actionNames"] = ["AssumeRole", "CreateUser", "DeleteTrail"]
        assert run_stage1_contract(rule) == []


# ---------------------------------------------------------------------------
# Missing key violations
# ---------------------------------------------------------------------------


class TestStage1MissingKeys:
    @pytest.mark.parametrize("key", REQUIRED_RULE_KEYS)
    def test_missing_key_produces_violation(
        self, valid_rule: dict[str, Any], key: str
    ) -> None:
        """Removing any one of the 7 mandatory keys must produce exactly one violation
        that names the missing key."""
        violations = run_stage1_contract(_drop_key(valid_rule, key))
        assert len(violations) >= 1
        assert any(key in v for v in violations), (
            f"Expected violation to mention key '{key}', got: {violations}"
        )

    def test_multiple_missing_keys_all_reported(
        self, valid_rule: dict[str, Any]
    ) -> None:
        """Removing three keys at once must produce at least three violations — none
        are silently swallowed after the first failure."""
        rule = copy.deepcopy(valid_rule)
        dropped_keys = ["name", "recommend", "remediate"]
        for k in dropped_keys:
            del rule[k]

        violations = run_stage1_contract(rule)
        assert len(violations) >= len(dropped_keys), (
            f"Expected at least {len(dropped_keys)} violations, got {len(violations)}: {violations}"
        )
        for k in dropped_keys:
            assert any(k in v for v in violations), (
                f"Violation for missing key '{k}' was not reported"
            )


# ---------------------------------------------------------------------------
# Empty-value violations
# ---------------------------------------------------------------------------


class TestStage1EmptyValues:
    @pytest.mark.parametrize(
        "key,empty_value",
        [
            ("name", ""),
            ("description", "   "),       # whitespace-only counts as empty
            ("defaultSeverity", ""),
            ("threatType", ""),
            ("recommend", ""),
            ("remediate", ""),
        ],
    )
    def test_empty_string_produces_violation(
        self, valid_rule: dict[str, Any], key: str, empty_value: str
    ) -> None:
        """An empty or whitespace-only string for any required key must be flagged."""
        violations = run_stage1_contract(_empty_key(valid_rule, key, empty_value))
        assert len(violations) >= 1
        assert any(key in v for v in violations), (
            f"Expected a violation mentioning '{key}', got: {violations}"
        )

    def test_empty_action_names_list_produces_violation(
        self, valid_rule: dict[str, Any]
    ) -> None:
        """An empty list for actionNames must be treated as a violation."""
        violations = run_stage1_contract(_empty_key(valid_rule, "actionNames", []))
        assert any("actionNames" in v for v in violations), (
            f"Expected violation for empty actionNames list, got: {violations}"
        )


# ---------------------------------------------------------------------------
# Severity enum violations
# ---------------------------------------------------------------------------


class TestStage1SeverityEnum:
    @pytest.mark.parametrize(
        "bad_severity",
        ["low", "CRITICAL", "critical", "Info", "unknown", "None", "warning"],
    )
    def test_invalid_severity_produces_violation(
        self, valid_rule: dict[str, Any], bad_severity: str
    ) -> None:
        """Any severity not in {Low, Medium, High, Critical} must be rejected."""
        rule = copy.deepcopy(valid_rule)
        rule["defaultSeverity"] = bad_severity
        violations = run_stage1_contract(rule)
        assert any("severity" in v.lower() for v in violations), (
            f"Expected severity violation for '{bad_severity}', got: {violations}"
        )
