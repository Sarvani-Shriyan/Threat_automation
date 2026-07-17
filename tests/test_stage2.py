"""
Unit tests — Stage 2: Knowledge Base action-name lookup
(main_validator.run_stage2_kb_lookup).

All tests are pure Python, no LLM calls, no filesystem I/O.
The KB is supplied as a pre-built frozenset via the `minimal_kb` fixture.

Covered behaviours
------------------
- All actionNames present in KB → zero violations.
- One unknown actionName → exactly one violation naming the unknown action.
- Multiple unknown actionNames → one violation per unknown action.
- Empty actionNames list → zero violations (nothing to check).
- Blank / whitespace-only action string → flagged as invalid.
- Non-string action value (int, None) → flagged as invalid.
- Platform-specific actions from multiple catalogs → all resolve correctly.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from main_validator import run_stage2_kb_lookup


# ---------------------------------------------------------------------------
# Happy-path
# ---------------------------------------------------------------------------


class TestStage2HappyPath:
    def test_all_known_actions_pass(
        self, valid_rule: dict[str, Any], minimal_kb: frozenset[str]
    ) -> None:
        """A rule whose every actionName exists in the KB must return no violations."""
        violations = run_stage2_kb_lookup(valid_rule, minimal_kb)
        assert violations == [], f"Unexpected violations: {violations}"

    def test_empty_action_list_passes(
        self, valid_rule: dict[str, Any], minimal_kb: frozenset[str]
    ) -> None:
        """An empty actionNames list has nothing to cross-reference → no violation."""
        rule = copy.deepcopy(valid_rule)
        rule["actionNames"] = []
        violations = run_stage2_kb_lookup(rule, minimal_kb)
        assert violations == []

    def test_missing_action_names_key_passes(
        self, valid_rule: dict[str, Any], minimal_kb: frozenset[str]
    ) -> None:
        """If actionNames key is absent entirely, Stage 2 has nothing to look up."""
        rule = copy.deepcopy(valid_rule)
        del rule["actionNames"]
        violations = run_stage2_kb_lookup(rule, minimal_kb)
        assert violations == []

    def test_okta_action_resolves(
        self, valid_rule_okta: dict[str, Any], minimal_kb: frozenset[str]
    ) -> None:
        """An Okta-specific actionName that exists in the KB must pass."""
        violations = run_stage2_kb_lookup(valid_rule_okta, minimal_kb)
        assert violations == [], f"Okta action incorrectly rejected: {violations}"

    def test_github_action_resolves(
        self, valid_rule: dict[str, Any], minimal_kb: frozenset[str]
    ) -> None:
        """A GitHub actionName present in the KB must pass."""
        rule = copy.deepcopy(valid_rule)
        rule["actionNames"] = ["branch_protection_rule"]
        violations = run_stage2_kb_lookup(rule, minimal_kb)
        assert violations == []

    def test_large_known_action_set_passes(
        self, valid_rule: dict[str, Any], minimal_kb: frozenset[str]
    ) -> None:
        """Multiple known actions in one rule must all pass without violations."""
        rule = copy.deepcopy(valid_rule)
        rule["actionNames"] = [
            "AssumeRole",
            "CreateUser",
            "AttachUserPolicy",
            "DeleteTrail",
            "check_run",
        ]
        violations = run_stage2_kb_lookup(rule, minimal_kb)
        assert violations == []


# ---------------------------------------------------------------------------
# Unknown action violations
# ---------------------------------------------------------------------------


class TestStage2UnknownActions:
    def test_single_unknown_action_produces_violation(
        self, valid_rule: dict[str, Any], minimal_kb: frozenset[str]
    ) -> None:
        """One unknown actionName must produce exactly one violation."""
        rule = copy.deepcopy(valid_rule)
        rule["actionNames"] = ["AssumeRole", "FakeAction.TotallyMadeUp"]
        violations = run_stage2_kb_lookup(rule, minimal_kb)
        assert len(violations) == 1
        assert "FakeAction.TotallyMadeUp" in violations[0]

    def test_all_unknown_actions_each_produce_violation(
        self, valid_rule: dict[str, Any], minimal_kb: frozenset[str]
    ) -> None:
        """Every unknown actionName must generate its own violation."""
        unknown_actions = ["Ghost.Action1", "Phantom.Action2", "Shadow.Action3"]
        rule = copy.deepcopy(valid_rule)
        rule["actionNames"] = unknown_actions
        violations = run_stage2_kb_lookup(rule, minimal_kb)
        assert len(violations) == len(unknown_actions)
        for action in unknown_actions:
            assert any(action in v for v in violations), (
                f"Missing violation for unknown action '{action}'"
            )

    def test_mixed_known_and_unknown_only_flags_unknown(
        self, valid_rule: dict[str, Any], minimal_kb: frozenset[str]
    ) -> None:
        """Known actions must not be flagged even when unknown ones appear alongside them."""
        rule = copy.deepcopy(valid_rule)
        rule["actionNames"] = ["AssumeRole", "NonExistentAction.DoEvil"]
        violations = run_stage2_kb_lookup(rule, minimal_kb)
        assert len(violations) == 1
        assert "AssumeRole" not in violations[0]
        assert "NonExistentAction.DoEvil" in violations[0]

    def test_empty_kb_rejects_everything(
        self, valid_rule: dict[str, Any]
    ) -> None:
        """Against an empty KB frozenset, every actionName must be flagged."""
        rule = copy.deepcopy(valid_rule)
        rule["actionNames"] = ["AssumeRole", "CreateUser"]
        violations = run_stage2_kb_lookup(rule, frozenset())
        assert len(violations) == 2


# ---------------------------------------------------------------------------
# Malformed action value violations
# ---------------------------------------------------------------------------


class TestStage2MalformedActions:
    def test_blank_string_action_produces_violation(
        self, valid_rule: dict[str, Any], minimal_kb: frozenset[str]
    ) -> None:
        """A blank string in actionNames must be flagged, not silently ignored."""
        rule = copy.deepcopy(valid_rule)
        rule["actionNames"] = ["AssumeRole", "   "]
        violations = run_stage2_kb_lookup(rule, minimal_kb)
        assert any("blank" in v.lower() or "non-string" in v.lower() for v in violations), (
            f"Expected a blank-action violation, got: {violations}"
        )

    @pytest.mark.parametrize("bad_value", [None, 42, 3.14, True, [], {}])
    def test_non_string_action_produces_violation(
        self, valid_rule: dict[str, Any], minimal_kb: frozenset[str], bad_value: Any
    ) -> None:
        """Non-string entries inside actionNames must be reported as violations."""
        rule = copy.deepcopy(valid_rule)
        rule["actionNames"] = [bad_value]
        violations = run_stage2_kb_lookup(rule, minimal_kb)
        assert len(violations) >= 1, (
            f"Expected violation for non-string action {bad_value!r}, got none"
        )
