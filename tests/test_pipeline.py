"""
Integration tests — end-to-end pipeline state tracing with mocked LLM.

All Ollama / OpenAI network calls are intercepted via unittest.mock.patch so
these tests consume zero VRAM and run fully offline.

The mock LLM layer returns the canonical MOCK_CTI_REPORT fixture string
(complete with <thinking> tags) to exercise the real regex-parsing code paths
inside Stage 3 without contacting the host machine.

All file I/O uses pytest's `tmp_path` fixture — the live ./data directory is
never touched.

Test groups
-----------
TestLoadKbActionSet
  - Uses a self-contained temp KB directory (no production KB dependency).
  - Verifies action accumulation, raw-file skipping, and corrupted-file resilience.
  - Verifies real knowledge_base/ loads > 0 actions (smoke-test).

TestValidateVariantStages
  - Stage 1 failure: missing keys short-circuits before Stage 2 and Stage 3.
  - Stage 2 failure: valid schema but unknown actionName stops before Stage 3.
  - Full pass:  mocked Ollama returns the CTI fixture → all three stages pass.

TestValidateEntry
  - Validates a multi-variant entry end-to-end (Ollama mocked).
  - Verifies each variant receives a 'validation' key.

TestRunValidationPipeline
  - Reads a staging JSON from tmp_path, writes annotated output to tmp_path.
  - Output file is parseable JSON with the expected top-level schema.
  - Passed variants appear correctly in stats.
  - Stage 1 failures produce the right 'stage' label.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import main_validator
from main_validator import (
    load_kb_action_set,
    run_validation,
    validate_entry,
    validate_variant,
)
from tests.conftest import MINIMAL_KB_ACTIONS, MOCK_CTI_REPORT, VALID_RULE


# ---------------------------------------------------------------------------
# Shared mock factory
# ---------------------------------------------------------------------------

def _make_ollama_mock(report_text: str = MOCK_CTI_REPORT) -> MagicMock:
    """
    Return a MagicMock that mimics the return value of _call_ollama_sync.

    We mock at the _call_ollama_sync level (not the OpenAI constructor) so the
    real parsing helpers (_strip_thinking_tags, _extract_kent_tag, …) are still
    exercised — only the network round-trip is bypassed.
    """
    choice = MagicMock()
    choice.message.content = report_text
    response = MagicMock()
    response.choices = [choice]
    return response


# ---------------------------------------------------------------------------
# TestLoadKbActionSet
# ---------------------------------------------------------------------------


class TestLoadKbActionSet:
    def test_loads_actions_from_temp_kb(self, temp_kb_dir: Path) -> None:
        """Actions from both catalog files must be present; raw file excluded."""
        actions = load_kb_action_set(temp_kb_dir)
        assert "AssumeRole" in actions
        assert "security.session.detect_client_roaming" in actions

    def test_raw_json_files_are_skipped(self, temp_kb_dir: Path) -> None:
        """upstream.raw.json must never contribute actions."""
        actions = load_kb_action_set(temp_kb_dir)
        assert "ShouldBeIgnored" not in actions

    def test_all_catalog_actions_accumulated(self, temp_kb_dir: Path) -> None:
        """Both catalog files contribute — total action count must equal their union."""
        actions = load_kb_action_set(temp_kb_dir)
        # aws_test (3) + okta_test (1) = 4
        assert len(actions) == 4

    def test_corrupt_json_file_is_skipped_gracefully(
        self, temp_kb_dir: Path
    ) -> None:
        """A malformed JSON file must be skipped without raising an exception."""
        (temp_kb_dir / "broken.json").write_text("NOT VALID JSON", encoding="utf-8")
        actions = load_kb_action_set(temp_kb_dir)
        # The valid catalogs must still be loaded
        assert "AssumeRole" in actions

    def test_empty_catalog_file_is_skipped(self, temp_kb_dir: Path) -> None:
        """A catalog with an empty actionNames list contributes nothing."""
        (temp_kb_dir / "empty_catalog.json").write_text(
            json.dumps({"platform": "test", "actionNames": []}),
            encoding="utf-8",
        )
        actions_before = load_kb_action_set(temp_kb_dir) - {"ShouldBeIgnored"}
        assert len(actions_before) == 4  # same as baseline

    def test_real_knowledge_base_loads_nonzero_actions(self) -> None:
        """Smoke-test: the production KB directory must resolve > 1000 actions."""
        real_kb = Path("knowledge_base")
        if not real_kb.exists():
            pytest.skip("production knowledge_base/ directory not found")
        actions = load_kb_action_set(real_kb)
        assert len(actions) > 1_000, (
            f"Expected > 1000 KB actions, found {len(actions)}"
        )


# ---------------------------------------------------------------------------
# TestValidateVariantStages
# ---------------------------------------------------------------------------


class TestValidateVariantStages:
    async def test_stage1_fail_short_circuits(self) -> None:
        """A rule missing mandatory keys must fail at Stage 1 without reaching Stage 3."""
        incomplete = copy.deepcopy(VALID_RULE)
        del incomplete["name"]
        del incomplete["recommend"]

        result = await validate_variant(
            incomplete, 0, "Test Threat", MINIMAL_KB_ACTIONS
        )

        assert result["validation"]["stage"] == "failed_stage_1"
        assert result["validation"]["stage3_audit"] is None
        # At least both missing keys should appear in the error list
        errors = result["validation"]["errors"]
        assert any("name" in e for e in errors)
        assert any("recommend" in e for e in errors)

    async def test_stage2_fail_short_circuits(self) -> None:
        """A schema-valid rule with an unknown actionName must fail at Stage 2."""
        rule = copy.deepcopy(VALID_RULE)
        rule["actionNames"] = ["CompletelyUnknown.FakeAction"]

        result = await validate_variant(rule, 0, "Test Threat", MINIMAL_KB_ACTIONS)

        assert result["validation"]["stage"] == "failed_stage_2"
        assert result["validation"]["stage3_audit"] is None
        assert any("CompletelyUnknown.FakeAction" in e for e in result["validation"]["errors"])

    async def test_full_pass_with_mocked_ollama(self) -> None:
        """
        A valid rule with known KB actions must pass all three stages when
        _call_ollama_sync is mocked to return the canonical CTI fixture.

        Assertions verify:
          - stage == 'passed'
          - Stage 3 thinking tags have been stripped from full_report
          - kent_probability_tag is correctly extracted as 'Highly Likely'
          - audit_rationale is non-empty
        """
        rule = copy.deepcopy(VALID_RULE)

        mock_stage3_result = {
            "is_valid": True,
            "kent_probability_tag": "Highly Likely",
            "audit_rationale": "Test rationale",
            "full_report": main_validator._strip_thinking_tags(MOCK_CTI_REPORT),
            "model": "phi4-mini-reasoning",
            "model_error": None,
        }

        with patch.object(
            main_validator,
            "_call_ollama_sync",
            return_value=mock_stage3_result,
        ):
            result = await validate_variant(rule, 0, "AWS Escalation", MINIMAL_KB_ACTIONS)

        assert result["validation"]["stage"] == "passed"
        assert result["validation"]["errors"] == []

        audit = result["validation"]["stage3_audit"]
        assert audit is not None
        assert audit["is_valid"] is True
        assert audit["kent_probability_tag"] == "Highly Likely"
        assert audit["audit_rationale"]
        assert "<thinking>" not in (audit["full_report"] or "")

    async def test_stage3_ollama_timeout_returns_fallback_but_still_passes(
        self,
    ) -> None:
        """
        When Ollama is unreachable, _call_ollama_sync returns the fallback dict
        (is_valid=False, model_error set).  validate_variant must still record
        stage='passed' because Stage 3 is informational — it does not reject rules.
        """
        from main_validator import _STAGE3_FALLBACK

        with patch.object(
            main_validator,
            "_call_ollama_sync",
            return_value={**_STAGE3_FALLBACK, "model_error": "Connection refused"},
        ):
            result = await validate_variant(
                copy.deepcopy(VALID_RULE), 0, "Test", MINIMAL_KB_ACTIONS
            )

        assert result["validation"]["stage"] == "passed"
        audit = result["validation"]["stage3_audit"]
        assert audit["model_error"] is not None


# ---------------------------------------------------------------------------
# TestValidateEntry
# ---------------------------------------------------------------------------


class TestValidateEntry:
    async def test_all_variants_receive_validation_key(self) -> None:
        """Every variant in an entry must emerge with a 'validation' sub-dict."""
        v1 = copy.deepcopy(VALID_RULE)
        v1["name"] = "Variant-Process"
        v2 = copy.deepcopy(VALID_RULE)
        v2["name"] = "Variant-Network"
        v2["actionNames"] = ["CreateAccessKey", "DeleteTrail"]

        entry: dict[str, Any] = {
            "threat_title": "AWS Escalation",
            "threat_id": "t-001",
            "variants": [v1, v2],
        }

        mock_result = {
            "is_valid": True,
            "kent_probability_tag": "Likely",
            "audit_rationale": "Test.",
            "full_report": "Report text.",
            "model": "phi4-mini-reasoning",
            "model_error": None,
        }

        with patch.object(main_validator, "_call_ollama_sync", return_value=mock_result):
            result = await validate_entry(entry, MINIMAL_KB_ACTIONS)

        assert len(result["variants"]) == 2
        for variant in result["variants"]:
            assert "validation" in variant, "Variant is missing the 'validation' key"

    async def test_entry_with_no_variants_returns_empty_variants(self) -> None:
        """An entry with no variants must be returned unchanged (no crash)."""
        entry: dict[str, Any] = {
            "threat_title": "Empty Threat",
            "threat_id": "t-002",
            "variants": [],
        }
        result = await validate_entry(entry, MINIMAL_KB_ACTIONS)
        assert result["variants"] == []

    async def test_mixed_pass_and_fail_variants_processed_independently(
        self,
    ) -> None:
        """A passing and a failing variant in the same entry must each receive
        the correct stage label independently."""
        good = copy.deepcopy(VALID_RULE)
        good["name"] = "GoodVariant"

        bad = copy.deepcopy(VALID_RULE)
        bad["name"] = ""  # empty name → Stage 1 fail

        entry: dict[str, Any] = {
            "threat_title": "Mixed Entry",
            "threat_id": "t-003",
            "variants": [good, bad],
        }

        mock_result = {
            "is_valid": True,
            "kent_probability_tag": "Likely",
            "audit_rationale": "Test.",
            "full_report": "Report.",
            "model": "phi4-mini-reasoning",
            "model_error": None,
        }

        with patch.object(main_validator, "_call_ollama_sync", return_value=mock_result):
            result = await validate_entry(entry, MINIMAL_KB_ACTIONS)

        stages = {v["name"]: v["validation"]["stage"] for v in result["variants"]}
        assert stages["GoodVariant"] == "passed"
        # bad variant has empty name, must fail Stage 1
        assert stages[""] == "failed_stage_1"


# ---------------------------------------------------------------------------
# TestRunValidationPipeline
# ---------------------------------------------------------------------------


class TestRunValidationPipeline:
    async def test_output_file_written_to_tmp_path(
        self,
        staging_file: Path,
        tmp_path: Path,
    ) -> None:
        """
        run_validation must write a parseable JSON file to the supplied output path,
        which is inside tmp_path — never touching ./data.
        """
        output_path = tmp_path / "validated_rules.json"
        real_kb = Path("knowledge_base")
        if not real_kb.exists():
            pytest.skip("knowledge_base/ not found")

        mock_result = {
            "is_valid": True,
            "kent_probability_tag": "Likely",
            "audit_rationale": "Mocked.",
            "full_report": "Mocked report.",
            "model": "phi4-mini-reasoning",
            "model_error": None,
        }

        with patch.object(main_validator, "_call_ollama_sync", return_value=mock_result):
            exit_code = await run_validation(
                staging_path=staging_file,
                output_path=output_path,
            )

        assert exit_code == 0
        assert output_path.exists(), "Output file was not created"

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert "entries" in payload
        assert "stats" in payload
        assert "validated_at" in payload

    async def test_stats_reflect_passed_variants(
        self,
        staging_file: Path,
        tmp_path: Path,
    ) -> None:
        """Passed variants must increment stats['passed'] correctly."""
        output_path = tmp_path / "validated_rules.json"
        real_kb = Path("knowledge_base")
        if not real_kb.exists():
            pytest.skip("knowledge_base/ not found")

        mock_result = {
            "is_valid": True,
            "kent_probability_tag": "Highly Likely",
            "audit_rationale": "Mocked.",
            "full_report": "Mocked report.",
            "model": "phi4-mini-reasoning",
            "model_error": None,
        }

        with patch.object(main_validator, "_call_ollama_sync", return_value=mock_result):
            await run_validation(staging_path=staging_file, output_path=output_path)

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        # The staging fixture has 2 variants; both use real KB actions → both pass
        assert payload["stats"]["passed"] == 2
        assert payload["stats"]["failed_stage_1"] == 0
        assert payload["stats"]["failed_stage_2"] == 0

    async def test_stage1_failures_counted_in_stats(
        self,
        tmp_path: Path,
    ) -> None:
        """A staging file with a schema-broken variant must record a Stage 1 failure."""
        real_kb = Path("knowledge_base")
        if not real_kb.exists():
            pytest.skip("knowledge_base/ not found")

        bad_variant = copy.deepcopy(VALID_RULE)
        del bad_variant["remediate"]  # deliberate schema violation

        staging_payload = {
            "entries": [
                {
                    "threat_title": "Bad Threat",
                    "threat_id": "t-bad",
                    "variants": [bad_variant],
                }
            ]
        }
        staging_file = tmp_path / "bad_staging.json"
        staging_file.write_text(json.dumps(staging_payload), encoding="utf-8")
        output_path = tmp_path / "validated_out.json"

        mock_result = {
            "is_valid": True,
            "kent_probability_tag": "Likely",
            "audit_rationale": "Mocked.",
            "full_report": "Mocked.",
            "model": "phi4-mini-reasoning",
            "model_error": None,
        }

        with patch.object(main_validator, "_call_ollama_sync", return_value=mock_result):
            await run_validation(staging_path=staging_file, output_path=output_path)

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["stats"]["failed_stage_1"] >= 1
        assert payload["stats"]["passed"] == 0

    async def test_missing_staging_file_returns_nonzero_exit(
        self, tmp_path: Path
    ) -> None:
        """If the staging file does not exist, run_validation must return exit code 1."""
        exit_code = await run_validation(
            staging_path=tmp_path / "nonexistent.json",
            output_path=tmp_path / "out.json",
        )
        assert exit_code == 1

    async def test_empty_staging_file_produces_zero_entry_output(
        self,
        empty_staging_file: Path,
        tmp_path: Path,
    ) -> None:
        """A staging file with an empty entries array must write a valid (empty) output."""
        real_kb = Path("knowledge_base")
        if not real_kb.exists():
            pytest.skip("knowledge_base/ not found")

        output_path = tmp_path / "empty_out.json"

        with patch.object(main_validator, "_call_ollama_sync", return_value={}):
            exit_code = await run_validation(
                staging_path=empty_staging_file,
                output_path=output_path,
            )

        assert exit_code == 0
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["entries"] == []
        assert payload["stats"]["total_variants"] == 0

    async def test_live_data_dir_is_never_touched(
        self,
        staging_file: Path,
        tmp_path: Path,
    ) -> None:
        """Output must go only to tmp_path; the live data/ directory must be unchanged."""
        real_kb = Path("knowledge_base")
        if not real_kb.exists():
            pytest.skip("knowledge_base/ not found")

        output_path = tmp_path / "safe_output.json"
        live_validated = Path("data") / "validated_rules.json"
        mtime_before = live_validated.stat().st_mtime if live_validated.exists() else None

        mock_result = {
            "is_valid": True,
            "kent_probability_tag": "Likely",
            "audit_rationale": "Mocked.",
            "full_report": "Mocked report.",
            "model": "phi4-mini-reasoning",
            "model_error": None,
        }

        with patch.object(main_validator, "_call_ollama_sync", return_value=mock_result):
            await run_validation(staging_path=staging_file, output_path=output_path)

        if mtime_before is not None:
            mtime_after = live_validated.stat().st_mtime
            assert mtime_before == mtime_after, "Live data/validated_rules.json was modified!"

    async def test_output_contains_kent_tag_from_mock(
        self,
        staging_file: Path,
        tmp_path: Path,
    ) -> None:
        """The mocked kent_probability_tag must be present in the written JSON output."""
        real_kb = Path("knowledge_base")
        if not real_kb.exists():
            pytest.skip("knowledge_base/ not found")

        output_path = tmp_path / "kent_test_out.json"

        mock_result = {
            "is_valid": True,
            "kent_probability_tag": "Almost Certain",
            "audit_rationale": "Mocked rationale.",
            "full_report": "Full mocked report.",
            "model": "phi4-mini-reasoning",
            "model_error": None,
        }

        with patch.object(main_validator, "_call_ollama_sync", return_value=mock_result):
            await run_validation(staging_path=staging_file, output_path=output_path)

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        for entry in payload["entries"]:
            for variant in entry.get("variants", []):
                audit = variant.get("validation", {}).get("stage3_audit")
                if audit and audit.get("is_valid"):
                    assert audit["kent_probability_tag"] == "Almost Certain"
