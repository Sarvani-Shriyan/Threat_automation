import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from config.settings import Settings
from threat_pipeline.models.rules import ThreatRule, ValidationStatus
from threat_pipeline.validators.rule_validator import RuleValidator


@pytest.fixture
def validator() -> RuleValidator:
    return RuleValidator(Settings(llm_mock=True))


def _valid_rule(**overrides) -> ThreatRule:
    base = dict(
        name="Test Rule",
        description="Detects suspicious activity",
        actionNames=["alert_soc"],
        defaultSeverity="high",
        threatType="identity",
        recommend="Monitor logs",
        remediate="Disable account",
    )
    base.update(overrides)
    return ThreatRule(**base)


def test_valid_rule_passes(validator: RuleValidator) -> None:
    result = validator.validate_variant(0, _valid_rule())
    assert result.status == ValidationStatus.VALID
    assert not result.errors


def test_invalid_action_fails(validator: RuleValidator) -> None:
    result = validator.validate_variant(0, _valid_rule(actionNames=["nuke_from_orbit"]))
    assert result.status == ValidationStatus.INVALID
    assert any(e.code == "ACTION_SEMANTIC" for e in result.errors)


def test_invalid_severity_fails(validator: RuleValidator) -> None:
    result = validator.validate_variant(0, _valid_rule(defaultSeverity="apocalyptic"))
    assert result.status == ValidationStatus.INVALID
    assert any(e.code == "SEVERITY_ENUM" for e in result.errors)


def test_empty_name_fails(validator: RuleValidator) -> None:
    result = validator.validate_variant(0, _valid_rule(name="  "))
    assert result.status == ValidationStatus.INVALID
    assert any(e.code == "SCHEMA_REQUIRED" for e in result.errors)
