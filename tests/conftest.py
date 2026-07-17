"""
Shared pytest fixtures for the Threat Automation test suite.

Design principles
-----------------
- Every fixture that touches the filesystem uses `tmp_path` so no test can
  accidentally write to the live ./data directory.
- KB action fixtures for unit tests use a hand-crafted minimal frozenset;
  integration tests load from the real knowledge_base/ directory.
- The mock CTI report deliberately contains a <thinking> block and all five
  Sherman Kent report sections so parsing helpers can be exercised end-to-end.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Canonical 7-key rule payloads
# ---------------------------------------------------------------------------

#: A rule whose actionNames come from the real aws_cloudtrail KB catalog.
VALID_RULE: dict[str, Any] = {
    "name": "Detect-AssumeRole-Privilege-Escalation",
    "description": (
        "Detects suspicious AssumeRole API calls used for privilege escalation "
        "inside AWS IAM environments."
    ),
    "actionNames": ["AssumeRole", "CreateUser"],
    "defaultSeverity": "High",
    "threatType": "PrivilegeEscalation",
    "recommend": (
        "Review IAM role trust policies and restrict cross-account AssumeRole "
        "permissions to known principals only."
    ),
    "remediate": (
        "Revoke all active session tokens for the affected principal, rotate "
        "access keys, and audit CloudTrail for full blast radius."
    ),
}

#: Same structure but actionNames reference the Okta catalog.
VALID_RULE_OKTA: dict[str, Any] = {
    "name": "Detect-Okta-Session-Hijack",
    "description": "Detects session roaming anomalies in Okta auth events.",
    "actionNames": ["security.session.detect_client_roaming"],
    "defaultSeverity": "Critical",
    "threatType": "AccountTakeover",
    "recommend": "Force MFA re-enrollment and expire all active sessions.",
    "remediate": "Disable the affected account and audit recent login history.",
}


# ---------------------------------------------------------------------------
# Minimal KB frozenset used by Stage 2 unit tests (no filesystem dependency)
# ---------------------------------------------------------------------------

MINIMAL_KB_ACTIONS: frozenset[str] = frozenset(
    {
        # AWS CloudTrail
        "AssumeRole",
        "CreateUser",
        "AttachUserPolicy",
        "PutUserPolicy",
        "CreateAccessKey",
        "DeleteTrail",
        "StopLogging",
        # Okta
        "security.session.detect_client_roaming",
        "user.account.expire_password",
        # GitHub
        "branch_protection_rule",
        "check_run",
    }
)


# ---------------------------------------------------------------------------
# Simulated phi4-mini-reasoning CTI report (Stage 3 mock response)
# ---------------------------------------------------------------------------

#: Contains a <thinking> block that must be stripped, plus all five mandatory
#: Sherman Kent report sections with an unambiguous Probability Assessment line.
MOCK_CTI_REPORT: str = """\
<thinking>
Let me carefully evaluate this detection rule against Sherman Kent's analytic framework.
The rule targets AssumeRole calls which are commonly abused during privilege escalation.
I need to assess probability and confidence separately.
</thinking>

## 1. Executive Summary
It is Highly Likely that this detection rule would surface real-world privilege
escalation activity targeting AWS IAM environments, based on known attacker
tradecraft observed in public threat reports.

## 2. Technical Observations & Evidence Categorization
- AssumeRole API call: Reported (third-party CTI feeds)
- CreateUser following AssumeRole: Inferred (deduced from attack chain patterns)
- CloudTrail log availability: Source-observed (assumed present in monitored accounts)

## 3. Core Analysis & Assessment
- Primary Hypothesis: A threat actor is abusing AWS IAM role chaining to escalate
  privileges and create persistent access via a new IAM user.
- Probability Assessment: Highly Likely — consistent with documented AWS lateral
  movement and privilege escalation patterns (MITRE T1078.004).
- Confidence Assessment & Justification: Medium Confidence — the assessment relies
  on third-party threat intelligence rather than direct incident data.

## 4. Alternative Hypotheses
- The AssumeRole call originates from a legitimate CI/CD pipeline performing
  cross-account deployments, not an adversary.
- Automated cloud governance tooling may trigger both API calls during routine
  compliance remediation cycles.

## 5. Collection Gaps
- No direct CloudTrail event logs were supplied for correlation.
- Endpoint telemetry from the originating host is absent, preventing confirmation
  of lateral movement beyond the IAM API calls.
"""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def valid_rule() -> dict[str, Any]:
    """Deep copy of the canonical valid 7-key rule (AWS actions)."""
    return dict(VALID_RULE)


@pytest.fixture()
def valid_rule_okta() -> dict[str, Any]:
    """Deep copy of the canonical valid 7-key rule (Okta actions)."""
    return dict(VALID_RULE_OKTA)


@pytest.fixture()
def minimal_kb() -> frozenset[str]:
    """Small frozenset used by Stage 2 unit tests — no filesystem I/O."""
    return MINIMAL_KB_ACTIONS


@pytest.fixture()
def mock_cti_report() -> str:
    """The simulated phi4-mini-reasoning response (thinking tags + 5 sections)."""
    return MOCK_CTI_REPORT


@pytest.fixture()
def staging_file(tmp_path: Path, valid_rule: dict[str, Any]) -> Path:
    """
    Write a minimal generated_rules_staging.json to a temp directory and
    return its Path.  Uses two variants so multi-variant entry logic is tested.
    """
    variant_process = dict(valid_rule)
    variant_process["name"] = "Detect-AssumeRole-Process-CLI"

    variant_network = dict(valid_rule)
    variant_network["name"] = "Detect-AssumeRole-Network-API"
    variant_network["actionNames"] = ["CreateAccessKey", "DeleteTrail"]

    payload: dict[str, Any] = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "entries": [
            {
                "threat_title": "AWS IAM Privilege Escalation via AssumeRole",
                "threat_id": "threat-001",
                "variants": [variant_process, variant_network],
            }
        ],
    }
    path = tmp_path / "generated_rules_staging.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.fixture()
def empty_staging_file(tmp_path: Path) -> Path:
    """A staging file containing zero entries."""
    path = tmp_path / "generated_rules_staging_empty.json"
    path.write_text(json.dumps({"entries": []}), encoding="utf-8")
    return path


@pytest.fixture()
def temp_kb_dir(tmp_path: Path) -> Path:
    """
    A self-contained knowledge_base directory under tmp_path with two minimal
    catalog JSON files.  Used for load_kb_action_set isolation tests.
    """
    kb = tmp_path / "knowledge_base"
    kb.mkdir()

    (kb / "aws_test.json").write_text(
        json.dumps(
            {
                "platform": "aws",
                "display_name": "AWS Test Catalog",
                "actionNames": ["AssumeRole", "CreateUser", "DeleteTrail"],
            }
        ),
        encoding="utf-8",
    )
    (kb / "okta_test.json").write_text(
        json.dumps(
            {
                "platform": "okta",
                "display_name": "Okta Test Catalog",
                "actionNames": ["security.session.detect_client_roaming"],
            }
        ),
        encoding="utf-8",
    )
    # A raw upstream dump that must be SKIPPED by load_kb_action_set
    (kb / "upstream.raw.json").write_text(
        json.dumps({"actionNames": ["ShouldBeIgnored"]}),
        encoding="utf-8",
    )
    return kb
