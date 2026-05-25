#!/usr/bin/env python3
"""Rebuild GitHub workflow + audit catalogs from vendored reference extracts."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KB = ROOT / "knowledge_base"

WORKFLOW_REF = ROOT / "agent-tools/github_workflow_events.txt"
AUDIT_REF = ROOT / "agent-tools/github_audit_events.txt"


def build_workflow_events() -> list[str]:
    if WORKFLOW_REF.exists():
        text = WORKFLOW_REF.read_text(encoding="utf-8")
        events = sorted(set(re.findall(r"^## `([^`]+)`", text, re.M)))
        return [e for e in events if "use `" not in e and e != "pull_request_comment"]
    return [
        "branch_protection_rule", "check_run", "check_suite", "create", "delete",
        "deployment", "deployment_status", "discussion", "discussion_comment", "fork",
        "gollum", "image_version", "issue_comment", "issues", "label", "merge_group",
        "milestone", "page_build", "public", "pull_request", "pull_request_review",
        "pull_request_review_comment", "pull_request_target", "push", "registry_package",
        "release", "repository_dispatch", "schedule", "status", "watch",
        "workflow_call", "workflow_dispatch", "workflow_run",
    ]


def build_audit_events() -> list[str]:
    events: set[str] = set()
    if AUDIT_REF.exists():
        category = None
        for line in AUDIT_REF.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^## ([a-z0-9_]+) category actions", line)
            if m:
                category = m.group(1)
                continue
            m = re.match(r"\| `([^`]+)` \|", line)
            if category and m:
                action = m.group(1).strip()
                events.add(action if "." in action else f"{category}.{action}")

    events.update([
        "org.disable_two_factor_requirement",
        "org.enable_two_factor_requirement",
        "repo.public",
        "repo.access",
        "repo.destroy",
        "repo.create",
        "secret_scanning_alert.bypass",
        "secret_scanning_alert.create",
        "repo.cb_protection_rule_create",
        "repo.cb_protection_rule_destroy",
    ])
    return sorted(events)


def main() -> None:
    workflow = build_workflow_events()
    audit = build_audit_events()
    now = datetime.now(timezone.utc).isoformat()

    (KB / "github_actions_workflow.json").write_text(
        json.dumps(
            {
                "platform": "github",
                "catalog_profile": "github_workflow",
                "display_name": "GitHub Actions Workflow Triggers",
                "source": "github_docs_actions_events",
                "references": [
                    "https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows",
                    "https://www.devopsschool.com/blog/github-actioon-list-of-events-that-trigger-workflows/",
                ],
                "keywords": [
                    "github actions", "workflow", "ci/cd", "pipeline",
                    "pull_request_target", "workflow_dispatch", "runner", "github",
                ],
                "actionNames": workflow,
                "synced_at": now,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    (KB / "github_audit_logs.json").write_text(
        json.dumps(
            {
                "platform": "github",
                "catalog_profile": "github_audit",
                "display_name": "GitHub Organization Audit Log Events",
                "source": "github_docs_org_audit_log",
                "references": [
                    "https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization",
                ],
                "keywords": [
                    "audit log", "organization", "org.", "repo.",
                    "secret_scanning", "two-factor", "bypass", "administrative", "github",
                ],
                "actionNames": audit,
                "synced_at": now,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"workflow events: {len(workflow)}")
    print(f"audit events: {len(audit)}")


if __name__ == "__main__":
    main()
