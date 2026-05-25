#!/usr/bin/env python3
"""
Rebuild Azure knowledge-base catalogs from iann0036/iam-dataset provider operations.

Source: azure/provider-operations.json
Run: python scripts/build_azure_catalogs.py
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KB = ROOT / "knowledge_base"
RAW = KB / "catalogs" / "azure_provider_operations.raw.json"
SOURCE_URL = "https://raw.githubusercontent.com/iann0036/iam-dataset/main/azure/provider-operations.json"

MUST_ADMIN = {
    "Microsoft.RecoveryServices/vaults/replicationFabrics/delete",
    "Microsoft.RecoveryServices/vaults/replicationFabrics/replicationNetworks/replicationNetworkMappings/delete",
}

ENTRA_AUDIT_ACTIVITIES = [
    "Add member to group",
    "Add app role assignment to service principal",
    "Add service principal",
    "Add service principal credentials",
    "Consent to application",
    "Change user password",
    "Reset password (by admin)",
    "Reset user password",
    "Add owner to application",
    "Update application",
    "Update service principal",
    "Set federation configuration on domain",
    "Add delegated permission grant",
    "Add application",
    "Delete application",
    "Remove member from group",
    "Remove owner from application",
    "Add owner to service principal",
    "Add credentials to service principal",
    "Service principal sign-in",
    "Sign-in activity",
    "User signed in",
    "User registered security info",
    "User registered all required security info",
    "User started security info registration",
    "User changed default security method",
    "User updated security info",
    "User deleted security info",
    "User reviewed security info",
    "User registered device",
    "User deleted device",
    "Update conditional access policy",
    "Add conditional access policy",
    "Delete conditional access policy",
    "Add policy",
    "Update policy",
    "Add app role assignment grant to user",
    "Grant admin consent",
    "Revoke all refresh tokens for user",
    "Reset password (self-service)",
    "Self-service password reset flow",
    "AuditActivity",
]


def _download(url: str, dest: Path) -> None:
    import urllib.request

    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {url} -> {dest.name}")
    urllib.request.urlretrieve(url, dest)


def _collect_ops(node: object, out: set[str]) -> None:
    if isinstance(node, dict):
        name = node.get("name")
        if isinstance(name, str) and name.startswith("Microsoft."):
            out.add(name)
        for value in node.values():
            _collect_ops(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_ops(item, out)


def _is_admin(op: str) -> bool:
    low = op.lower()
    if op in MUST_ADMIN:
        return True
    if "recoveryservices" in low and ("replication" in low or "delete" in low or "write" in low):
        return True
    if "microsoft.authorization" in low and any(
        x in low
        for x in ("roleassignment", "roledefinition", "elevateaccess", "denyassignment", "policyassignment")
    ):
        return True
    if "microsoft.resources" in low and any(
        x in low for x in ("resourcegroups/delete", "deployments/delete", "resourcegroups/write")
    ):
        return True
    return any(
        x in low
        for x in ("replicationfabrics", "replicationnetworkmappings", "replicationprotecteditems")
    )


def _is_auth_arm(op: str) -> bool:
    low = op.lower()
    return any(
        p in low
        for p in ("microsoft.azureactivedirectory/", "microsoft.aad/", "microsoft.graphservices/")
    ) and any(a in low for a in ("/write", "/delete", "/action", "credential", "tenant", "directory"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Azure KB catalogs")
    parser.add_argument("--raw", type=Path, default=RAW, help="Local provider-operations.json")
    args = parser.parse_args()

    if not args.raw.exists():
        _download(SOURCE_URL, args.raw)

    providers = json.loads(args.raw.read_text(encoding="utf-8"))
    all_ops: set[str] = set()
    _collect_ops(providers, all_ops)

    admin_ops = sorted({op for op in all_ops if _is_admin(op)} | MUST_ADMIN)
    auth_ops = sorted(set(ENTRA_AUDIT_ACTIVITIES) | {op for op in all_ops if _is_auth_arm(op)})
    now = datetime.now(timezone.utc).isoformat()

    for filename, profile, display, source, keywords, events in (
        (
            "azure_admin_events.json",
            "azure_admin",
            "Azure ARM Administrative & Infrastructure Events",
            "iann0036_iam_dataset",
            [
                "azure",
                "microsoft.recoveryservices",
                "resourcegroups",
                "arm template",
                "disaster recovery",
                "replication",
                "rbac",
                "role assignment",
                "delete",
            ],
            admin_ops,
        ),
        (
            "azure_auth_events.json",
            "azure_auth",
            "Azure Entra ID Identity & Authentication Events",
            "iann0036_iam_dataset_entra",
            [
                "azure",
                "entra id",
                "entra",
                "microsoft entra",
                "aad",
                "service principal",
                "token",
                "directory",
                "sign-in",
                "authentication",
            ],
            auth_ops,
        ),
    ):
        (KB / filename).write_text(
            json.dumps(
                {
                    "platform": "azure",
                    "catalog_profile": profile,
                    "display_name": display,
                    "source": source,
                    "source_file": "azure/provider-operations.json",
                    "references": ["https://github.com/iann0036/iam-dataset/tree/main/azure"],
                    "keywords": keywords,
                    "actionNames": events,
                    "event_count": len(events),
                    "synced_at": now,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    print(f"Wrote {len(admin_ops)} admin + {len(auth_ops)} auth Azure events to {KB}")
    assert all(m in admin_ops for m in MUST_ADMIN)
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
