#!/usr/bin/env python3
"""
Rebuild Azure knowledge-base catalogs from iann0036/iam-dataset azure/map.json.

Authoritative ARM RBAC operation format:
  Provider.Namespace/resourceType/operation
  e.g. Microsoft.RecoveryServices/vaults/replicationFabrics/delete
       ArizeAi.ObservabilityEval/register/action

Source: https://raw.githubusercontent.com/iann0036/iam-dataset/refs/heads/main/azure/map.json

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
MAP_RAW = KB / "catalogs" / "azure_map.raw.json"
MAP_URL = "https://raw.githubusercontent.com/iann0036/iam-dataset/refs/heads/main/azure/map.json"

MUST_ADMIN = {
    "Microsoft.RecoveryServices/vaults/replicationFabrics/delete",
    "Microsoft.RecoveryServices/vaults/replicationFabrics/replicationNetworks/replicationNetworkMappings/delete",
}


def _download(url: str, dest: Path) -> None:
    import urllib.request

    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {url} -> {dest.name}")
    urllib.request.urlretrieve(url, dest)


def extract_map_operations(map_data: dict) -> set[str]:
    """Extract RBAC operation keys from map.json (verb -> path -> operation)."""
    operations: set[str] = set()
    for _verb, paths in map_data.items():
        if not isinstance(paths, dict):
            continue
        for _path, path_ops in paths.items():
            if not isinstance(path_ops, dict):
                continue
            for op_name, meta in path_ops.items():
                if not isinstance(op_name, str) or "/" not in op_name:
                    continue
                if op_name.startswith("/"):
                    continue
                if isinstance(meta, dict):
                    operations.add(op_name)
    return operations


def _is_third_party_rp(op: str) -> bool:
    """Publisher.Provider/resource/operation (e.g. Anyscale.Platform/admin/action)."""
    if op.startswith("Microsoft.") or "/" not in op:
        return False
    provider = op.split("/", 1)[0]
    return "." in provider


def _is_admin(op: str) -> bool:
    if op in MUST_ADMIN:
        return True
    low = op.lower()
    if low.startswith("microsoft.authorization/"):
        return True
    if low.startswith("microsoft.recoveryservices/"):
        return True
    if low.startswith("microsoft.resources/") and any(
        x in low for x in ("resourcegroups/delete", "deployments/delete", "resourcegroups/write")
    ):
        return True
    if any(
        x in low
        for x in (
            "replicationfabrics",
            "replicationnetworkmappings",
            "replicationprotecteditems",
            "roleassignments/",
            "roledefinitions/",
        )
    ):
        return True
    if _is_third_party_rp(op) and low.rsplit("/", 1)[-1] in (
        "delete",
        "write",
        "action",
        "read",
    ):
        return True
    return False


def _is_auth(op: str) -> bool:
    low = op.lower()
    if low.startswith("microsoft.azureactivedirectory/"):
        return True
    if low.startswith("microsoft.aad/"):
        return True
    if low.startswith("microsoft.graph") or low.startswith("microsoft.graph/"):
        return True
    return any(
        x in low
        for x in (
            "/entratenants/",
            "b2cdirectories",
            "b2ctenants",
            "ciamdirectories",
            "guestusages",
            "directories/",
        )
    )


def classify(operations: set[str]) -> tuple[list[str], list[str]]:
    admin_ops = sorted({op for op in operations if _is_admin(op)} | MUST_ADMIN)
    auth_ops = sorted({op for op in operations if _is_auth(op)})
    return admin_ops, auth_ops


def write_catalog(
    path: Path,
    *,
    profile: str,
    display_name: str,
    source: str,
    keywords: list[str],
    action_names: list[str],
    synced_at: str,
) -> None:
    path.write_text(
        json.dumps(
            {
                "platform": "azure",
                "catalog_profile": profile,
                "display_name": display_name,
                "source": source,
                "source_file": "azure/map.json",
                "references": [MAP_URL],
                "keywords": keywords,
                "actionNames": action_names,
                "event_count": len(action_names),
                "synced_at": synced_at,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Azure KB catalogs from map.json")
    parser.add_argument("--map", type=Path, default=MAP_RAW, help="Local azure/map.json")
    args = parser.parse_args()

    if not args.map.exists():
        _download(MAP_URL, args.map)

    map_data = json.loads(args.map.read_text(encoding="utf-8"))
    all_ops = extract_map_operations(map_data)
    admin_ops, auth_ops = classify(all_ops)
    now = datetime.now(timezone.utc).isoformat()

    write_catalog(
        KB / "azure_admin_events.json",
        profile="azure_admin",
        display_name="Azure ARM Administrative Operations (map.json)",
        source="iann0036_azure_map",
        keywords=[
            "azure",
            "microsoft.recoveryservices",
            "resourcegroups",
            "arm template",
            "disaster recovery",
            "replication",
            "rbac",
            "role assignment",
            "policy",
            "delete",
        ],
        action_names=admin_ops,
        synced_at=now,
    )
    write_catalog(
        KB / "azure_auth_events.json",
        profile="azure_auth",
        display_name="Azure Entra / Identity ARM Operations (map.json)",
        source="iann0036_azure_map",
        keywords=[
            "azure",
            "entra id",
            "microsoft entra",
            "entra",
            "aad",
            "service principal",
            "directory",
            "b2c",
            "ciam",
            "authentication",
        ],
        action_names=auth_ops,
        synced_at=now,
    )

    print(f"map.json operations total : {len(all_ops)}")
    print(f"azure_admin_events.json   : {len(admin_ops)}")
    print(f"azure_auth_events.json    : {len(auth_ops)}")
    assert all(m in admin_ops for m in MUST_ADMIN)
    rp_sample = next((o for o in all_ops if "." in o.split("/")[0] and not o.startswith("Microsoft.")), None)
    if rp_sample:
        print(f"third-party RP sample     : {rp_sample}")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
