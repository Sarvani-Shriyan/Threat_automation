#!/usr/bin/env python3
"""
Download authoritative IAM datasets and build local knowledge-base catalogs.

Source datasets (iann0036/iam-dataset) — vendored locally, no runtime URLs.
  - GCP: gcp/permissions.json  -> permission string keys
  - AWS: aws/docs.json        -> Service.Action API name keys

Run: python scripts/sync_knowledge_base.py
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOGS_DIR = ROOT / "knowledge_base" / "catalogs"

GCP_SOURCE = "https://raw.githubusercontent.com/iann0036/iam-dataset/refs/heads/main/gcp/permissions.json"
AWS_SOURCE = "https://raw.githubusercontent.com/iann0036/iam-dataset/refs/heads/main/aws/docs.json"

GCP_RAW = CATALOGS_DIR / "gcp_permissions.raw.json"
AWS_RAW = CATALOGS_DIR / "aws_docs.raw.json"
GCP_CATALOG = CATALOGS_DIR / "gcp_iam_permissions.json"
AWS_CATALOG = CATALOGS_DIR / "aws_iam_actions.json"


def _download(url: str, dest: Path) -> None:
    import urllib.request

    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {url} -> {dest.name}")
    urllib.request.urlretrieve(url, dest)


def build_gcp_catalog(raw_path: Path, out_path: Path) -> int:
    data = json.loads(raw_path.read_text(encoding="utf-8"))
    permissions = sorted(data.keys()) if isinstance(data, dict) else []
    catalog = {
        "platform": "gcp",
        "display_name": "GCP IAM Permissions (iann0036/iam-dataset)",
        "source": "iann0036_iam_dataset",
        "source_file": "gcp/permissions.json",
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "keywords": ["gcp", "google cloud", "iam", "cloud logging", "bigquery", "gke", "compute"],
        "actionNames": permissions,
        "permission_count": len(permissions),
    }
    out_path.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    return len(permissions)


def build_aws_catalog(raw_path: Path, out_path: Path) -> int:
    data = json.loads(raw_path.read_text(encoding="utf-8"))
    actions = sorted(data.keys()) if isinstance(data, dict) else []
    catalog = {
        "platform": "aws",
        "display_name": "AWS API Actions (iann0036/iam-dataset)",
        "source": "iann0036_iam_dataset",
        "source_file": "aws/docs.json",
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "keywords": [
            "aws", "cloudtrail", "iam", "sts", "s3", "ec2", "lambda",
            "guardduty", "kms", "secretsmanager", "organizations",
        ],
        "actionNames": actions,
        "action_count": len(actions),
    }
    out_path.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    return len(actions)


def main() -> int:
    if not GCP_RAW.exists():
        _download(GCP_SOURCE, GCP_RAW)
    if not AWS_RAW.exists():
        _download(AWS_SOURCE, AWS_RAW)

    gcp_n = build_gcp_catalog(GCP_RAW, GCP_CATALOG)
    aws_n = build_aws_catalog(AWS_RAW, AWS_CATALOG)

    print(f"Built GCP catalog: {gcp_n} permissions -> {GCP_CATALOG}")
    print(f"Built AWS catalog: {aws_n} actions -> {AWS_CATALOG}")
    print("Done. Knowledge base loader reads catalogs/*.json automatically.")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
