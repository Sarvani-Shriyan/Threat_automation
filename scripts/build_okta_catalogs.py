#!/usr/bin/env python3
"""
Rebuild Okta knowledge-base catalogs from the Okta Event Types reference page.

Sources:
  - https://sec.okta.com/articles/2023/02/user-sign-and-recovery-events-okta-system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
  - https://support.okta.com/help/s/article/User-Signin-and-Recovery-Events-in-the-Okta-System-Log

Run: python scripts/build_okta_catalogs.py
Optional: python scripts/build_okta_catalogs.py --csv path/to/okta-event-types.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KB = ROOT / "knowledge_base"
DEFAULT_CSV_URL = "https://developer.okta.com/docs/okta-event-types.csv"

AUTH_PREFIXES = (
    "user.session.",
    "user.authentication.",
    "user.mfa.",
    "user.account.",
    "user.risk.",
    "user.credential.",
    "user.behavior.",
    "security.session",
)
ADMIN_PREFIXES = (
    "policy.",
    "system.",
    "application.",
    "user.user_privilege.",
    "user.lifecycle.",
    "group.lifecycle.",
    "group.privilege.",
    "org.",
    "directory.",
    "iam.",
    "zone.",
    "network.",
    "feature.",
    "custom_role.",
    "access.group.",
    "resource.set.",
    "admin.app.",
)


def load_event_names(csv_path: Path | None) -> list[str]:
    if csv_path and csv_path.exists():
        with csv_path.open(encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            col = "Event Type" if "Event Type" in (reader.fieldnames or []) else (reader.fieldnames or [""])[0]
            return sorted({row[col].strip() for row in reader if row.get(col, "").strip()})

    try:
        import urllib.request

        with urllib.request.urlopen(DEFAULT_CSV_URL, timeout=60) as resp:
            text = resp.read().decode("utf-8")
        reader = csv.DictReader(text.splitlines())
        col = "Event Type" if "Event Type" in (reader.fieldnames or []) else (reader.fieldnames or [""])[0]
        return sorted({row[col].strip() for row in reader if row.get(col, "").strip()})
    except Exception as exc:
        raise SystemExit(
            f"Could not fetch Okta CSV ({exc}). Pass --csv with a local copy of {DEFAULT_CSV_URL}"
        ) from exc


def classify(events: list[str]) -> tuple[list[str], list[str]]:
    auth: set[str] = set()
    admin: set[str] = set()
    for e in events:
        if e.startswith(AUTH_PREFIXES):
            auth.add(e)
        elif e.startswith(ADMIN_PREFIXES):
            admin.add(e)
    return sorted(auth), sorted(admin)


def write_catalog(path: Path, profile: str, display: str, source: str, keywords: list[str], events: list[str]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    path.write_text(
        json.dumps(
            {
                "platform": "okta",
                "catalog_profile": profile,
                "display_name": display,
                "source": source,
                "references": [
                    "https://sec.okta.com/articles/2023/02/user-sign-and-recovery-events-okta-system-log/",
                    "https://developer.okta.com/docs/reference/api/event-types/",
                    "https://support.okta.com/help/s/article/User-Signin-and-Recovery-Events-in-the-Okta-System-Log?language=en_US",
                ],
                "keywords": keywords,
                "actionNames": events,
                "event_count": len(events),
                "synced_at": now,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Okta KB catalogs")
    parser.add_argument("--csv", type=Path, default=None, help="Local okta-event-types.csv")
    args = parser.parse_args()

    events = load_event_names(args.csv)
    auth_events, admin_events = classify(events)

    write_catalog(
        KB / "okta_auth_events.json",
        "okta_auth",
        "Okta Authentication & Session Events",
        "okta_system_log_auth",
        [
            "okta",
            "mfa",
            "session",
            "sign-in",
            "recovery",
            "authentication",
            "session hijacking",
            "identity takeover",
            "saml bypass",
        ],
        auth_events,
    )
    write_catalog(
        KB / "okta_admin_events.json",
        "okta_admin",
        "Okta Administrative & Policy Events",
        "okta_system_log_admin",
        ["okta", "policy", "administrative", "api token", "privilege", "directory", "lifecycle"],
        admin_events,
    )
    print(f"Wrote {len(auth_events)} auth + {len(admin_events)} admin Okta events to {KB}")


if __name__ == "__main__":
    main()
