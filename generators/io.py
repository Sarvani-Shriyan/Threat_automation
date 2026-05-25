# pip install pydantic

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_FILTERED_INPUT = Path("data/filtered_threat_queue.json")
DEFAULT_STAGING_OUTPUT = Path("data/generated_rules_staging.json")


def load_filtered_threats(path: Path | str = DEFAULT_FILTERED_INPUT) -> list[dict[str, Any]]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Filtered queue not found: {file_path}")
    data = json.loads(file_path.read_text(encoding="utf-8"))
    return list(data.get("articles", []))


def _empty_staging_payload() -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "generated_at": now,
        "last_updated_at": now,
        "threat_count": 0,
        "total_rule_variants": 0,
        "successful_threats": 0,
        "failed_threats": 0,
        "entries": [],
    }


def _recompute_counts(payload: dict[str, Any]) -> None:
    entries = payload.get("entries", [])
    payload["threat_count"] = len(entries)
    payload["total_rule_variants"] = sum(e.get("variant_count", 0) for e in entries)
    payload["successful_threats"] = sum(
        1 for e in entries if e.get("generation_status") == "success"
    )
    payload["failed_threats"] = len(entries) - payload["successful_threats"]


class StagingStore:
    """Incremental append-only persistence for generated rule staging."""

    def __init__(self, path: Path | str = DEFAULT_STAGING_OUTPUT) -> None:
        self.path = Path(path)
        os.makedirs(self.path.parent, exist_ok=True)
        if not self.path.exists():
            self._write(_empty_staging_payload())
            logger.info("Initialized empty staging file at %s", self.path)

    def load_entries(self) -> list[dict[str, Any]]:
        payload = self._read()
        return list(payload.get("entries", []))

    def processed_threat_ids(self) -> set[str]:
        return {e.get("threat_id", "") for e in self.load_entries() if e.get("threat_id")}

    def append_entry(self, entry: dict[str, Any]) -> None:
        payload = self._read()
        entries: list[dict[str, Any]] = list(payload.get("entries", []))
        entries.append(entry)
        payload["entries"] = entries
        payload["last_updated_at"] = datetime.now(timezone.utc).isoformat()
        _recompute_counts(payload)
        self._write(payload)
        logger.debug(
            "staging_append threat_id=%s variants=%s",
            entry.get("threat_id"),
            entry.get("variant_count"),
        )

    def update_run_stats(self, stats: dict[str, Any]) -> None:
        payload = self._read()
        payload["run_stats"] = stats
        payload["last_updated_at"] = datetime.now(timezone.utc).isoformat()
        self._write(payload)

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return _empty_staging_payload()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return {**_empty_staging_payload(), "entries": data}
            if "entries" not in data:
                data["entries"] = []
            return data
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("staging_read_failed error=%s — reinitializing", exc)
            return _empty_staging_payload()

    def _write(self, payload: dict[str, Any]) -> None:
        self.path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


def export_staging(
    entries: list[dict[str, Any]],
    *,
    output_path: Path | str = DEFAULT_STAGING_OUTPUT,
    stats: dict[str, Any] | None = None,
) -> Path:
    """Bulk export (legacy) — prefer StagingStore.append_entry for streaming runs."""
    store = StagingStore(output_path)
    for entry in entries:
        store.append_entry(entry)
    if stats:
        store.update_run_stats(stats)
    return store.path
