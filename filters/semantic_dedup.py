"""
Tiered Semantic Deduplication Engine — Step 2 filter layer.

Two-tier workflow
─────────────────
Tier 1  SimHash near-duplicate check (fast, CPU, no ML)
        Generates a 64-bit Charikar fingerprint of the article text and checks
        it against all stored fingerprints using Hamming distance.
        Distance ≤ SIMHASH_HAMMING_THRESHOLD  →  near-textual duplicate, drop.

Tier 2  LanceDB vector cosine-similarity check (semantic, sentence-transformers)
        Encodes article text as a 384-dim sentence embedding and queries the
        local LanceDB table for the nearest historical threat vector.
        Cosine distance ≤ COSINE_DISTANCE_THRESHOLD  →  semantic duplicate, drop.

Registration
────────────
After Gemma confirms an article, call `register_confirmed(article)` to:
  • Persist its SimHash fingerprint to data/filter_simhash_state.json
  • Insert its dense embedding into the LanceDB threat_vectors table

Both stores enforce a rolling VECTOR_MAX_RECORDS ceiling by evicting the oldest
entries, keeping memory and disk usage bounded across long operational intervals.

Graceful degradation
────────────────────
Both tiers use lazy imports.  If `simhash` is unavailable Tier 1 is skipped.
If `lancedb` or `sentence-transformers` are unavailable Tier 2 is skipped.
A warning is logged and the pipeline continues unimpeded.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ingestion.config import (
    COSINE_DISTANCE_THRESHOLD,
    EMBEDDING_DIM,
    EMBEDDING_MODEL_NAME,
    LANCEDB_PATH,
    LANCEDB_TABLE_NAME,
    SIMHASH_HAMMING_THRESHOLD,
    SIMHASH_STATE_PATH,
    VECTOR_MAX_RECORDS,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_EMBEDDING_TEXT_MAX_CHARS = 2000  # chars of content fed into the embedder


def _threat_id(article: dict[str, Any]) -> str:
    """Stable 16-hex threat identifier (mirrors rule_engine.threat_id)."""
    key = f"{article.get('title', '')}|{article.get('url', '')}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _article_text(article: dict[str, Any]) -> str:
    """Build the canonical text blob used for both SimHash and embeddings."""
    title = article.get("title") or ""
    content = article.get("content") or article.get("raw_content") or ""
    return f"{title}\n{content[:_EMBEDDING_TEXT_MAX_CHARS]}"


# ---------------------------------------------------------------------------
# SimHash state I/O
# ---------------------------------------------------------------------------

_SimhashEntry = dict[str, Any]  # {"threat_id": str, "simhash": int, "inserted_at": str}


def _load_simhash_state(path: Path) -> list[_SimhashEntry]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return [e for e in data.get("entries", []) if isinstance(e, dict)]
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("simhash_state_load_failed path=%s error=%s", path, exc)
        return []


def _save_simhash_state(path: Path, entries: list[_SimhashEntry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "entries": entries}, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# SemanticDeduplicator
# ---------------------------------------------------------------------------


class SemanticDeduplicator:
    """
    2-tier duplicate detector for confirmed threat articles.

    The class is stateful — call `register_confirmed(article)` for each
    Gemma-approved article to keep the SimHash and LanceDB state current.
    """

    def __init__(
        self,
        db_path: str | Path = LANCEDB_PATH,
        table_name: str = LANCEDB_TABLE_NAME,
        embedding_model: str = EMBEDDING_MODEL_NAME,
        cosine_threshold: float = COSINE_DISTANCE_THRESHOLD,
        simhash_hamming: int = SIMHASH_HAMMING_THRESHOLD,
        max_records: int = VECTOR_MAX_RECORDS,
        simhash_state_path: str | Path = SIMHASH_STATE_PATH,
    ) -> None:
        self._db_path = Path(db_path)
        self._table_name = table_name
        self._embedding_model_name = embedding_model
        self._cosine_threshold = cosine_threshold
        self._simhash_hamming = simhash_hamming
        self._max_records = max_records
        self._simhash_state_path = Path(simhash_state_path)

        # Lazy-loaded instances
        self._embedding_model: Any = None   # sentence_transformers.SentenceTransformer
        self._lancedb_table: Any = None     # lancedb.Table

        # Load SimHash history from disk
        self._simhash_entries: list[_SimhashEntry] = _load_simhash_state(
            self._simhash_state_path
        )
        logger.info(
            "semantic_dedup_init simhash_entries=%d cosine_threshold=%.2f hamming=%d",
            len(self._simhash_entries),
            self._cosine_threshold,
            self._simhash_hamming,
        )

    # ------------------------------------------------------------------
    # Lazy accessors
    # ------------------------------------------------------------------

    def _get_embedding_model(self) -> Any | None:
        """Load sentence-transformers model once; return None if unavailable."""
        if self._embedding_model is not None:
            return self._embedding_model
        try:
            from sentence_transformers import SentenceTransformer  # noqa: PLC0415

            logger.info(
                "embedding_model_load model=%s", self._embedding_model_name
            )
            self._embedding_model = SentenceTransformer(self._embedding_model_name)
            logger.info("embedding_model_ready model=%s", self._embedding_model_name)
        except ImportError:
            logger.warning(
                "sentence_transformers_unavailable — Tier 2 vector check disabled; "
                "install sentence-transformers to enable it"
            )
        except Exception as exc:
            logger.warning(
                "embedding_model_load_failed model=%s error=%s",
                self._embedding_model_name,
                exc,
            )
        return self._embedding_model

    def _get_lancedb_table(self) -> Any | None:
        """Open or create the LanceDB table; return None if unavailable."""
        if self._lancedb_table is not None:
            return self._lancedb_table
        try:
            import lancedb  # noqa: PLC0415
            import pyarrow as pa  # noqa: PLC0415

            self._db_path.mkdir(parents=True, exist_ok=True)
            db = lancedb.connect(str(self._db_path))

            if self._table_name not in db.table_names():
                schema = pa.schema(
                    [
                        pa.field("threat_id", pa.utf8()),
                        pa.field("title", pa.utf8()),
                        pa.field("inserted_at", pa.utf8()),
                        pa.field(
                            "vector",
                            pa.list_(pa.float32(), EMBEDDING_DIM),
                        ),
                    ]
                )
                self._lancedb_table = db.create_table(
                    self._table_name, schema=schema
                )
                logger.info(
                    "lancedb_table_created path=%s table=%s",
                    self._db_path,
                    self._table_name,
                )
            else:
                self._lancedb_table = db.open_table(self._table_name)
                logger.info(
                    "lancedb_table_opened path=%s table=%s rows=%d",
                    self._db_path,
                    self._table_name,
                    self._lancedb_table.count_rows(),
                )
        except ImportError:
            logger.warning(
                "lancedb_unavailable — Tier 2 vector check disabled; "
                "install lancedb to enable it"
            )
        except Exception as exc:
            logger.warning("lancedb_init_failed path=%s error=%s", self._db_path, exc)
        return self._lancedb_table

    # ------------------------------------------------------------------
    # Tier 1 — SimHash near-duplicate check
    # ------------------------------------------------------------------

    def _compute_simhash(self, text: str) -> int | None:
        """Return the 64-bit SimHash fingerprint, or None if simhash is unavailable."""
        try:
            from simhash import Simhash  # noqa: PLC0415

            return Simhash(text.split()).value
        except ImportError:
            logger.warning(
                "simhash_unavailable — Tier 1 SimHash check disabled; "
                "install simhash to enable it"
            )
            return None

    @staticmethod
    def _hamming_distance(a: int, b: int) -> int:
        diff = a ^ b
        return bin(diff).count("1")

    def check_tier1_simhash(
        self, article: dict[str, Any]
    ) -> tuple[bool, str | None]:
        """
        Return (is_duplicate, matched_threat_id).

        Skips silently if the simhash package is not installed.
        """
        text = _article_text(article)
        fingerprint = self._compute_simhash(text)
        if fingerprint is None:
            return False, None  # package unavailable — pass through

        for entry in self._simhash_entries:
            stored = entry.get("simhash")
            if not isinstance(stored, int):
                continue
            if self._hamming_distance(fingerprint, stored) <= self._simhash_hamming:
                matched_id = entry.get("threat_id", "unknown")
                logger.info(
                    "tier1_simhash_duplicate title=%r matched_id=%s hamming=%d",
                    article.get("title", ""),
                    matched_id,
                    self._hamming_distance(fingerprint, stored),
                )
                return True, matched_id

        return False, None

    # ------------------------------------------------------------------
    # Tier 2 — LanceDB vector semantic-similarity check
    # ------------------------------------------------------------------

    def _embed(self, text: str) -> list[float] | None:
        model = self._get_embedding_model()
        if model is None:
            return None
        try:
            return model.encode(text, show_progress_bar=False).tolist()
        except Exception as exc:
            logger.warning("embedding_failed error=%s", exc)
            return None

    def check_tier2_vector(
        self, article: dict[str, Any]
    ) -> tuple[bool, str | None]:
        """
        Return (is_duplicate, matched_threat_id).

        Skips silently if lancedb or sentence-transformers are unavailable,
        or if the table contains no historical entries yet.
        """
        table = self._get_lancedb_table()
        if table is None:
            return False, None

        try:
            row_count = table.count_rows()
        except Exception as exc:
            logger.warning("lancedb_count_failed error=%s", exc)
            return False, None

        if row_count == 0:
            return False, None  # empty DB on first run — nothing to compare against

        text = _article_text(article)
        vector = self._embed(text)
        if vector is None:
            return False, None

        try:
            results = (
                table.search(vector, vector_column_name="vector")
                .distance_type("cosine")
                .limit(1)
                .to_list()
            )
        except Exception as exc:
            logger.warning("lancedb_search_failed error=%s", exc)
            return False, None

        if not results:
            return False, None

        top = results[0]
        dist: float = top.get("_distance", 1.0)
        if dist <= self._cosine_threshold:
            matched_id: str = top.get("threat_id", "unknown")
            logger.info(
                "tier2_vector_duplicate title=%r matched_id=%s cosine_dist=%.4f",
                article.get("title", ""),
                matched_id,
                dist,
            )
            return True, matched_id

        return False, None

    # ------------------------------------------------------------------
    # Combined gate
    # ------------------------------------------------------------------

    def is_duplicate(
        self, article: dict[str, Any]
    ) -> tuple[bool, str, str | None]:
        """
        Run Tier 1 then (if needed) Tier 2.

        Returns (is_duplicate, tier_label, matched_threat_id).
        tier_label is "simhash", "vector", or "" (unique).
        """
        dup, match_id = self.check_tier1_simhash(article)
        if dup:
            return True, "simhash", match_id

        dup, match_id = self.check_tier2_vector(article)
        if dup:
            return True, "vector", match_id

        return False, "", None

    def filter_articles(
        self, articles: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int, int]:
        """
        Filter a batch through Tier 1 + Tier 2.

        Returns (passed_articles, tier1_dropped_count, tier2_dropped_count).
        """
        passed: list[dict[str, Any]] = []
        tier1_dropped = 0
        tier2_dropped = 0

        for article in articles:
            is_dup, tier, match_id = self.is_duplicate(article)
            if is_dup:
                if tier == "simhash":
                    tier1_dropped += 1
                else:
                    tier2_dropped += 1
            else:
                passed.append(article)

        logger.info(
            "semantic_dedup_filter passed=%d tier1_dropped=%d tier2_dropped=%d",
            len(passed),
            tier1_dropped,
            tier2_dropped,
        )
        return passed, tier1_dropped, tier2_dropped

    # ------------------------------------------------------------------
    # Registration — call after Gemma confirmation
    # ------------------------------------------------------------------

    def register_confirmed(self, article: dict[str, Any]) -> None:
        """
        Atomically register a Gemma-confirmed article into both tiers.

        Should be called once per article that will be written to the
        filtered_threat_queue.json.  This ensures future runs can detect
        semantic duplicates of topics already in the pipeline.
        """
        tid = _threat_id(article)
        now = datetime.now(timezone.utc).isoformat()

        self._register_simhash(article, tid, now)
        self._insert_vector(article, tid, now)

    def register_confirmed_batch(self, articles: list[dict[str, Any]]) -> None:
        """Register a batch of confirmed articles; persists SimHash state once at end."""
        if not articles:
            return

        now = datetime.now(timezone.utc).isoformat()
        for article in articles:
            tid = _threat_id(article)
            self._register_simhash_entry(article, tid, now, persist=False)
            self._insert_vector(article, tid, now)

        # Single disk write for the whole batch
        self._prune_and_save_simhash_state()
        logger.info(
            "semantic_dedup_registered batch_size=%d total_simhash_entries=%d",
            len(articles),
            len(self._simhash_entries),
        )

    # ------------------------------------------------------------------
    # Internal registration helpers
    # ------------------------------------------------------------------

    def _register_simhash(
        self, article: dict[str, Any], threat_id: str, now: str
    ) -> None:
        self._register_simhash_entry(article, threat_id, now, persist=True)

    def _register_simhash_entry(
        self,
        article: dict[str, Any],
        threat_id: str,
        now: str,
        *,
        persist: bool,
    ) -> None:
        text = _article_text(article)
        fingerprint = self._compute_simhash(text)
        if fingerprint is None:
            return  # simhash package unavailable

        # Skip if this threat_id already exists
        existing_ids = {e["threat_id"] for e in self._simhash_entries}
        if threat_id in existing_ids:
            return

        self._simhash_entries.append(
            {
                "threat_id": threat_id,
                "simhash": fingerprint,
                "inserted_at": now,
                "title": article.get("title", "")[:120],
            }
        )
        if persist:
            self._prune_and_save_simhash_state()

    def _prune_and_save_simhash_state(self) -> None:
        """Enforce rolling cap then atomically persist to disk."""
        if len(self._simhash_entries) > self._max_records:
            # Sort by insertion time; discard oldest excess entries
            self._simhash_entries.sort(key=lambda e: e.get("inserted_at", ""))
            pruned_count = len(self._simhash_entries) - self._max_records
            self._simhash_entries = self._simhash_entries[pruned_count:]
            logger.info(
                "simhash_state_pruned removed=%d remaining=%d",
                pruned_count,
                len(self._simhash_entries),
            )
        _save_simhash_state(self._simhash_state_path, self._simhash_entries)

    def _insert_vector(
        self, article: dict[str, Any], threat_id: str, now: str
    ) -> None:
        table = self._get_lancedb_table()
        if table is None:
            return

        text = _article_text(article)
        vector = self._embed(text)
        if vector is None:
            return

        try:
            record = {
                "threat_id": threat_id,
                "title": article.get("title", "")[:120],
                "inserted_at": now,
                "vector": vector,
            }
            table.add([record])
            logger.debug(
                "lancedb_insert threat_id=%s title=%r",
                threat_id,
                article.get("title", ""),
            )
            self._prune_lancedb_table(table)
        except Exception as exc:
            logger.warning(
                "lancedb_insert_failed threat_id=%s error=%s", threat_id, exc
            )

    def _prune_lancedb_table(self, table: Any) -> None:
        """Evict oldest rows when the table exceeds max_records."""
        try:
            count = table.count_rows()
            if count <= self._max_records:
                return

            excess = count - self._max_records
            df = table.to_pandas()
            df_sorted = df.sort_values("inserted_at")
            oldest_ids = df_sorted.head(excess)["threat_id"].tolist()
            for tid in oldest_ids:
                # Escape single quotes in threat_id (hex-only, but be safe)
                safe_tid = tid.replace("'", "''")
                table.delete(f"threat_id = '{safe_tid}'")

            logger.info(
                "lancedb_pruned removed=%d remaining=%d",
                excess,
                self._max_records,
            )
        except Exception as exc:
            logger.warning("lancedb_prune_failed error=%s", exc)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def simhash_entry_count(self) -> int:
        return len(self._simhash_entries)

    def lancedb_row_count(self) -> int:
        table = self._get_lancedb_table()
        if table is None:
            return 0
        try:
            return table.count_rows()
        except Exception:
            return 0
