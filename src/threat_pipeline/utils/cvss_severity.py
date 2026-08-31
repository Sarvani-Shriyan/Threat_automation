"""
CVSS v4.0 / v3.x severity parsing utilities.

Public API
----------
apply_official_severity(rule, threat_advisory)
    Override a rule's defaultSeverity with the qualitative text derived from an
    official CVSS vector found in the threat advisory.  Falls back to the AI's
    estimated severity (capitalised and validated) when no vector is present.
    Also sets ``cvss_score`` (float) and ``severity_source`` ("cvss"|"ai") on
    the returned rule dict.

enrich_threat_with_nvd_cvss(threat)
    If the threat dict has ``cve_ids`` and no ``cvss_vector`` yet, fetches the
    CVSS vector from the NVD 2.0 API for the first matching CVE and stores it
    as ``threat["cvss_vector"]``.  Cached per CVE ID; never raises.

Severity enum (VALID_SEVERITIES)
    {"Low", "Medium", "High", "Critical"} — pure word strings, never numeric.

Score → text mapping (CVSS v3.x qualitative ranges)
    0.1 – 3.9  → "Low"
    4.0 – 6.9  → "Medium"
    7.0 – 8.9  → "High"
    9.0 – 10.0 → "Critical"
    (CVSS v4.0 uses the same qualitative labels via CVSS4.severity.)
"""

from __future__ import annotations

import functools
import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_SEVERITIES: frozenset[str] = frozenset({"Low", "Medium", "High", "Critical"})

_SEVERITY_NORMALISE: dict[str, str] = {s.lower(): s for s in VALID_SEVERITIES}

# Common field names that may carry a raw CVSS vector string.
_KNOWN_VECTOR_FIELDS: tuple[str, ...] = (
    "cvss_vector",
    "cvss_v4_vector",
    "cvss_v3_vector",
    "cvss_v2_vector",
    "vector_string",
    "cvssV3",
    "cvssV4",
    "cvss",
    "cve_cvss_vector",
    "baseMetricV3",
    "cvssData",
)

# Matches a CVSS vector prefix, e.g. "CVSS:4.0/…" or "CVSS:3.1/…"
_VECTOR_RE: re.Pattern[str] = re.compile(
    r"CVSS:[0-9]+\.[0-9]+/\S+", re.IGNORECASE
)

# Reject non-word characters in a defaultSeverity value (digits, punctuation, etc.)
_WORD_ONLY_RE: re.Pattern[str] = re.compile(r"^[A-Za-z]+$")

# NVD 2.0 base URL — documented response shape only.
_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_cvss_vector(threat_advisory: dict[str, Any]) -> str | None:
    """
    Search the threat advisory dict for a CVSS vector string.

    Strategy
    --------
    1. Check every field listed in _KNOWN_VECTOR_FIELDS at the top level.
    2. Recurse into nested dicts / lists up to depth 4.
    3. Any string value that matches _VECTOR_RE is accepted.

    Returns the first matching vector string, or None.
    """

    def _search(obj: Any, depth: int) -> str | None:
        if depth > 4:
            return None

        if isinstance(obj, str):
            m = _VECTOR_RE.search(obj.strip())
            return m.group() if m else None

        if isinstance(obj, dict):
            # Prioritise known field names
            for field in _KNOWN_VECTOR_FIELDS:
                val = obj.get(field)
                if isinstance(val, str):
                    m = _VECTOR_RE.search(val.strip())
                    if m:
                        return m.group()
            # Then recurse into all values
            for val in obj.values():
                result = _search(val, depth + 1)
                if result:
                    return result

        elif isinstance(obj, (list, tuple)):
            for item in obj:
                result = _search(item, depth + 1)
                if result:
                    return result

        return None

    return _search(threat_advisory, 0)


def _parse_cvss_result(vector: str) -> tuple[str | None, float | None]:
    """
    Parse a CVSS vector string and return ``(qualitative_severity, base_score)``.

    The ``cvss`` package is imported lazily; an ``ImportError`` degrades
    gracefully to ``(None, None)`` instead of crashing the pipeline.

    Returns
    -------
    (severity, score) where severity is one of VALID_SEVERITIES and score is
    a float (e.g. 9.8), or (None, None) on any failure.
    """
    try:
        from cvss import CVSS3, CVSS4  # noqa: PLC0415 — lazy; avoid startup cost
        from cvss.exceptions import CVSSError  # noqa: PLC0415
    except ImportError:
        logger.warning(
            "cvss_pkg_missing — cannot parse CVSS vector; falling back to AI severity"
        )
        return None, None

    vector = vector.strip()
    upper = vector.upper()

    try:
        if upper.startswith("CVSS:4.0/"):
            obj = CVSS4(vector)
            sev: str = obj.severity
            score = float(obj.base_score)
        elif upper.startswith("CVSS:3."):
            obj = CVSS3(vector)
            sev = obj.severities()[0]
            score = float(obj.base_score)
        else:
            # Unknown prefix — try both parsers, most-specific first
            try:
                obj = CVSS4(vector)
                sev = obj.severity
                score = float(obj.base_score)
            except CVSSError:
                obj = CVSS3(vector)
                sev = obj.severities()[0]
                score = float(obj.base_score)
    except CVSSError as exc:
        logger.warning("cvss_parse_failed vector=%r error=%s", vector, exc)
        return None, None
    except Exception as exc:  # defensive: unknown library errors
        logger.error("cvss_unexpected_error vector=%r error=%s", vector, exc)
        return None, None

    # Ensure the library returned a value we recognise
    if sev not in VALID_SEVERITIES:
        logger.warning(
            "cvss_unknown_severity vector=%r library_returned=%r", vector, sev
        )
        return None, None

    return sev, score


def _parse_severity_from_vector(vector: str) -> str | None:
    """
    Parse a CVSS vector string and return the qualitative severity label.

    Routing
    -------
    * Prefix ``CVSS:4.0/`` → CVSS4 parser  → CVSS4.severity (str)
    * Prefix ``CVSS:3.``   → CVSS3 parser  → CVSS3.severities()[0] (str)
    * Fallback             → try CVSS3 then CVSS4

    Returns one of {"Low", "Medium", "High", "Critical"}, or None on failure.
    """
    return _parse_cvss_result(vector)[0]


def _normalise_fallback_severity(ai_severity: Any) -> str:
    """
    Capitalise and validate the AI's estimated severity string.

    Accepts case-insensitive variants ("low", "HIGH", "critical") and maps them
    to the canonical form.  Returns "Medium" as a safe default for anything
    unrecognised, and logs a warning.
    """
    if not isinstance(ai_severity, str):
        logger.warning(
            "cvss_fallback_non_string severity=%r — defaulting to Medium", ai_severity
        )
        return "Medium"

    normalised = _SEVERITY_NORMALISE.get(ai_severity.strip().lower())
    if normalised:
        return normalised

    logger.warning(
        "cvss_fallback_invalid_severity severity=%r — defaulting to Medium", ai_severity
    )
    return "Medium"


# ---------------------------------------------------------------------------
# NVD API lookup (Task 2)
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=256)
def _fetch_nvd_cvss_vector(cve_id: str) -> str | None:
    """
    Fetch the highest-version CVSS vector string for *cve_id* from the NVD 2.0 API.

    Cached per CVE ID (LRU, process-scoped) so each CVE is queried at most once.
    On any network or parsing error, logs a warning and returns None — never raises.

    NVD 2.0 response shape used:
        vulnerabilities[0].cve.metrics.cvssMetricV4{0,1}[0].cvssData.vectorString
        vulnerabilities[0].cve.metrics.cvssMetricV3{1,0}[0].cvssData.vectorString
    """
    url = f"{_NVD_API_URL}?cveId={cve_id}"
    try:
        resp = httpx.get(url, timeout=10.0, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            logger.debug("nvd_no_data cve_id=%r", cve_id)
            return None
        metrics = vulns[0].get("cve", {}).get("metrics", {})
        # Prefer v4.0 → v3.1 → v3.0 (highest fidelity first)
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                vector = entries[0].get("cvssData", {}).get("vectorString")
                if vector:
                    logger.info(
                        "nvd_found_vector cve_id=%r metric=%r vector=%r",
                        cve_id,
                        key,
                        vector,
                    )
                    return vector
        return None
    except Exception as exc:
        logger.warning("nvd_lookup_failed cve_id=%r error=%s", cve_id, exc)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def enrich_threat_with_nvd_cvss(threat: dict[str, Any]) -> None:
    """
    Fetch a CVSS vector from the NVD API and attach it to *threat* in-place.

    Does nothing when:
    - ``threat`` already has a ``cvss_vector`` value, or
    - ``threat["cve_ids"]`` is absent or empty.

    On any error (network, parsing, etc.) logs and returns silently — never raises.
    The lookup is cached per CVE ID so it is called at most once per CVE per process.
    """
    if threat.get("cvss_vector"):
        return
    cve_ids = threat.get("cve_ids") or []
    for cve_id in cve_ids:
        vector = _fetch_nvd_cvss_vector(str(cve_id).upper())
        if vector:
            threat["cvss_vector"] = vector
            logger.info(
                "nvd_cvss_enriched threat=%r cve_id=%r vector=%r",
                threat.get("title", ""),
                cve_id,
                vector,
            )
            return


def apply_official_severity(
    rule: dict[str, Any],
    threat_advisory: dict[str, Any],
) -> dict[str, Any]:
    """
    Override *rule['defaultSeverity']* with the qualitative text label derived
    from an official CVSS vector found in *threat_advisory*.

    Behaviour
    ---------
    * If a CVSS vector is found in the threat advisory, parse it and replace
      the AI's estimated severity with the official character-word label.
      Sets ``cvss_score`` (float) and ``severity_source = "cvss"`` on the rule.
    * If no CVSS vector is present, retain the AI's severity after normalising
      it to a valid capitalised member of VALID_SEVERITIES.
      ``cvss_score`` is absent / None; ``severity_source`` is not overridden.
    * ``defaultSeverity`` is always a pure word string ("Low", "Medium", "High",
      or "Critical") — never a numeric score or decimal.

    Parameters
    ----------
    rule:
        A detection-rule dict with at least a ``defaultSeverity`` key.
    threat_advisory:
        The raw threat payload dict (may contain ``cvss_vector``,
        ``vector_string``, nested CVSS data, etc.).

    Returns
    -------
    A shallow copy of *rule* with ``defaultSeverity`` set to the authoritative
    or normalised severity string.  When an official CVSS vector is used, the
    vector string is also stored under ``cvss_vector_source``, the numeric base
    score under ``cvss_score``, and ``severity_source`` is set to ``"cvss"``.
    """
    rule = dict(rule)
    current_severity = rule.get("defaultSeverity", "")

    vector = _extract_cvss_vector(threat_advisory)

    if vector:
        official, cvss_score = _parse_cvss_result(vector)
        if official:
            if official != current_severity:
                logger.info(
                    "cvss_override rule=%r ai_severity=%r cvss_vector=%r official=%r score=%s",
                    rule.get("name", ""),
                    current_severity,
                    vector,
                    official,
                    cvss_score,
                )
            rule["defaultSeverity"] = official
            rule["cvss_vector_source"] = vector
            rule["cvss_score"] = cvss_score
            rule["severity_source"] = "cvss"
            return rule
        # Vector found but unparseable — fall through to AI fallback below
        logger.warning(
            "cvss_vector_unparseable rule=%r vector=%r — keeping AI severity",
            rule.get("name", ""),
            vector,
        )

    # No usable CVSS vector — normalise the AI's estimated severity
    rule["defaultSeverity"] = _normalise_fallback_severity(current_severity)
    return rule
