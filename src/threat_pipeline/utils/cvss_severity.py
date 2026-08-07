"""
CVSS v4.0 / v3.x severity parsing utilities.

Public API
----------
apply_official_severity(rule, threat_advisory)
    Override a rule's defaultSeverity with the qualitative text derived from an
    official CVSS vector found in the threat advisory.  Falls back to the AI's
    estimated severity (capitalised and validated) when no vector is present.

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

import logging
import re
from typing import Any

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
    from cvss import CVSS3, CVSS4  # noqa: PLC0415 — lazy; avoid startup cost
    from cvss.exceptions import CVSSError  # noqa: PLC0415

    vector = vector.strip()
    upper = vector.upper()

    try:
        if upper.startswith("CVSS:4.0/"):
            sev: str = CVSS4(vector).severity
        elif upper.startswith("CVSS:3."):
            sev = CVSS3(vector).severities()[0]
        else:
            # Unknown prefix — try both parsers, most-specific first
            try:
                sev = CVSS4(vector).severity
            except CVSSError:
                sev = CVSS3(vector).severities()[0]
    except CVSSError as exc:
        logger.warning("cvss_parse_failed vector=%r error=%s", vector, exc)
        return None
    except Exception as exc:  # defensive: unknown library errors
        logger.error("cvss_unexpected_error vector=%r error=%s", vector, exc)
        return None

    # Ensure the library returned a value we recognise
    if sev not in VALID_SEVERITIES:
        logger.warning(
            "cvss_unknown_severity vector=%r library_returned=%r", vector, sev
        )
        return None

    return sev


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
# Public API
# ---------------------------------------------------------------------------


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
    * If no CVSS vector is present, retain the AI's severity after normalising
      it to a valid capitalised member of VALID_SEVERITIES.
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
    vector string is also stored under the key ``cvss_vector_source`` so that
    downstream steps (triage dashboard, audit log) can surface it.
    """
    rule = dict(rule)
    current_severity = rule.get("defaultSeverity", "")

    vector = _extract_cvss_vector(threat_advisory)

    if vector:
        official = _parse_severity_from_vector(vector)
        if official:
            if official != current_severity:
                logger.info(
                    "cvss_override rule=%r ai_severity=%r cvss_vector=%r official=%r",
                    rule.get("name", ""),
                    current_severity,
                    vector,
                    official,
                )
            rule["defaultSeverity"] = official
            rule["cvss_vector_source"] = vector
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
