#!/usr/bin/env python3
"""
Threat Intelligence Stream Console — read-only Streamlit dashboard.

Reads exclusively from data/filtered_threat_queue.json.
Does not invoke ingestion, filtering, or local SLM inference.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

APP_TITLE = "Threat Intelligence Stream Console"
DEFAULT_DATA_PATH = Path("data/filtered_threat_queue.json")
MAX_ACTIVE_THREATS = 50
REFRESH_INTERVAL_SECONDS = 60
SUMMARY_MAX_CHARS = 420

PLATFORM_KEYWORDS: tuple[str, ...] = (
    "AWS",
    "GCP",
    "Azure",
    "GitHub",
    "Okta",
    "OAuth",
    "Salesforce",
    "IdP",
    "Active Directory",
    "SAML",
    "OIDC",
    "Microsoft Entra",
)

_PLATFORM_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        kw,
        re.compile(re.escape(kw), re.IGNORECASE)
        if (" " in kw or len(kw) > 4)
        else re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE),
    )
    for kw in sorted(PLATFORM_KEYWORDS, key=len, reverse=True)
]


# ---------------------------------------------------------------------------
# Data layer (JSON read-only)
# ---------------------------------------------------------------------------


@st.cache_data(ttl=REFRESH_INTERVAL_SECONDS, show_spinner=False)
def load_filtered_threats(data_path: str) -> dict[str, Any]:
    """
    Load and normalize the filtered threat queue from disk.

    Returns a dict with keys: articles, filtered_at, stats, error, warning.
    Never raises — callers inspect error/warning for UI messaging.
    """
    path = Path(data_path)
    result: dict[str, Any] = {
        "articles": [],
        "filtered_at": None,
        "stats": {},
        "error": None,
        "warning": None,
    }

    if not path.is_file():
        result["error"] = f"Queue file not found: `{path}`"
        return result

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        result["error"] = f"Unable to read queue file: {exc}"
        return result

    if not raw_text.strip():
        result["warning"] = f"Queue file is empty: `{path}`"
        return result

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        result["error"] = f"Queue file contains invalid JSON: {exc}"
        return result

    if not isinstance(payload, dict):
        result["error"] = "Queue file root must be a JSON object."
        return result

    articles = payload.get("articles")
    if articles is None:
        result["warning"] = "Queue file has no `articles` array — nothing to display."
        return result
    if not isinstance(articles, list):
        result["error"] = "Queue `articles` field must be a JSON array."
        return result

    normalized = [a for a in articles if isinstance(a, dict)]
    if not normalized and articles:
        result["warning"] = "Queue articles could not be parsed as threat objects."
        return result

    result["articles"] = normalized[:MAX_ACTIVE_THREATS]
    result["filtered_at"] = payload.get("filtered_at")
    result["stats"] = payload.get("stats") if isinstance(payload.get("stats"), dict) else {}

    if len(normalized) > MAX_ACTIVE_THREATS:
        result["warning"] = (
            f"Display capped at {MAX_ACTIVE_THREATS} threats "
            f"({len(normalized)} present in file)."
        )

    return result


def _parse_timestamp(article: dict[str, Any]) -> datetime:
    for field in ("timestamp", "published_at", "fetched_at"):
        raw = article.get(field)
        if not raw:
            continue
        try:
            text = raw.replace("Z", "+00:00") if isinstance(raw, str) else str(raw)
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except (ValueError, TypeError):
            continue
    return datetime.min.replace(tzinfo=timezone.utc)


def sort_threats_newest_first(articles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(articles, key=_parse_timestamp, reverse=True)


# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------


def classify_platforms(article: dict[str, Any]) -> list[str]:
    text = f"{article.get('title', '')}\n{article.get('content', '')}"
    matched: list[str] = []
    seen: set[str] = set()
    for label, pattern in _PLATFORM_PATTERNS:
        if pattern.search(text) and label not in seen:
            matched.append(label)
            seen.add(label)
    return matched or ["General / Unclassified"]


def build_extraction_summary(article: dict[str, Any]) -> str:
    verdict = article.get("gemma_verdict")
    if isinstance(verdict, dict):
        reasoning = (verdict.get("reasoning_summary") or verdict.get("justification") or "").strip()
        skip_marker = "Gemma skipped (--skip-gemma)"
        if reasoning and reasoning != skip_marker:
            domain = verdict.get("primary_domain")
            platform = verdict.get("primary_platform")
            score = verdict.get("confidence_score")
            prefix_parts = []
            if domain:
                prefix_parts.append(str(domain))
            if platform and platform != "Unknown":
                prefix_parts.append(str(platform))
            if score is not None:
                prefix_parts.append(f"score {score}/10")
            if prefix_parts:
                return f"**{' · '.join(prefix_parts)}** — {reasoning}"
            return reasoning

    content = (article.get("content") or article.get("raw_content") or "").strip()
    if not content:
        return "_No extraction summary available._"
    if len(content) <= SUMMARY_MAX_CHARS:
        return content
    return content[: SUMMARY_MAX_CHARS - 1].rstrip() + "…"


def format_timestamp(raw: Any) -> str:
    if not raw:
        return "—"
    try:
        text = raw.replace("Z", "+00:00") if isinstance(raw, str) else str(raw)
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return str(raw)


def platform_badge_markdown(platforms: list[str]) -> str:
    return " · ".join(f"`{p}`" for p in platforms)


# ---------------------------------------------------------------------------
# Auto-refresh
# ---------------------------------------------------------------------------


def configure_auto_refresh() -> None:
    """Refresh the dashboard every 60 seconds without blocking the main thread."""
    try:
        from streamlit_autorefresh import st_autorefresh

        st_autorefresh(
            interval=REFRESH_INTERVAL_SECONDS * 1000,
            limit=None,
            key="threat_intel_stream_autorefresh",
        )
        return
    except ImportError:
        pass

    if hasattr(st, "fragment"):
        # Streamlit >= 1.33 native periodic fragment (no extra dependency).
        @st.fragment(run_every=f"{REFRESH_INTERVAL_SECONDS}s")
        def _tick() -> None:
            st.session_state["_refresh_tick"] = datetime.now(timezone.utc).isoformat()

        _tick()
    else:
        st.caption(
            f"Auto-refresh every {REFRESH_INTERVAL_SECONDS}s requires "
            "`pip install streamlit-autorefresh` or Streamlit ≥ 1.33."
        )


# ---------------------------------------------------------------------------
# UI sections
# ---------------------------------------------------------------------------


def inject_layout_css() -> None:
    st.markdown(
        """
        <style>
          div[data-testid="stMetric"] {
            background: #0e1117;
            border: 1px solid #262730;
            border-radius: 8px;
            padding: 12px 16px;
          }
          .threat-expander-label { font-weight: 600; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_status_banner(queue: dict[str, Any]) -> None:
    if queue.get("error"):
        st.error(queue["error"])
    elif queue.get("warning"):
        st.warning(queue["warning"])
    if not queue.get("error") and not queue["articles"]:
        st.info("No active threats in the filtered queue. Run the filter pipeline to populate data.")


def render_metrics(articles: list[dict[str, Any]], queue: dict[str, Any]) -> None:
    active_count = min(len(articles), MAX_ACTIVE_THREATS)
    filtered_at = queue.get("filtered_at")
    stats = queue.get("stats") or {}
    gemma_confirmed = stats.get("confirmed_gemma_this_run") or stats.get("confirmed_gemma")

    col_primary, col_meta, col_refresh = st.columns([2, 2, 2])

    with col_primary:
        st.metric(
            label="Active Pending Threats",
            value=active_count,
            delta=f"max {MAX_ACTIVE_THREATS}",
            delta_color="off",
        )

    with col_meta:
        st.metric(
            label="Last Filter Run",
            value=format_timestamp(filtered_at) if filtered_at else "—",
        )

    with col_refresh:
        st.metric(
            label="Auto-Refresh",
            value=f"{REFRESH_INTERVAL_SECONDS}s",
            help="Dashboard reloads queue data from disk on this interval.",
        )

    if gemma_confirmed is not None:
        st.caption(
            f"Pipeline stats — Gemma confirmed (last run): **{gemma_confirmed}** · "
            f"Source: `{DEFAULT_DATA_PATH}`"
        )


def render_threat_matrix(articles: list[dict[str, Any]]) -> None:
    st.subheader("Threat Matrix")
    st.caption("Expand a row to inspect platform tags, Gemma rationale, and content excerpt.")

    if not articles:
        return

    for index, article in enumerate(articles, start=1):
        title = (article.get("title") or "Untitled threat").strip()
        source = (article.get("source") or "Unknown source").strip()
        platforms = classify_platforms(article)
        platform_line = platform_badge_markdown(platforms)
        header = f"{index}. {title} — {platforms[0]}"

        with st.expander(header, expanded=False):
            st.markdown(f"**Title:** {title}")
            st.markdown(f"**Source feed:** {source}")
            st.markdown(f"**Platform classification:** {platform_line}")
            st.markdown(f"**Observed:** {format_timestamp(article.get('timestamp'))}")

            url = article.get("url")
            if isinstance(url, str) and url.strip():
                st.markdown(f"**URL:** [{url}]({url})")

            st.markdown("---")
            st.markdown("**Extraction summary**")
            st.markdown(build_extraction_summary(article))

            verdict = article.get("gemma_verdict")
            if isinstance(verdict, dict):
                is_relevant = verdict.get("is_relevant", verdict.get("relevant"))
                if is_relevant is not None:
                    relevant = "Yes" if is_relevant else "No"
                    st.markdown(f"**Dynamic filter relevant:** {relevant}")
                score = verdict.get("confidence_score")
                if score is not None:
                    st.markdown(f"**Confidence score:** {score}/10")
                domain = verdict.get("primary_domain")
                if domain:
                    st.markdown(f"**Primary domain:** {domain}")
                platform = verdict.get("primary_platform")
                if platform:
                    st.markdown(f"**Primary platform:** {platform}")


def render_sidebar(data_path: Path) -> Path:
    st.sidebar.header("Console")
    st.sidebar.markdown(
        "Read-only view of the filtered threat queue. "
        "No models are loaded in this process."
    )
    custom_path = st.sidebar.text_input(
        "Queue file path",
        value=str(data_path),
        help="Override path for local testing only.",
    )
    if st.sidebar.button("Refresh now", use_container_width=True):
        load_filtered_threats.clear()
        st.rerun()

    st.sidebar.divider()
    st.sidebar.caption(
        f"Data source: `{custom_path}`\n\n"
        f"Cap: {MAX_ACTIVE_THREATS} threats · Refresh: {REFRESH_INTERVAL_SECONDS}s"
    )
    return Path(custom_path)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    st.set_page_config(
        page_title=APP_TITLE,
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    inject_layout_css()
    configure_auto_refresh()

    st.title(APP_TITLE)
    st.markdown(
        "Live console for Gemma-verified threats · "
        "**read-only** · no on-device inference"
    )

    data_path = render_sidebar(DEFAULT_DATA_PATH)
    queue = load_filtered_threats(str(data_path.resolve()))
    articles = sort_threats_newest_first(queue["articles"])

    render_status_banner(queue)
    render_metrics(articles, queue)
    st.divider()
    render_threat_matrix(articles)


if __name__ == "__main__":
    main()
