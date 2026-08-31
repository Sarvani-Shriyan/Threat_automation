#!/usr/bin/env python3
"""
Security Engineer Triage Dashboard  —  app_triage.py

3-column decision panel for reviewing exactly 3 validated detection rule variants
per threat. One rule wins; the other two are logged to the feedback queue.

Variant columns map to the threat-centric multi-variant strategy:
  Col 1 — 🎯 Primary High-Fidelity Trigger
  Col 2 — 🔗 Behavioral & Chained Action
  Col 3 — 🛡️ Defense-in-Depth / Secondary Vector

Data sources (read/written from shared ./data volume):
  IN   data/validated_rules.json        Step 4 output — entries with validated variants
  OUT  data/prod_detection_rules.json   Single approved rule per threat
  OUT  data/failed_feedback_queue.json  Rejected variants with justification strings

NOTE: The spec references data/threat_queue.json as the rule source, but that file
      holds raw RSS articles with no rule variants. The correct pipeline output is
      data/validated_rules.json (Step 4). The DATA_SOURCE constant below is the
      single place to change if that ever differs.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st
import streamlit.components.v1 as components

from llm.observability import log_approval_score, log_rejection_score

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATA_SOURCE = Path("data/validated_rules.json")
PROD_RULES = Path("data/prod_detection_rules.json")
FEEDBACK_QUEUE = Path("data/failed_feedback_queue.json")

_IMPLICIT_REJECT_REASON = (
    "Implicitly rejected: Another variant strategy was selected for production by the engineer."
)

# Threat-centric variant labels — aligned with the Rule Engine's 3-variant prompt order.
_STRATEGY_LABELS: list[tuple[str, str]] = [
    ("🎯", "Primary High-Fidelity Trigger"),
    ("🔗", "Behavioral & Chained Action"),
    ("🛡️", "Defense-in-Depth / Secondary Vector"),
]

# ---------------------------------------------------------------------------
# Button colour injection
# ---------------------------------------------------------------------------
# st.button has no colour parameter.  We inject a tiny JavaScript snippet via
# st.components.v1.html (which runs inside a srcdoc iframe that inherits the
# parent document's origin) so window.parent.document is accessible.
# A MutationObserver re-applies colours after every Streamlit re-render.

_COLOUR_JS = """
<script>
(function () {
    function paint() {
        try {
            var doc = window.parent.document;
            doc.querySelectorAll("button").forEach(function (btn) {
                var txt = (btn.innerText || btn.textContent || "").trim();
                if (txt.indexOf("Approve") !== -1 || txt.indexOf("Move to Prod") !== -1) {
                    btn.style.setProperty("background-color", "#27ae60", "important");
                    btn.style.setProperty("border-color",     "#1e8449", "important");
                    btn.style.setProperty("color",            "white",   "important");
                    btn.style.setProperty("font-weight",      "600",     "important");
                } else if (
                    txt.indexOf("Reject") !== -1 ||
                    txt.indexOf("Mark Invalid") !== -1 ||
                    txt.indexOf("Submit Rejection") !== -1
                ) {
                    btn.style.setProperty("background-color", "#e74c3c", "important");
                    btn.style.setProperty("border-color",     "#c0392b", "important");
                    btn.style.setProperty("color",            "white",   "important");
                    btn.style.setProperty("font-weight",      "600",     "important");
                }
            });
        } catch (e) { /* cross-origin guard — silent */ }
    }
    paint();
    try {
        new MutationObserver(function () { paint(); })
            .observe(window.parent.document.body, { childList: true, subtree: true });
    } catch (e) {}
})();
</script>
"""


def _inject_button_colours() -> None:
    """Render a zero-height component that colours approve/reject buttons."""
    components.html(_COLOUR_JS, height=0, scrolling=False)


def _green_button(label: str, key: str, **kwargs: Any) -> bool:
    """Thin wrapper — colouring is handled by the JS observer."""
    return st.button(label, key=key, **kwargs)


def _red_button(label: str, key: str, **kwargs: Any) -> bool:
    """Thin wrapper — colouring is handled by the JS observer."""
    return st.button(label, key=key, **kwargs)


# ---------------------------------------------------------------------------
# Badge styling
# ---------------------------------------------------------------------------

_SEVERITY_BG: dict[str, str] = {
    "Critical": "#c0392b",
    "High":     "#e67e22",
    "Medium":   "#f39c12",
    "Low":      "#27ae60",
    "None":     "#708090",
}
_SEVERITY_FG: dict[str, str] = {
    "Critical": "#fff",
    "High":     "#fff",
    "Medium":   "#000",
    "Low":      "#fff",
    "None":     "#fff",
}
_KENT_BG: dict[str, str] = {
    "Almost Certain":  "#922b21",
    "Highly Likely":   "#c0392b",
    "Probable":        "#d35400",
    "Likely":          "#d68910",
    "Possible":        "#117a65",
    "Unlikely":        "#1a5276",
    "Remote":          "#6c3483",
    "Highly Unlikely": "#717d7e",
    "Unknown":         "#aab7b8",
}


def _badge(text: str, bg: str, fg: str = "#fff", size: str = "0.76rem") -> str:
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 8px;'
        f'border-radius:4px;font-size:{size};font-weight:700;'
        f'white-space:nowrap;">{text}</span>'
    )


def _severity_badge(s: str) -> str:
    return _badge(s, _SEVERITY_BG.get(s, "#555"), _SEVERITY_FG.get(s, "#fff"))


def _kent_badge(tag: str) -> str:
    return _badge(f"🔍 {tag}", _KENT_BG.get(tag, "#aab7b8"))


def _platform_badge(p: str) -> str:
    return _badge(p, "#1f618d")


_DOMAIN_BG: dict[str, str] = {
    "Identity":  "#6c3483",
    "Cloud":     "#1a5276",
    "SaaS":      "#117a65",
    "NHI":       "#7d6608",
    "AI_Agent":  "#1b4f72",
    "Unrelated": "#555",
}


def _domain_badge(d: str) -> str:
    """Return a styled badge for primary_domain values including NHI and AI_Agent."""
    label_map = {"AI_Agent": "AI Agent", "NHI": "NHI"}
    label = label_map.get(d, d)
    return _badge(label, _DOMAIN_BG.get(d, "#555"))


# ---------------------------------------------------------------------------
# Safe file I/O
# ---------------------------------------------------------------------------


def _load_json(path: Path, default: Any) -> Any:
    """Load JSON; return default on missing or corrupt file."""
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def _save_json(path: Path, data: Any) -> None:
    """Atomic write: tmp file → os.replace → final path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def _append_to_file(path: Path, new_items: list[dict[str, Any]]) -> None:
    """Load existing array → extend → write back."""
    existing: list[dict[str, Any]] = _load_json(path, [])
    if not isinstance(existing, list):
        existing = []
    existing.extend(new_items)
    _save_json(path, existing)


def _remove_threat_from_queue(threat_id: str) -> None:
    """Strip a resolved threat entry from validated_rules.json."""
    payload = _load_json(DATA_SOURCE, {})
    payload["entries"] = [
        e for e in payload.get("entries", [])
        if e.get("threat_id") != threat_id
    ]
    payload["threat_count"] = len(payload["entries"])
    _save_json(DATA_SOURCE, payload)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Data loader
# ---------------------------------------------------------------------------


def load_triage_entries() -> list[dict[str, Any]]:
    """
    Return entries from validated_rules.json that have ≥1 passing variant.
    Injects up to 3 passing variants per entry (matching the 3-strategy model).
    """
    payload = _load_json(DATA_SOURCE, {})
    result: list[dict[str, Any]] = []
    for entry in payload.get("entries", []):
        passing = [
            v for v in entry.get("variants", [])
            if v.get("validation", {}).get("stage") == "passed"
        ]
        if passing:
            e = dict(entry)
            e["variants"] = passing[:3]   # cap at 3 — one per strategy layer
            result.append(e)
    return result


# ---------------------------------------------------------------------------
# Triage action builders
# ---------------------------------------------------------------------------


def _prod_record(variant: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "approved_at":       _now_iso(),
        "threat_id":         entry.get("threat_id"),
        "threat_title":      entry.get("threat_title"),
        "threat_url":        entry.get("threat_url"),
        "source":            entry.get("source"),
        "gemma_verdict":     entry.get("gemma_verdict"),
        "rule":              {k: v for k, v in variant.items() if k != "validation"},
        "validation":        variant.get("validation"),
        # Carry trace_id so it can be referenced in downstream analysis
        "langfuse_trace_id": entry.get("langfuse_trace_id"),
    }


_STRATEGY_NAMES: list[str] = [
    "Primary High-Fidelity Trigger",
    "Behavioral & Chained Action",
    "Defense-in-Depth / Secondary Vector",
]


def _strategy_for_variant(
    variant: dict[str, Any],
    all_variants: list[dict[str, Any]],
) -> str:
    """Return the strategy label based on the variant's position in the 3-column grid."""
    try:
        idx = next(
            i for i, v in enumerate(all_variants) if v.get("name") == variant.get("name")
        )
        return _STRATEGY_NAMES[idx] if idx < len(_STRATEGY_NAMES) else f"Variant {idx + 1}"
    except StopIteration:
        return "Unknown"


def _feedback_record(
    variant: dict[str, Any],
    entry: dict[str, Any],
    reason: str,
    rejection_type: str,
    all_variants: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    strategy = (
        _strategy_for_variant(variant, all_variants)
        if all_variants is not None
        else "Unknown"
    )
    return {
        "rejected_at":        _now_iso(),
        "rejection_type":     rejection_type,
        "rejection_reason":   reason,
        "detection_strategy": strategy,
        "threat_id":          entry.get("threat_id"),
        "threat_title":       entry.get("threat_title"),
        "source":             entry.get("source"),
        "rule":               {k: v for k, v in variant.items() if k != "validation"},
        "validation":         variant.get("validation"),
        # Carry trace_id for cross-pipeline lineage
        "langfuse_trace_id":  entry.get("langfuse_trace_id"),
    }


# ---------------------------------------------------------------------------
# Triage action handlers
# ---------------------------------------------------------------------------


def _clear_threat_state(threat_id: str, variants: list[dict[str, Any]]) -> None:
    keys = [
        f"rej_set__{threat_id}",
        *[f"show_rej__{threat_id}__{v['name']}" for v in variants],
    ]
    for k in keys:
        st.session_state.pop(k, None)


def action_approve(
    approved: dict[str, Any],
    all_variants: list[dict[str, Any]],
    entry: dict[str, Any],
    already_rejected: set[str],
) -> None:
    """
    1. Write approved variant to prod.
    2. Implicitly reject all remaining (non-already-explicitly-rejected) siblings.
    3. Log positive Langfuse feedback score (1.0) for this approval.
    4. Remove threat from queue. Clear session state.
    """
    _append_to_file(PROD_RULES, [_prod_record(approved, entry)])

    implicit = [
        _feedback_record(v, entry, _IMPLICIT_REJECT_REASON, "implicit", all_variants)
        for v in all_variants
        if v.get("name") != approved.get("name")
        and v.get("name") not in already_rejected
    ]
    if implicit:
        _append_to_file(FEEDBACK_QUEUE, implicit)

    # ── Langfuse: log positive engineer feedback score ────────────────────
    log_approval_score(
        entry.get("langfuse_trace_id"),
        rule_name=approved.get("name", ""),
    )

    _remove_threat_from_queue(entry["threat_id"])
    _clear_threat_state(entry["threat_id"], all_variants)


def action_explicit_reject(
    variant: dict[str, Any],
    entry: dict[str, Any],
    reason: str,
    all_variants: list[dict[str, Any]],
    already_rejected: set[str],
) -> None:
    """
    Write one explicitly rejected variant to feedback queue.
    Log negative Langfuse feedback score (0.0) with the engineer's reason.
    If all variants are now rejected, also remove the threat from queue.
    """
    clean_reason = reason.strip()
    _append_to_file(
        FEEDBACK_QUEUE,
        [_feedback_record(variant, entry, clean_reason, "explicit", all_variants)],
    )

    # ── Langfuse: log negative engineer feedback score ────────────────────
    log_rejection_score(
        entry.get("langfuse_trace_id"),
        rejection_reason=clean_reason,
        rule_name=variant.get("name", ""),
    )

    updated = already_rejected | {variant["name"]}
    if {v["name"] for v in all_variants} == updated:
        _remove_threat_from_queue(entry["threat_id"])
        _clear_threat_state(entry["threat_id"], all_variants)
    else:
        st.session_state[f"rej_set__{entry['threat_id']}"] = updated


# ---------------------------------------------------------------------------
# Column renderer — one strategy variant per column
# ---------------------------------------------------------------------------


def _variant_column(
    col: Any,
    variant: dict[str, Any],
    strategy_icon: str,
    strategy_label: str,
    entry: dict[str, Any],
    all_variants: list[dict[str, Any]],
    already_rejected: set[str],
    col_idx: int,
) -> None:
    """Render a single strategy column inside a pre-created st.column context."""
    tid       = entry["threat_id"]
    v_name    = variant.get("name", f"Variant {col_idx + 1}")
    severity  = variant.get("defaultSeverity", "Unknown")
    ttype     = variant.get("threatType", "—")
    actions   = variant.get("actionNames", [])
    desc      = variant.get("description", "")
    recommend = variant.get("recommend", "")
    remediate = variant.get("remediate", "")
    audit     = (variant.get("validation") or {}).get("stage3_audit") or {}
    kent_tag  = audit.get("kent_probability_tag", "Unknown")
    rationale = audit.get("audit_rationale", "")

    # Severity source label: "CVSS 8.7 · High" vs "AI Est. · High"
    cvss_score_val  = variant.get("cvss_score")
    severity_src    = variant.get("severity_source", "ai")
    if severity_src == "cvss" and cvss_score_val is not None:
        sev_source_label = f"CVSS {float(cvss_score_val):.1f} · {severity}"
    else:
        sev_source_label = f"AI Est. · {severity}"

    reject_form_key = f"show_rej__{tid}__{v_name}"
    is_rejected     = v_name in already_rejected

    with col:
        # ── Strategy layer label ─────────────────────────────────
        st.markdown(
            f"<div style='text-align:center;font-size:0.8rem;font-weight:700;"
            f"color:#7f8c8d;letter-spacing:0.05em;text-transform:uppercase;"
            f"margin-bottom:4px;'>{strategy_icon} {strategy_label}</div>",
            unsafe_allow_html=True,
        )

        # ── Column card ──────────────────────────────────────────
        with st.container(border=True):
            if is_rejected:
                st.markdown(
                    "<p style='text-align:center;color:#c0392b;font-weight:700;"
                    "font-size:0.85rem;margin:4px 0;'>⛔ Explicitly Rejected</p>",
                    unsafe_allow_html=True,
                )
                st.caption(v_name)
                return

            # Rule name + badges
            st.markdown(f"**{v_name}**")
            st.markdown(
                f"{_severity_badge(severity)}&nbsp;{_kent_badge(kent_tag)}&nbsp;"
                f"<span style='font-size:0.75rem;color:#7f8c8d;'>{sev_source_label}</span>",
                unsafe_allow_html=True,
            )
            st.markdown("")

            # Threat type
            st.caption(f"**MITRE Tactic:** {ttype}")

            # Action names
            st.code("\n".join(actions) if actions else "—", language=None)

            # Description
            st.markdown(desc)

            # Expandable details
            with st.expander("Recommend & Remediate"):
                st.markdown(f"**Recommend:** {recommend}")
                st.divider()
                st.markdown(f"**Remediate:** {remediate}")

            if rationale:
                with st.expander("CTI Audit Rationale"):
                    st.markdown(rationale)

        # ── Decision buttons ─────────────────────────────────────
        if _green_button(
            "✅ Approve / Move to Prod",
            key=f"approve__{tid}__{v_name}",
            use_container_width=True,
        ):
            action_approve(variant, all_variants, entry, already_rejected)
            st.toast(f"✅ **{v_name}** approved → production.", icon="✅")
            st.rerun()

        if _red_button(
            "❌ Reject / Mark Invalid",
            key=f"reject_btn__{tid}__{v_name}",
            use_container_width=True,
        ):
            st.session_state[reject_form_key] = True

        # Reject form — appears inline under the reject button
        if st.session_state.get(reject_form_key, False):
            reason_text = st.text_area(
                "Reason for Failure",
                key=f"reason__{tid}__{v_name}",
                placeholder="Describe why this variant is invalid for production…",
                height=90,
            )
            c_sub, c_can = st.columns(2)
            with c_sub:
                if _red_button(
                    "Submit Rejection",
                    key=f"submit_rej__{tid}__{v_name}",
                    disabled=not (reason_text and reason_text.strip()),
                    use_container_width=True,
                ):
                    action_explicit_reject(
                        variant, entry, reason_text, all_variants, already_rejected
                    )
                    st.session_state[reject_form_key] = False
                    st.toast(f"⚠️ **{v_name}** logged to feedback queue.")
                    st.rerun()
            with c_can:
                if st.button(
                    "Cancel",
                    key=f"cancel_rej__{tid}__{v_name}",
                    use_container_width=True,
                ):
                    st.session_state[reject_form_key] = False
                    st.rerun()


# ---------------------------------------------------------------------------
# Threat block — header + 3-column comparison grid
# ---------------------------------------------------------------------------


def _threat_block(entry: dict[str, Any]) -> None:
    tid      = entry.get("threat_id", "unknown")
    title    = entry.get("threat_title", "Untitled Threat")
    url      = entry.get("threat_url", "")
    source   = entry.get("source", "Unknown source")
    verdict  = entry.get("gemma_verdict") or {}
    platform = verdict.get("primary_platform", "Unknown")
    domain   = verdict.get("primary_domain", "Unknown")
    score    = verdict.get("confidence_score", "—")
    reasoning = verdict.get("reasoning_summary", "")

    all_variants: list[dict[str, Any]] = entry.get("variants", [])
    already_rejected: set[str] = st.session_state.get(f"rej_set__{tid}", set())

    # Skip if every variant has been individually rejected already
    if {v["name"] for v in all_variants} == already_rejected:
        return

    # Pull CVSS vector source from the first variant that carries it (set by
    # apply_official_severity when an official CVSS vector was found).
    cvss_vector_src: str = next(
        (v.get("cvss_vector_source", "") for v in all_variants if v.get("cvss_vector_source")),
        "",
    )

    # Derive NHI / AI_Agent domain tags from grounding_context if present.
    grounding: dict[str, Any] = entry.get("grounding_context") or {}
    _extra_domains: list[str] = []
    matched_platforms: list[str] = [p.lower() for p in (grounding.get("matched_platforms") or [])]
    if any(p in matched_platforms for p in ("nhi", "active_directory", "workload_identity")):
        _extra_domains.append("NHI")
    if any(p in matched_platforms for p in ("ai_agent", "llm", "mcp")):
        _extra_domains.append("AI_Agent")

    with st.container(border=True):
        # ── Threat header ────────────────────────────────────────
        linked = f"[{title}]({url})" if url else title
        st.markdown(f"### 🔗 {linked}")

        h1, h2, h3, h4 = st.columns(4)
        with h1:
            st.markdown(f"**Source:** {source}")
        with h2:
            domain_badges_html = _domain_badge(domain)
            for ed in _extra_domains:
                domain_badges_html += f"&nbsp;{_domain_badge(ed)}"
            st.markdown(
                f"**Platform:** {_platform_badge(platform)}&nbsp;&nbsp;"
                f"**Domain:** {domain_badges_html}",
                unsafe_allow_html=True,
            )
        with h3:
            st.markdown(f"**Gemma Score:** {score}/10")
        with h4:
            pending = len([v for v in all_variants if v["name"] not in already_rejected])
            rejected = len(already_rejected)
            label = f"⏳ {pending} pending"
            if rejected:
                label += f" · ⛔ {rejected} rejected"
            st.caption(label)

        if cvss_vector_src:
            st.markdown(
                f"**CVSS Vector:** `{cvss_vector_src}`",
                unsafe_allow_html=False,
            )

        if reasoning:
            st.info(f"🧠 {reasoning}")

        st.divider()

        # ── 3-column comparison grid ─────────────────────────────
        n = len(all_variants)
        cols = st.columns(n if n > 0 else 1)

        for idx, variant in enumerate(all_variants):
            icon, label = _STRATEGY_LABELS[idx] if idx < len(_STRATEGY_LABELS) else ("📌", f"Variant {idx+1}")
            _variant_column(
                col=cols[idx],
                variant=variant,
                strategy_icon=icon,
                strategy_label=label,
                entry=entry,
                all_variants=all_variants,
                already_rejected=already_rejected,
                col_idx=idx,
            )


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------


def main() -> None:
    st.set_page_config(
        page_title="Triage — Detection Rules",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    # Inject JS observer that colours approve/reject buttons
    _inject_button_colours()

    # ── Sidebar ──────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("## 🛡️ Triage Console")
        st.caption("Source: `data/validated_rules.json`")
        st.divider()

        prod_count     = len(_load_json(PROD_RULES, []))
        feedback_count = len(_load_json(FEEDBACK_QUEUE, []))
        st.metric("Rules in Production", prod_count)
        st.metric("Feedback Queue", feedback_count)
        st.divider()

        if st.button("🔄 Refresh Queue", use_container_width=True):
            st.rerun()

        st.markdown("---")
        st.markdown(
            "**How it works:**\n\n"
            "Each threat shows **3 variants** side-by-side — "
            "🎯 Primary High-Fidelity, 🔗 Behavioral & Chained, 🛡️ Defense-in-Depth.\n\n"
            "Click **Approve** on the winning variant. "
            "The other 2 are automatically sent to the feedback queue.\n\n"
            "Click **Reject** on any variant to log it with a custom reason "
            "before approving a different one."
        )

    # ── Page header ──────────────────────────────────────────────
    st.markdown("# 🛡️ Security Engineer Triage Dashboard")
    st.markdown(
        "Compare **3 detection strategies** side-by-side per threat. "
        "**One rule wins.** The other two are logged with justification."
    )

    entries = load_triage_entries()

    if not entries:
        st.success(
            "✅ **Queue empty.** All threats have been triaged. "
            "Re-run the pipeline (Steps 1–4) to populate new threats."
        )
        return

    # ── Stats bar ────────────────────────────────────────────────
    total_pending = sum(
        len([
            v for v in e.get("variants", [])
            if v.get("name") not in st.session_state.get(f"rej_set__{e.get('threat_id')}", set())
        ])
        for e in entries
    )
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Threats to Triage", len(entries))
    m2.metric("Variants Pending", total_pending)
    m3.metric("Approved to Prod", len(_load_json(PROD_RULES, [])))
    m4.metric("Feedback Queue", len(_load_json(FEEDBACK_QUEUE, [])))

    st.divider()

    # ── Render each threat block ──────────────────────────────────
    for entry in entries:
        _threat_block(entry)
        st.markdown("&nbsp;")


if __name__ == "__main__":
    main()
