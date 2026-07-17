"""
JSON Schema definitions for every structured-output step in the pipeline.

These schemas serve a dual purpose:
  • OpenAI cloud mode  — passed verbatim as the `json_schema.schema` field inside
    `response_format={"type":"json_schema","json_schema":{"strict":True,...}}`,
    giving API-level contract enforcement.
  • Ollama / LiteLLM mode — used only by downstream Pydantic validators as a
    reference contract; the model itself receives `json_object` mode.

Schema authoring notes
----------------------
- Every schema must satisfy OpenAI strict mode requirements:
    * `"additionalProperties": false` on every object node.
    * Every property listed in `"properties"` must appear in `"required"`.
    * No unsupported keywords (avoid `minimum`/`maximum` — use Pydantic instead).
- enum constraints ARE supported and should be used wherever the value domain is finite.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Step 2 — Dynamic Semantic Filter (GemmaVerifier)
# ---------------------------------------------------------------------------

GEMMA_VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "is_relevant": {
            "type": "boolean",
            "description": "True if the article describes an actionable threat in our monitored domains.",
        },
        "confidence_score": {
            "type": "integer",
            "description": "Relevance certainty from 1 (irrelevant) to 10 (high-confidence threat).",
        },
        "primary_domain": {
            "type": "string",
            "enum": ["Identity", "Cloud", "SaaS", "Unrelated"],
            "description": "The primary security domain the threat belongs to.",
        },
        "primary_platform": {
            "type": "string",
            "enum": ["AWS", "GCP", "GitHub", "Okta", "Azure", "Unknown"],
            "description": "The specific cloud or identity platform most directly affected.",
        },
        "reasoning_summary": {
            "type": "string",
            "description": "One sentence explaining the exact evidence that drove this classification.",
        },
    },
    "required": [
        "is_relevant",
        "confidence_score",
        "primary_domain",
        "primary_platform",
        "reasoning_summary",
    ],
    "additionalProperties": False,
}

# ---------------------------------------------------------------------------
# Step 3 — Rule Generation Engine (RuleEngine)
# 7-key detection rule contract × exactly 3 strategy-diverse variants
# ---------------------------------------------------------------------------

_DETECTION_RULE_OBJECT: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "description": "[Platform]: [Actionable Indicator Title]",
        },
        "description": {
            "type": "string",
            "description": "Operational trigger, condition boundaries, and telemetry layer focus.",
        },
        "actionNames": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Exact infrastructure / API action names to monitor (from KB catalog).",
        },
        "defaultSeverity": {
            "type": "string",
            "enum": ["Low", "Medium", "High", "Critical"],
            "description": "Alert severity level.",
        },
        "threatType": {
            "type": "string",
            "description": "MITRE ATT&CK Tactic name.",
        },
        "recommend": {
            "type": "string",
            "description": "Structural hardening and preventive configuration guidance.",
        },
        "remediate": {
            "type": "string",
            "description": "Tactical response, containment, and post-incident validation steps.",
        },
    },
    "required": [
        "name",
        "description",
        "actionNames",
        "defaultSeverity",
        "threatType",
        "recommend",
        "remediate",
    ],
    "additionalProperties": False,
}

RULE_BATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "rules": {
            "type": "array",
            "items": _DETECTION_RULE_OBJECT,
            "minItems": 3,
            "maxItems": 3,
            "description": (
                "Exactly 3 detection rule variants: "
                "[0] Process/CLI, [1] File/Registry, [2] Network/API."
            ),
        },
    },
    "required": ["rules"],
    "additionalProperties": False,
}

# ---------------------------------------------------------------------------
# Step 4 Stage 3 — Sherman Kent CTI Cognitive Audit (cloud path)
#
# In OpenAI cloud mode the model embeds the full 5-section markdown report
# inside `full_report` as a JSON string value, so the 3 canonical keys are
# delivered at API-enforcement level without altering the system prompt text.
#
# In Ollama mode this schema is not sent to the model; the free-form CTI
# report text is returned by generate_text() and the existing regex helpers
# (_extract_kent_tag, _extract_executive_summary) populate these fields.
# ---------------------------------------------------------------------------

KENT_AUDIT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "kent_probability_tag": {
            "type": "string",
            "enum": [
                "Almost Certain",
                "Highly Likely",
                "Highly Unlikely",
                "Probable",
                "Unlikely",
                "Likely",
                "Possible",
                "Remote",
            ],
            "description": (
                "Sherman Kent estimative probability label extracted from "
                "the Probability Assessment section of the report."
            ),
        },
        "audit_rationale": {
            "type": "string",
            "description": "Executive Summary section of the CTI report (≤ 600 chars).",
        },
        "full_report": {
            "type": "string",
            "description": (
                "The complete 5-section Sherman Kent CTI report as a "
                "markdown string (sections 1–5 intact)."
            ),
        },
    },
    "required": ["kent_probability_tag", "audit_rationale", "full_report"],
    "additionalProperties": False,
}

# ---------------------------------------------------------------------------
# Step 6 — Automated Feedback Loop (main_feedback.py)
# ---------------------------------------------------------------------------

FEEDBACK_CONSTRAINTS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "negative_constraints": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 2,
            "maxItems": 3,
            "description": (
                "2–3 generalized engineering constraints that prevent the "
                "rule generation model from repeating detected mistake patterns."
            ),
        },
    },
    "required": ["negative_constraints"],
    "additionalProperties": False,
}
