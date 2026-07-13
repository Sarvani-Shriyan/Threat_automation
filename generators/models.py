# pip install pydantic

from typing import Literal

from pydantic import BaseModel, Field, field_validator

Severity = Literal["Low", "Medium", "High", "Critical"]


class DetectionRule(BaseModel):
    """Exact detection rule schema contract."""

    name: str = Field(description="[Platform]: [Actionable, Precise Indicator Title]")
    description: str
    actionNames: list[str] = Field(min_length=1)
    defaultSeverity: Severity
    threatType: str = Field(description="MITRE ATT&CK Tactic name")
    recommend: str
    remediate: str

    @field_validator("defaultSeverity", mode="before")
    @classmethod
    def normalize_severity(cls, v: object) -> str:
        if isinstance(v, str):
            mapping = {
                "low": "Low",
                "medium": "Medium",
                "high": "High",
                "critical": "Critical",
            }
            return mapping.get(v.strip().lower(), v.strip().title())
        return v


class ThreatRuleBatch(BaseModel):
    """Exactly 3 structurally diverse rule variants per threat."""

    rules: list[DetectionRule] = Field(min_length=3, max_length=3)


class StagedThreatRules(BaseModel):
    """Staging record per verified threat."""

    threat_id: str
    threat_title: str
    threat_url: str | None = None
    source: str
    gemma_verdict: dict | None = None
    variants: list[DetectionRule] = Field(default_factory=list)
    generation_status: Literal["success", "failed", "skipped"] = "success"
    error: str | None = None
