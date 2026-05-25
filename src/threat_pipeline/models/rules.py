from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ThreatRule(BaseModel):
    """Exact schema for detection rule variants."""

    name: str
    description: str
    actionNames: list[str]
    defaultSeverity: str
    threatType: str
    recommend: str
    remediate: str

    @field_validator("actionNames")
    @classmethod
    def action_names_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("actionNames must contain at least one action")
        return v


class RuleVariant(BaseModel):
    variant_index: int
    rule: ThreatRule
    raw_json: dict[str, Any] | None = None


class ValidationStatus(str, Enum):
    VALID = "Valid"
    INVALID = "Invalid"


class ValidationErrorDetail(BaseModel):
    code: str
    field: str | None = None
    message: str


class ValidationResult(BaseModel):
    variant_index: int
    status: ValidationStatus
    rule: ThreatRule | None = None
    errors: list[ValidationErrorDetail] = Field(default_factory=list)
