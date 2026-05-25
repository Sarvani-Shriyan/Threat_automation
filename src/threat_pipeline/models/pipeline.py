from datetime import datetime

from pydantic import BaseModel, Field

from threat_pipeline.models.rules import ThreatRule, ValidationErrorDetail, ValidationResult


class RelevanceVerdict(BaseModel):
    is_threat: bool
    rationale: str


class RuleGenerationBatch(BaseModel):
    threat_id: str
    variants: list[ThreatRule] = Field(min_length=5, max_length=6)


class ThreatContext(BaseModel):
    threat_id: str
    title: str
    source: str
    url: str | None = None
    published_at: datetime | None = None
    excerpt: str


class InvalidRuleEntry(BaseModel):
    rule: ThreatRule
    errors: list[ValidationErrorDetail]


class HITLPayload(BaseModel):
    threat_id: str
    threat_context: ThreatContext
    validated_rules: list[ThreatRule] = Field(max_length=3)
    invalid_rules: list[InvalidRuleEntry] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class FeedbackBundle(BaseModel):
    threat_id: str
    threat_context: ThreatContext
    rejected_rules: list[ThreatRule] = Field(default_factory=list)
    validation_results: list[ValidationResult] = Field(default_factory=list)
    human_notes: str | None = None
    retry_count: int = 0
