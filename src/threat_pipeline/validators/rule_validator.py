import json
from typing import Any

from config.settings import Settings
from threat_pipeline.models.rules import (
    ThreatRule,
    ValidationErrorDetail,
    ValidationResult,
    ValidationStatus,
)


class RuleValidator:
    """Deterministic JSON syntax, schema, and actionName validation."""

    def __init__(self, settings: Settings) -> None:
        self._valid_actions = set(settings.valid_action_names)
        self._valid_severities = set(settings.valid_severities)

    def validate_variant(self, variant_index: int, raw: dict[str, Any] | ThreatRule) -> ValidationResult:
        errors: list[ValidationErrorDetail] = []

        if isinstance(raw, ThreatRule):
            rule_dict = raw.model_dump()
        else:
            try:
                json.dumps(raw)
            except (TypeError, ValueError) as exc:
                return ValidationResult(
                    variant_index=variant_index,
                    status=ValidationStatus.INVALID,
                    errors=[
                        ValidationErrorDetail(
                            code="JSON_SYNTAX",
                            message=str(exc),
                        )
                    ],
                )
            rule_dict = raw

        try:
            rule = ThreatRule.model_validate(rule_dict)
        except Exception as exc:
            errors.append(
                ValidationErrorDetail(
                    code="SCHEMA_TYPE",
                    message=str(exc),
                )
            )
            return ValidationResult(
                variant_index=variant_index,
                status=ValidationStatus.INVALID,
                errors=errors,
            )

        errors.extend(self._check_required(rule))
        errors.extend(self._check_actions(rule))
        errors.extend(self._check_severity(rule))

        if errors:
            return ValidationResult(
                variant_index=variant_index,
                status=ValidationStatus.INVALID,
                rule=rule,
                errors=errors,
            )
        return ValidationResult(
            variant_index=variant_index,
            status=ValidationStatus.VALID,
            rule=rule,
        )

    def validate_all(self, variants: list[ThreatRule]) -> list[ValidationResult]:
        return [self.validate_variant(i, v) for i, v in enumerate(variants)]

    def _check_required(self, rule: ThreatRule) -> list[ValidationErrorDetail]:
        errors: list[ValidationErrorDetail] = []
        for field in ("name", "description", "threatType", "recommend", "remediate"):
            if not getattr(rule, field, "").strip():
                errors.append(
                    ValidationErrorDetail(
                        code="SCHEMA_REQUIRED",
                        field=field,
                        message=f"{field} must be non-empty",
                    )
                )
        return errors

    def _check_actions(self, rule: ThreatRule) -> list[ValidationErrorDetail]:
        invalid = [a for a in rule.actionNames if a not in self._valid_actions]
        if invalid:
            return [
                ValidationErrorDetail(
                    code="ACTION_SEMANTIC",
                    field="actionNames",
                    message=f"Unknown actions: {invalid}. Allowed: {sorted(self._valid_actions)}",
                )
            ]
        return []

    def _check_severity(self, rule: ThreatRule) -> list[ValidationErrorDetail]:
        if rule.defaultSeverity.lower() not in self._valid_severities:
            return [
                ValidationErrorDetail(
                    code="SEVERITY_ENUM",
                    field="defaultSeverity",
                    message=f"Invalid severity '{rule.defaultSeverity}'. Allowed: {sorted(self._valid_severities)}",
                )
            ]
        return []
