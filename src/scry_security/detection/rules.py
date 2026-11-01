"""Typed detection vocabulary. No executable expressions or dynamic imports."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(pattern=r"^SCRY-[A-Z0-9-]{3,60}$")
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=4000)
    severity: Severity
    operating_systems: list[Literal["windows", "linux"]] = Field(min_length=1)
    required_sources: list[str] = Field(min_length=1)
    mode: Literal["threshold", "distinct", "sequence"] = "threshold"
    event_types: list[str] = Field(min_length=1)
    group_by: list[str] = Field(default_factory=lambda: ["operating_system", "hostname"])
    conditions: dict[str, list[JsonValue]] = Field(default_factory=dict)
    exclude: dict[str, list[JsonValue]] = Field(default_factory=dict)
    threshold: int = Field(default=1, ge=1, le=1000)
    window_seconds: int = Field(default=300, ge=1, le=86400)
    distinct_field: str | None = None
    preceding_event_type: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    false_positives: str = Field(min_length=1, max_length=4000)
    investigation: str = Field(min_length=1, max_length=4000)
    defensive_actions: str = Field(min_length=1, max_length=4000)

    @model_validator(mode="after")
    def valid_fields(self) -> "Rule":
        fields = [*self.group_by, *self.conditions, *self.exclude]
        if self.distinct_field:
            fields.append(self.distinct_field)
        allowed = {
            "operating_system",
            "hostname",
            "username",
            "source_ip",
            "destination_ip",
            "category",
            "event_type",
            "outcome",
            "source",
            "native_event_id",
            "synthetic",
        }
        for field in fields:
            if field not in allowed and not (
                (field.startswith("details.") or field.startswith("context."))
                and len(field.split(".")) == 2
                and field.split(".", 1)[1].replace("_", "").isalnum()
            ):
                raise ValueError(f"Unsupported detection field: {field}")
        if self.mode == "distinct" and not self.distinct_field:
            raise ValueError("Distinct rules require distinct_field")
        if self.mode == "sequence" and not self.preceding_event_type:
            raise ValueError("Sequence rules require preceding_event_type")
        if not self.group_by:
            raise ValueError("A rule must group evidence explicitly")
        return self


def initial_rules() -> list[Rule]:
    """Load the packaged, validated default YAML catalogue."""
    from scry_security.detection.loader import load_rules

    return load_rules()
