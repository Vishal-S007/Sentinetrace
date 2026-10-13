"""Correlation: several different rules fired for the same source IP in one time bucket."""

from pydantic import Field, field_validator

from app.detection.base import Rule, RuleConfig


class CorrelationConfig(RuleConfig):
    rule_ids: list[str] = Field(
        default=[
            "ST-AUTH-002",
            "ST-WEB-001",
            "ST-WEB-002",
            "ST-WEB-003",
            "ST-WEB-004",
            "ST-WEB-005",
            "ST-WEB-006",
            "ST-WEB-007",
        ],
        min_length=2,
        max_length=50,
        description="Rules whose alerts are combined",
    )
    min_distinct_rules: int = Field(
        default=2, ge=2, le=50, description="Distinct rules that must fire for one IP"
    )

    @field_validator("rule_ids")
    @classmethod
    def no_self_reference(cls, v: list[str]) -> list[str]:
        if "ST-CORR-001" in v:
            raise ValueError("the correlation rule cannot include itself")
        return v


class MultiStageActivity(Rule):
    """Evaluated by the engine over alerts (not events); see engine.correlate()."""

    rule_id = "ST-CORR-001"
    name = "Multi-stage suspicious activity from one IP"
    category = "correlation"
    description = (
        "Alerts from several different rules (e.g. reconnaissance followed by injection "
        "attempts, or scanning plus brute force) fired for the same source IP within the "
        "same grouping window. Combined behaviour is a stronger signal than any single alert."
    )
    default_severity = "high"
    config_model = CorrelationConfig
    event_types = None
    recommended_steps = [
        "Investigate this IP as a single actor: read the member alerts in time order.",
        "Determine whether any stage appears to have succeeded (200 responses to payloads, "
        "successful logins).",
        "Block the IP and search all sources for further activity from it.",
        "Consider opening an incident if any member alert shows possible success.",
    ]
