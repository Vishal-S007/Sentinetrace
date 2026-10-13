"""Detection rules (with version history), alerts, alert evidence and detection runs."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base

SEVERITIES = ("low", "medium", "high", "critical")
ALERT_STATUSES = ("new", "investigating", "resolved", "false_positive")
CONFIDENCES = ("low", "medium", "high")
RUN_STATUSES = ("queued", "running", "completed", "failed")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class DetectionRule(Base):
    """Runtime state of a rule. Logic, name and investigation steps live in code
    (app/detection/rules); severity, enabled state and thresholds live here."""

    __tablename__ = "detection_rules"
    __table_args__ = (CheckConstraint(_in("severity", SEVERITIES), name="ck_rules_severity"),)

    rule_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    severity: Mapped[str] = mapped_column(String(16))
    config: Mapped[dict[str, Any]] = mapped_column(JSONB)
    version: Mapped[int] = mapped_column(Integer, server_default="1")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))


class DetectionRuleVersion(Base):
    """Every configuration a rule has had. Alerts record the version that produced them."""

    __tablename__ = "detection_rule_versions"
    __table_args__ = (
        UniqueConstraint("rule_id", "version", name="uq_rule_versions_rule_version"),
        CheckConstraint(_in("severity", SEVERITIES), name="ck_rule_versions_severity"),
    )

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.rule_id"))
    version: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean)
    severity: Mapped[str] = mapped_column(String(16))
    config: Mapped[dict[str, Any]] = mapped_column(JSONB)
    note: Mapped[str] = mapped_column(String(500), server_default="")
    changed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Alert(Base):
    """A grouped detection: one alert per (rule, entity, time bucket).

    Alerts describe *observed indicators*; they never assert that an attack succeeded.
    Analyst-owned fields (status, assignee) survive re-detection of the same group.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("rule_id", "group_key", name="uq_alerts_rule_group"),
        CheckConstraint(_in("severity", SEVERITIES), name="ck_alerts_severity"),
        CheckConstraint(_in("status", ALERT_STATUSES), name="ck_alerts_status"),
        CheckConstraint(_in("confidence", CONFIDENCES), name="ck_alerts_confidence"),
        Index("ix_alerts_last_seen", "last_seen"),
        Index("ix_alerts_status_severity", "status", "severity"),
        Index("ix_alerts_source_ip", "source_ip"),
        Index("ix_alerts_bucket", "bucket_start"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.rule_id"), index=True)
    rule_version: Mapped[int] = mapped_column(Integer)
    group_key: Mapped[str] = mapped_column(String(255))
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    title: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24), server_default="new")
    confidence: Mapped[str] = mapped_column(String(8))
    confidence_reason: Mapped[str] = mapped_column(Text)
    recommended_action: Mapped[str] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(INET)
    username: Mapped[str | None] = mapped_column(String(256))
    endpoint: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer)
    window_seconds: Mapped[int] = mapped_column(Integer)
    evidence_truncated: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}")
    assigned_to: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AlertEvent(Base):
    """Links an alert to the events that support it (capped per alert)."""

    __tablename__ = "alert_events"
    __table_args__ = (Index("ix_alert_events_event", "event_id"),)

    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), primary_key=True)
    indicator: Mapped[str | None] = mapped_column(String(64))


class DetectionRun(Base):
    __tablename__ = "detection_runs"
    __table_args__ = (
        CheckConstraint(_in("status", RUN_STATUSES), name="ck_detection_runs_status"),
        Index("ix_detection_runs_status_id", "status", "id"),
    )

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    trigger: Mapped[str] = mapped_column(String(16))  # "ingestion" | "manual"
    status: Mapped[str] = mapped_column(String(16), server_default="queued")
    job_id: Mapped[int | None] = mapped_column(ForeignKey("ingestion_jobs.id"))
    range_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    range_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    alerts_created: Mapped[int] = mapped_column(Integer, server_default="0")
    alerts_updated: Mapped[int] = mapped_column(Integer, server_default="0")
    error_message: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
