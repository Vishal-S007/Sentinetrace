"""Incidents (groups of related alerts) and append-only investigation notes."""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.detection import SEVERITIES, _in

INCIDENT_STATUSES = ("open", "investigating", "contained", "resolved", "closed")
CLOSED_INCIDENT_STATUSES = ("resolved", "closed")
NOTE_KINDS = ("note", "action", "evidence")


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(_in("status", INCIDENT_STATUSES), name="ck_incidents_status"),
        CheckConstraint(_in("severity", SEVERITIES), name="ck_incidents_severity"),
        Index("ix_incidents_status_updated", "status", "updated_at"),
        Index("ix_incidents_assigned_to", "assigned_to"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    summary: Mapped[str] = mapped_column(Text, server_default="")
    status: Mapped[str] = mapped_column(String(16), server_default="open")
    severity: Mapped[str] = mapped_column(String(16))
    assigned_to: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IncidentAlert(Base):
    """An alert linked to an incident. An alert may belong to more than one incident."""

    __tablename__ = "incident_alerts"
    __table_args__ = (Index("ix_incident_alerts_alert", "alert_id"),)

    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), primary_key=True)
    linked_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class InvestigationNote(Base):
    """A note, action taken, or evidence reference on exactly one alert or incident.

    Insert-only: a database trigger rejects UPDATE and DELETE. Corrections are new notes.
    """

    __tablename__ = "investigation_notes"
    __table_args__ = (
        CheckConstraint(_in("kind", NOTE_KINDS), name="ck_notes_kind"),
        CheckConstraint("(alert_id IS NULL) <> (incident_id IS NULL)", name="ck_notes_one_parent"),
        CheckConstraint("length(body) BETWEEN 1 AND 5000", name="ck_notes_body_length"),
        Index("ix_notes_alert", "alert_id", "id"),
        Index("ix_notes_incident", "incident_id", "id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"))
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"))
    kind: Mapped[str] = mapped_column(String(16), server_default="note")
    body: Mapped[str] = mapped_column(Text)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id"))
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
