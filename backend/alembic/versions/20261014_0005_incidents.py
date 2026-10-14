"""Incidents, incident-alert links, append-only investigation notes; audit target index.

Revision ID: 0005
Revises: 0004
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | Sequence[str] | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SEVERITY_CHECK = "severity IN ('low', 'medium', 'high', 'critical')"


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("summary", sa.Text(), server_default="", nullable=False),
        sa.Column("status", sa.String(length=16), server_default="open", nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("assigned_to", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('open', 'investigating', 'contained', 'resolved', 'closed')",
            name="ck_incidents_status",
        ),
        sa.CheckConstraint(SEVERITY_CHECK, name="ck_incidents_severity"),
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_incidents_status_updated", "incidents", ["status", "updated_at"])
    op.create_index("ix_incidents_assigned_to", "incidents", ["assigned_to"])

    op.create_table(
        "incident_alerts",
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("alert_id", sa.BigInteger(), nullable=False),
        sa.Column("linked_by", sa.Integer(), nullable=False),
        sa.Column(
            "linked_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"]),
        sa.ForeignKeyConstraint(["linked_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("incident_id", "alert_id"),
    )
    op.create_index("ix_incident_alerts_alert", "incident_alerts", ["alert_id"])

    op.create_table(
        "investigation_notes",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("alert_id", sa.BigInteger(), nullable=True),
        sa.Column("incident_id", sa.BigInteger(), nullable=True),
        sa.Column("kind", sa.String(length=16), server_default="note", nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=True),
        sa.Column("author_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("kind IN ('note', 'action', 'evidence')", name="ck_notes_kind"),
        sa.CheckConstraint(
            "(alert_id IS NULL) <> (incident_id IS NULL)", name="ck_notes_one_parent"
        ),
        sa.CheckConstraint("length(body) BETWEEN 1 AND 5000", name="ck_notes_body_length"),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"]),
        sa.ForeignKeyConstraint(["author_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_notes_alert", "investigation_notes", ["alert_id", "id"])
    op.create_index("ix_notes_incident", "investigation_notes", ["incident_id", "id"])
    op.execute(
        """
        CREATE FUNCTION investigation_notes_reject_change() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'investigation_notes is append-only (% rejected)', TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$;
        """
    )
    op.execute(
        "CREATE TRIGGER investigation_notes_no_update_delete "
        "BEFORE UPDATE OR DELETE ON investigation_notes "
        "FOR EACH ROW EXECUTE FUNCTION investigation_notes_reject_change()"
    )

    op.create_index("ix_audit_log_target", "audit_log", ["target_type", "target_id", "id"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_target", table_name="audit_log")
    op.execute("DROP TABLE investigation_notes")
    op.execute("DROP FUNCTION IF EXISTS investigation_notes_reject_change()")
    op.drop_table("incident_alerts")
    op.drop_table("incidents")
