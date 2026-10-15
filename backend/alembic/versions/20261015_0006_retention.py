"""Retention support: mark stored uploads removed by retention; index note event refs.

Revision ID: 0006
Revises: 0005
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | Sequence[str] | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "imported_files", sa.Column("content_purged_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_index(
        "ix_notes_event",
        "investigation_notes",
        ["event_id"],
        postgresql_where=sa.text("event_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_notes_event", table_name="investigation_notes")
    op.drop_column("imported_files", "content_purged_at")
