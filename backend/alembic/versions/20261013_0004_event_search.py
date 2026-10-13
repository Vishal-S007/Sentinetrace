"""Trigram index for substring search over events.raw_line.

pg_trgm is a trusted extension (PostgreSQL 13+), so the database owner can create it.

Revision ID: 0004
Revises: 0003
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.create_index(
        "ix_events_raw_line_trgm",
        "events",
        ["raw_line"],
        postgresql_using="gin",
        postgresql_ops={"raw_line": "gin_trgm_ops"},
    )


def downgrade() -> None:
    op.drop_index("ix_events_raw_line_trgm", table_name="events")
    # The extension is left installed: other objects may depend on it.
