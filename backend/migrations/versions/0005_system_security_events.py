"""Add minimal system security events.

Revision ID: 0005_system_security_events
Revises: 0004_pending_totp
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_system_security_events"
down_revision = "0004_pending_totp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "system_security_events",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            "event_type IN ('password_breach_check_unavailable')",
            name="ck_system_security_event_type",
        ),
        sa.CheckConstraint("created_at >= 0", name="ck_system_security_event_time"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_system_security_events_created_at", "system_security_events", ["created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_system_security_events_created_at", table_name="system_security_events")
    op.drop_table("system_security_events")
