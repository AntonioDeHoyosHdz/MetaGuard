"""Persist minimized, expiring account-visible security events.

Revision ID: 0013_account_security_events
Revises: 0012_password_reset
"""

import sqlalchemy as sa
from alembic import op

revision = "0013_account_security_events"
down_revision = "0012_password_reset"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "account_security_events",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(36), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("pace_window", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            "kind IN ('login_failed', 'mfa_failed', 'upload_type_mismatch', "
            "'rate_limit_exceeded', 'new_ip_login', 'dangerous_content_detected', "
            "'leaked_password_rejected')",
            name="ck_account_security_event_kind",
        ),
        sa.CheckConstraint(
            "created_at >= 0 AND pace_window = created_at / 600",
            name="ck_account_security_event_pace_window",
        ),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("account_id", "kind", "pace_window", name="uq_account_event_pace"),
    )
    op.create_index(
        "ix_account_event_history", "account_security_events", ["account_id", "created_at", "id"]
    )
    op.create_index("ix_account_event_created_at", "account_security_events", ["created_at"])


def downgrade() -> None:
    op.drop_table("account_security_events")
