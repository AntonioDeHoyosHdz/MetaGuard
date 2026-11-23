"""Persist expiring, account-owned security alerts without recipient or event details.

Revision ID: 0014_security_alerts
Revises: 0013_account_security_events
"""

import sqlalchemy as sa
from alembic import op

revision = "0014_security_alerts"
down_revision = "0013_account_security_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_alert_outbox",
        sa.Column("account_id", sa.String(36), nullable=False),
        sa.Column("cooldown_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_id", sa.String(32), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("finished", sa.Boolean(), nullable=False),
        sa.CheckConstraint("attempts BETWEEN 0 AND 3", name="ck_security_alert_attempts"),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("account_id"),
    )
    op.create_index(
        "ix_security_alert_ready",
        "security_alert_outbox",
        ["finished", "available_at", "account_id"],
    )
    op.create_index(
        "ix_security_alert_cooldown", "security_alert_outbox", ["cooldown_until", "account_id"]
    )


def downgrade() -> None:
    op.drop_table("security_alert_outbox")
