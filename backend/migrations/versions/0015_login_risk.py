"""Persist bounded login-risk state and completed address familiarity.

Revision ID: 0015_login_risk
Revises: 0014_security_alerts
"""

import sqlalchemy as sa
from alembic import op

revision = "0015_login_risk"
down_revision = "0014_security_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "account_login_failures",
        sa.Column("account_id", sa.String(36), nullable=False),
        sa.Column("address_digest", sa.String(67), nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("lock_level", sa.Integer(), nullable=False),
        sa.Column("last_failed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("length(address_digest) = 67", name="ck_login_failure_digest_length"),
        sa.CheckConstraint("consecutive_failures BETWEEN 0 AND 4", name="ck_login_failure_streak"),
        sa.CheckConstraint("lock_level BETWEEN 0 AND 3", name="ck_login_failure_lock_level"),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("account_id", "address_digest"),
    )
    op.create_index(
        "ix_login_failure_owner_time", "account_login_failures", ["account_id", "last_failed_at"]
    )
    op.create_index("ix_login_failure_time", "account_login_failures", ["last_failed_at"])
    op.create_table(
        "account_login_failure_overflow",
        sa.Column("account_id", sa.String(36), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("account_id"),
    )
    op.create_index(
        "ix_login_failure_overflow_expires", "account_login_failure_overflow", ["expires_at"]
    )
    op.create_table(
        "account_familiar_addresses",
        sa.Column("account_id", sa.String(36), nullable=False),
        sa.Column("address_digest", sa.String(67), nullable=False),
        sa.Column("last_succeeded_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(address_digest) = 67", name="ck_familiar_address_digest_length"),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("account_id", "address_digest"),
    )
    op.create_index(
        "ix_familiar_address_owner_time",
        "account_familiar_addresses",
        ["account_id", "last_succeeded_at"],
    )
    op.create_index("ix_familiar_address_time", "account_familiar_addresses", ["last_succeeded_at"])


def downgrade() -> None:
    op.drop_table("account_familiar_addresses")
    op.drop_table("account_login_failure_overflow")
    op.drop_table("account_login_failures")
