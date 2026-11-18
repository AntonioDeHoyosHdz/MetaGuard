"""Add digest-only opaque account sessions and bound CSRF tokens.

Revision ID: 0007_account_sessions
Revises: 0006_email_verification
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_account_sessions"
down_revision = "0006_email_verification"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "account_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("account_id", sa.String(length=36), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("csrf_digest", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "length(token_digest) = 64", name="ck_account_sessions_token_digest_length"
        ),
        sa.CheckConstraint(
            "length(csrf_digest) = 64", name="ck_account_sessions_csrf_digest_length"
        ),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_digest", name="uq_account_sessions_token_digest"),
    )
    op.create_index(
        "ix_account_sessions_account_expires",
        "account_sessions",
        ["account_id", "expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_account_sessions_account_expires", table_name="account_sessions")
    op.drop_table("account_sessions")
