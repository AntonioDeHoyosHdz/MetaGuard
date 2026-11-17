"""Add account email verification state and one-use token storage.

Revision ID: 0006_email_verification
Revises: 0005_system_security_events
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_email_verification"
down_revision = "0005_system_security_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "accounts",
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "email_verification_tokens",
        sa.Column("account_id", sa.String(length=36), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(token_digest) = 64", name="ck_email_verification_digest_length"),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("account_id"),
        sa.UniqueConstraint("token_digest", name="uq_email_verification_token_digest"),
    )


def downgrade() -> None:
    op.drop_table("email_verification_tokens")
    op.drop_column("accounts", "email_verified_at")
