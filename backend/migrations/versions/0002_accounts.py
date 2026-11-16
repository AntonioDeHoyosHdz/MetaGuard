"""Add account persistence without enabling authentication.

Revision ID: 0002_accounts
Revises: 0001_reputation_cache
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_accounts"
down_revision = "0001_reputation_cache"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "accounts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.CheckConstraint("length(email) BETWEEN 3 AND 254", name="ck_accounts_email_length"),
        sa.CheckConstraint("email = lower(email)", name="ck_accounts_email_lowercase"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email", name="uq_accounts_email"),
    )


def downgrade() -> None:
    op.drop_table("accounts")
