"""Add separate pending TOTP enrollment storage.

Revision ID: 0004_pending_totp
Revises: 0003_account_totp
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_pending_totp"
down_revision = "0003_account_totp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "pending_totp",
        sa.Column("account_id", sa.String(36), nullable=False),
        sa.Column("encrypted_secret", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            "length(encrypted_secret) BETWEEN 30 AND 1053", name="ck_pending_totp_secret_length"
        ),
        sa.CheckConstraint("key_version > 0", name="ck_pending_totp_key_version"),
        sa.CheckConstraint("expires_at > 0", name="ck_pending_totp_expiry"),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("account_id"),
    )


def downgrade() -> None:
    op.drop_table("pending_totp")
