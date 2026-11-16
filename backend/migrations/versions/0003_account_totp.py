"""Add account-owned TOTP credential storage without enabling MFA.

Revision ID: 0003_account_totp
Revises: 0002_accounts
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_account_totp"
down_revision = "0002_accounts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "account_totp",
        sa.Column("account_id", sa.String(length=36), nullable=False),
        sa.Column("encrypted_secret", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("last_accepted_step", sa.BigInteger(), nullable=True),
        sa.CheckConstraint(
            "length(encrypted_secret) BETWEEN 30 AND 1053", name="ck_totp_secret_length"
        ),
        sa.CheckConstraint("key_version > 0", name="ck_totp_key_version"),
        sa.CheckConstraint(
            "last_accepted_step IS NULL OR last_accepted_step >= 0", name="ck_totp_step"
        ),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("account_id"),
    )


def downgrade() -> None:
    op.drop_table("account_totp")
