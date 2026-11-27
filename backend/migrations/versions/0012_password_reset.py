"""Persist expiring, account-owned password reset proof digests.

Revision ID: 0012_password_reset
Revises: 0011_mfa_recovery_codes
"""

import sqlalchemy as sa
from alembic import op

revision = "0012_password_reset"
down_revision = "0011_mfa_recovery_codes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "password_reset_proofs",
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(36), nullable=False),
        sa.Column("password_version", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(digest) = 64", name="ck_password_reset_digest_length"),
        sa.CheckConstraint(
            "length(password_version) = 64", name="ck_password_reset_version_length"
        ),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("digest"),
    )
    op.create_index(
        "ix_password_reset_account_expires", "password_reset_proofs", ["account_id", "expires_at"]
    )
    op.create_index("ix_password_reset_expires", "password_reset_proofs", ["expires_at"])
    op.add_column(
        "mfa_recovery_codes",
        sa.Column("password_reset_used", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("mfa_recovery_codes", "password_reset_used")
    op.drop_table("password_reset_proofs")
