"""Persist only account-owned recovery code digests for MFA.

Revision ID: 0011_mfa_recovery_codes
Revises: 0010_virustotal_cache_quota
"""

import sqlalchemy as sa
from alembic import op

revision = "0011_mfa_recovery_codes"
down_revision = "0010_virustotal_cache_quota"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mfa_recovery_codes",
        sa.Column("account_id", sa.String(36), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.CheckConstraint("length(digest) = 64", name="ck_mfa_recovery_codes_digest_length"),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("account_id", "digest"),
    )


def downgrade() -> None:
    op.drop_table("mfa_recovery_codes")
