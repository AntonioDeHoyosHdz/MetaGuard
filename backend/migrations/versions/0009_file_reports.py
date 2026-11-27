"""Persist minimized file reports and one-use download-token state.

Revision ID: 0009_file_reports
Revises: 0008_mfa_login_challenges
"""

import sqlalchemy as sa
from alembic import op

revision = "0009_file_reports"
down_revision = "0008_mfa_login_challenges"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "file_reports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("report_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("download_token_digest", sa.String(length=64), nullable=True),
        sa.Column("download_token_expires_at", sa.BigInteger(), nullable=True),
        sa.CheckConstraint("length(id) = 36", name="ck_file_reports_id_length"),
        sa.CheckConstraint("created_at >= 0", name="ck_file_reports_created_at"),
        sa.CheckConstraint("expires_at > created_at", name="ck_file_reports_expiry"),
        sa.CheckConstraint(
            "(download_token_digest IS NULL AND download_token_expires_at IS NULL) OR "
            "(length(download_token_digest) = 64 AND download_token_expires_at > 0)",
            name="ck_file_reports_download_token_pair",
        ),
        sa.ForeignKeyConstraint(["owner_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("download_token_digest", name="uq_file_reports_download_token_digest"),
    )
    op.create_index("ix_file_reports_owner_created", "file_reports", ["owner_id", "created_at"])
    op.create_index("ix_file_reports_expires_at", "file_reports", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_file_reports_expires_at", table_name="file_reports")
    op.drop_index("ix_file_reports_owner_created", table_name="file_reports")
    op.drop_table("file_reports")
