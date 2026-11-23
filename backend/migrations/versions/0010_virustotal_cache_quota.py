"""Cache minimized VirusTotal summaries and shared request quotas.

Revision ID: 0010_virustotal_cache_quota
Revises: 0009_file_reports
"""

import sqlalchemy as sa
from alembic import op

revision = "0010_virustotal_cache_quota"
down_revision = "0009_file_reports"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("reputation_cache") as batch_op:
        batch_op.add_column(sa.Column("analysis_stats_json", sa.String(256), nullable=True))
        batch_op.add_column(sa.Column("last_analysis_date", sa.BigInteger(), nullable=True))
        batch_op.create_check_constraint(
            "ck_reputation_stats_size",
            "analysis_stats_json IS NULL OR length(analysis_stats_json) <= 256",
        )
    op.create_table(
        "virustotal_request_quota",
        sa.Column("id", sa.SmallInteger(), nullable=False),
        sa.Column("recent_1", sa.BigInteger(), nullable=True),
        sa.Column("recent_2", sa.BigInteger(), nullable=True),
        sa.Column("recent_3", sa.BigInteger(), nullable=True),
        sa.Column("recent_4", sa.BigInteger(), nullable=True),
        sa.Column("day_window", sa.BigInteger(), nullable=False),
        sa.Column("day_count", sa.SmallInteger(), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_virustotal_quota_singleton"),
        sa.CheckConstraint("day_count BETWEEN 0 AND 500", name="ck_virustotal_day_count"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("virustotal_request_quota")
    with op.batch_alter_table("reputation_cache") as batch_op:
        batch_op.drop_constraint("ck_reputation_stats_size", type_="check")
        batch_op.drop_column("last_analysis_date")
        batch_op.drop_column("analysis_stats_json")
