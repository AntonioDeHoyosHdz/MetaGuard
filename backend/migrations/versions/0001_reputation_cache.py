"""Add a minimal, unlinked reputation cache.

Revision ID: 0001_reputation_cache
Revises: None
"""

import sqlalchemy as sa
from alembic import op

revision = "0001_reputation_cache"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "reputation_cache",
        sa.Column("digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("length(digest) = 32", name="ck_reputation_digest_length"),
        sa.CheckConstraint(
            "verdict IN ('malicious', 'suspicious', 'undetected', 'no_record')",
            name="ck_reputation_verdict",
        ),
        sa.PrimaryKeyConstraint("digest"),
    )
    op.create_index("ix_reputation_cache_expires_at", "reputation_cache", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_reputation_cache_expires_at", table_name="reputation_cache")
    op.drop_table("reputation_cache")
