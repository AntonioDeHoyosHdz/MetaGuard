"""Persist digest-only, CSRF-bound one-use MFA login challenges.

Revision ID: 0008_mfa_login_challenges
Revises: 0007_account_sessions
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_mfa_login_challenges"
down_revision = "0007_account_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mfa_login_challenges",
        sa.Column("challenge_digest", sa.String(length=64), nullable=False),
        sa.Column("account_id", sa.String(length=36), nullable=False),
        sa.Column("csrf_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(challenge_digest) = 64", name="ck_mfa_login_challenge_digest_length"
        ),
        sa.CheckConstraint("length(csrf_digest) = 64", name="ck_mfa_login_csrf_digest_length"),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("challenge_digest"),
    )
    op.create_index(
        "ix_mfa_login_challenges_expires_at",
        "mfa_login_challenges",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_mfa_login_challenges_expires_at", table_name="mfa_login_challenges")
    op.drop_table("mfa_login_challenges")
