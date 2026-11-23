"""Persist single-use email login step-up proofs.

Revision ID: 0016_login_email_challenge
Revises: 0015_login_risk
"""

import sqlalchemy as sa
from alembic import op

revision = "0016_login_email_challenge"
down_revision = "0015_login_risk"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "login_email_challenges",
        sa.Column("account_id", sa.String(36), nullable=False),
        sa.Column("csrf_digest", sa.String(64), nullable=False),
        sa.Column("address_digest", sa.String(67), nullable=False),
        sa.Column("code_digest", sa.String(64), nullable=False),
        sa.Column("password_version", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(csrf_digest) = 64", name="ck_login_email_csrf_length"),
        sa.CheckConstraint("length(address_digest) = 67", name="ck_login_email_address_length"),
        sa.CheckConstraint("length(code_digest) = 64", name="ck_login_email_code_length"),
        sa.CheckConstraint("length(password_version) = 64", name="ck_login_email_password_length"),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("account_id", "csrf_digest", "address_digest"),
    )
    op.create_index("ix_login_email_challenge_expires", "login_email_challenges", ["expires_at"])


def downgrade() -> None:
    op.drop_table("login_email_challenges")
