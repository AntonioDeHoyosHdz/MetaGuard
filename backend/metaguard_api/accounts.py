"""Private account persistence schema; no registration or authentication endpoints."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from metaguard_api.database import Base


class UTCDateTime(TypeDecorator):
    """Keep timezone-aware UTC datetimes consistent on SQLite and PostgreSQL."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, _dialect) -> datetime | None:
        if value is None:
            return None
        if value.utcoffset() != timedelta(0):
            raise ValueError("Timestamp must be UTC")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, _dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Account(Base):
    __tablename__ = "accounts"
    __table_args__ = (
        CheckConstraint("length(email) BETWEEN 3 AND 254", name="ck_accounts_email_length"),
        CheckConstraint("email = lower(email)", name="ck_accounts_email_lowercase"),
        UniqueConstraint("email", name="uq_accounts_email"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    email_verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class EmailVerificationToken(Base):
    """One pending verification token per account, stored only as a digest."""

    __tablename__ = "email_verification_tokens"
    __table_args__ = (
        CheckConstraint("length(token_digest) = 64", name="ck_email_verification_digest_length"),
    )

    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True
    )
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class AccountSession(Base):
    """JWT session revocation record; only token and CSRF digests are persisted."""

    __tablename__ = "account_sessions"
    __table_args__ = (
        CheckConstraint(
            "length(token_digest) = 64", name="ck_account_sessions_token_digest_length"
        ),
        CheckConstraint("length(csrf_digest) = 64", name="ck_account_sessions_csrf_digest_length"),
        Index("ix_account_sessions_account_expires", "account_id", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    csrf_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
