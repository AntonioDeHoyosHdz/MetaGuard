"""Digest-only email step-up proofs, issued only for a verified first factor."""

import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from hashlib import sha256

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, delete, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from metaguard_api.accounts import Account, UTCDateTime
from metaguard_api.database import Base

LOGIN_EMAIL_CODE_PATTERN = re.compile(r"[0-9a-f]{32}")
LOGIN_EMAIL_CODE_MINUTES = 5
_LIVE_LIMIT = 8


class LoginEmailChallenge(Base):
    __tablename__ = "login_email_challenges"
    __table_args__ = (
        CheckConstraint("length(csrf_digest) = 64", name="ck_login_email_csrf_length"),
        CheckConstraint("length(address_digest) = 67", name="ck_login_email_address_length"),
        CheckConstraint("length(code_digest) = 64", name="ck_login_email_code_length"),
        CheckConstraint("length(password_version) = 64", name="ck_login_email_password_length"),
        Index("ix_login_email_challenge_expires", "expires_at"),
    )

    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True
    )
    csrf_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    address_digest: Mapped[str] = mapped_column(String(67), primary_key=True)
    code_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    password_version: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


@dataclass(frozen=True, slots=True)
class PreparedLoginEmail:
    # No raw code is recoverable when the same browser already has a pending proof.
    code: str | None = field(repr=False)


class LoginEmailProof(Enum):
    REJECTED = auto()
    INVALID_CODE = auto()
    VERIFIED = auto()


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _password_version(account: Account) -> str:
    return _digest("metaguard:login-email:password:v1:" + account.password_hash)


def prepare_login_email_challenge(
    session: Session,
    account: Account,
    csrf_token: str,
    address_digest: str,
    *,
    now: datetime,
) -> PreparedLoginEmail | None:
    """Caller holds the Account lock and already verified the password."""
    if account.email_verified_at is None:
        return None
    challenge = LoginEmailChallenge
    session.execute(
        delete(challenge).where(challenge.account_id == account.id, challenge.expires_at <= now)
    )
    csrf_digest = _digest(csrf_token)
    existing = session.get(
        challenge, (account.id, csrf_digest, address_digest), with_for_update=True
    )
    version = _password_version(account)
    if existing is not None and hmac.compare_digest(existing.password_version, version):
        return PreparedLoginEmail(None)
    if (
        existing is None
        and session.scalar(
            select(func.count()).select_from(challenge).where(challenge.account_id == account.id)
        )
        >= _LIVE_LIMIT
    ):
        return None
    code = secrets.token_hex(16)
    expires_at = now + timedelta(minutes=LOGIN_EMAIL_CODE_MINUTES)
    if existing is None:
        session.add(
            challenge(
                account_id=account.id,
                csrf_digest=csrf_digest,
                address_digest=address_digest,
                code_digest=_digest(code),
                password_version=version,
                expires_at=expires_at,
            )
        )
    else:
        existing.code_digest = _digest(code)
        existing.password_version = version
        existing.expires_at = expires_at
    return PreparedLoginEmail(code)


def _active_login_email_challenge(
    session: Session,
    account: Account,
    csrf_token: str,
    address_digest: str,
    *,
    now: datetime,
) -> LoginEmailChallenge | None:
    if account.email_verified_at is None:
        return None
    challenge = session.get(
        LoginEmailChallenge, (account.id, _digest(csrf_token), address_digest), with_for_update=True
    )
    if (
        challenge is None
        or challenge.expires_at <= now
        or not hmac.compare_digest(challenge.password_version, _password_version(account))
    ):
        return None
    return challenge


def has_active_login_email_challenge(
    session: Session,
    account: Account,
    csrf_token: str,
    address_digest: str,
    *,
    now: datetime,
) -> bool:
    """Check the same binding as consumption, without altering the proof."""
    return (
        _active_login_email_challenge(session, account, csrf_token, address_digest, now=now)
        is not None
    )


def consume_login_email_challenge(
    session: Session,
    account: Account,
    csrf_token: str,
    address_digest: str,
    code: str,
    *,
    now: datetime,
) -> LoginEmailProof:
    """A successful deletion remains provisional until session issuance commits."""
    challenge = _active_login_email_challenge(session, account, csrf_token, address_digest, now=now)
    if challenge is None:
        return LoginEmailProof.REJECTED
    if LOGIN_EMAIL_CODE_PATTERN.fullmatch(code) is None or not hmac.compare_digest(
        challenge.code_digest, _digest(code)
    ):
        return LoginEmailProof.INVALID_CODE
    session.delete(challenge)
    return LoginEmailProof.VERIFIED


def purge_expired_login_email_challenges(session: Session, *, now: datetime) -> int:
    return session.execute(
        delete(LoginEmailChallenge).where(LoginEmailChallenge.expires_at <= now)
    ).rowcount
