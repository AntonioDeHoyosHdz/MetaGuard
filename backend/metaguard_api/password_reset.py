"""Account-owned, digest-only password reset proofs and transactional confirmation."""

import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hashlib import sha256

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    delete,
    func,
    select,
    text,
    update,
)
from sqlalchemy.orm import Mapped, Session, mapped_column

from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account, AccountSession, UTCDateTime
from metaguard_api.database import Base
from metaguard_api.mfa_lifecycle import check_password_reset_recovery_code
from metaguard_api.pending_totp import PendingTotp
from metaguard_api.sessions import MfaLoginChallenge
from metaguard_api.totp_verification import consume_totp, is_totp_usable

RESET_CODE_PATTERN = re.compile(r"[0-9a-f]{32}")
RESET_CODE_MINUTES = 15
_MAX_LIVE_PROOFS = 3


class PasswordResetProof(Base):
    __tablename__ = "password_reset_proofs"
    __table_args__ = (
        CheckConstraint("length(digest) = 64", name="ck_password_reset_digest_length"),
        CheckConstraint("length(password_version) = 64", name="ck_password_reset_version_length"),
        Index("ix_password_reset_account_expires", "account_id", "expires_at"),
        Index("ix_password_reset_expires", "expires_at"),
    )

    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    password_version: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


@dataclass(frozen=True, slots=True)
class PasswordResetCandidate:
    """Optimistic proof snapshot; only the locked recheck can authorize mutation."""

    account_id: str
    password_hash: str = field(repr=False)


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _verified_account(email: str):
    return Account.email == email, Account.email_verified_at.is_not(None)


def _lock_account(session: Session, email: str) -> Account | None:
    verified = _verified_account(email)
    if session.get_bind().dialect.name == "sqlite":
        # SQLite has no row-level FOR UPDATE. Make the first account operation a write.
        return session.scalar(
            update(Account)
            .where(*verified)
            .values(password_hash=Account.password_hash)
            .returning(Account)
        )
    return session.scalar(select(Account).where(*verified).with_for_update())


def bound_password_reset_transaction(session: Session) -> None:
    if session.get_bind().dialect.name == "postgresql":
        session.execute(text("SET LOCAL statement_timeout = '5000ms'"))


def _checked_time(clock: Callable[[], datetime | None]) -> datetime:
    now = clock()
    if now is None:
        raise RuntimeError("Authentication clock is unavailable")
    return now


def prepare_password_reset(
    session: Session, email: str, *, clock: Callable[[], datetime | None]
) -> str | None:
    """Return a new raw code to deliver only once the issuing transaction commits."""
    account = _lock_account(session, email)
    if account is None:
        return None
    now = _checked_time(clock)
    purge_password_reset_proofs(session, now=now, account_id=account.id)
    if (
        session.scalar(
            select(func.count())
            .select_from(PasswordResetProof)
            .where(PasswordResetProof.account_id == account.id)
        )
        >= _MAX_LIVE_PROOFS
    ):
        return None

    code = secrets.token_hex(16)
    session.add(
        PasswordResetProof(
            digest=_digest(code),
            account_id=account.id,
            password_version=_digest(account.password_hash),
            expires_at=now + timedelta(minutes=RESET_CODE_MINUTES),
        )
    )
    return code


def _proof(session: Session, account: Account, code: str, *, lock: bool):
    statement = select(PasswordResetProof).where(
        PasswordResetProof.digest == _digest(code),
        PasswordResetProof.account_id == account.id,
        PasswordResetProof.password_version == _digest(account.password_hash),
    )
    return session.scalar(statement.with_for_update() if lock else statement)


def _mfa_proven(
    session: Session,
    account_id: str,
    code: str | None,
    *,
    key: bytes,
    key_version: int,
    now: datetime,
    consume: bool,
) -> bool:
    enrolled = session.scalar(
        select(AccountTotp.account_id).where(AccountTotp.account_id == account_id)
    )
    if enrolled is None:
        return True
    if code is None:
        return False
    if len(code) == 6:
        verify = consume_totp if consume else is_totp_usable
        return verify(
            session, account_id, code, key=key, key_version=key_version, now=int(now.timestamp())
        )
    return check_password_reset_recovery_code(session, account_id, code, consume=consume)


def precheck_password_reset(
    session: Session,
    email: str,
    code: str,
    mfa_code: str | None,
    *,
    key: bytes,
    key_version: int,
    clock: Callable[[], datetime | None],
) -> PasswordResetCandidate | None:
    """Check both proofs without locks before expensive screening; never confer authority."""
    if RESET_CODE_PATTERN.fullmatch(code) is None:
        return None
    account = session.scalar(select(Account).where(*_verified_account(email)))
    if account is None:
        return None
    proof = _proof(session, account, code, lock=False)
    now = _checked_time(clock)
    if proof is None or proof.expires_at <= now:
        return None
    if not _mfa_proven(
        session, account.id, mfa_code, key=key, key_version=key_version, now=now, consume=False
    ):
        return None
    return PasswordResetCandidate(account.id, account.password_hash)


def confirm_password_reset(
    session: Session,
    email: str,
    code: str,
    mfa_code: str | None,
    *,
    candidate: PasswordResetCandidate,
    new_hash: str,
    key: bytes,
    key_version: int,
    clock: Callable[[], datetime | None],
) -> bool:
    """Confirm both proofs anew under lock; commit password and revocation together."""
    account = _lock_account(session, email)
    if (
        account is None
        or account.id != candidate.account_id
        or account.password_hash != candidate.password_hash
    ):
        return False
    proof = _proof(session, account, code, lock=True)
    now = _checked_time(clock)
    if proof is None or proof.expires_at <= now:
        return False
    if not _mfa_proven(
        session, account.id, mfa_code, key=key, key_version=key_version, now=now, consume=True
    ):
        return False

    account.password_hash = new_hash
    invalidate_password_resets(session, account.id)
    session.execute(
        update(AccountSession)
        .where(AccountSession.account_id == account.id, AccountSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    session.execute(delete(MfaLoginChallenge).where(MfaLoginChallenge.account_id == account.id))
    session.execute(delete(PendingTotp).where(PendingTotp.account_id == account.id))
    return True


def invalidate_password_resets(session: Session, account_id: str) -> None:
    session.execute(delete(PasswordResetProof).where(PasswordResetProof.account_id == account_id))


def purge_password_reset_proofs(
    session: Session, *, now: datetime, account_id: str | None = None
) -> int:
    expired = delete(PasswordResetProof).where(PasswordResetProof.expires_at <= now)
    if account_id is not None:
        expired = expired.where(PasswordResetProof.account_id == account_id)
    return session.execute(expired).rowcount
