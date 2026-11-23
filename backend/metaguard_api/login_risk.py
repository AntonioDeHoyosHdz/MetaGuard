"""Account-bound login risk and address familiarity without storing network addresses.

Call the login helpers inside the authentication transaction, holding the canonical
Account row lock, with an aware UTC timestamp sampled after acquiring that lock.
They never commit or interpret proxy headers. SQLite tests do not model PostgreSQL
row-lock concurrency. Call maintenance separately in its own transaction.
"""

import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv6Address, ip_address

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, delete, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from metaguard_api.accounts import UTCDateTime
from metaguard_api.database import Base

_ADDRESS_KEY_CONTEXT = b"metaguard:login-risk:address-key:v1"
_FAILURES_PER_LOCK = 5
_LOCK_MINUTES = (1, 5, 15)
_MULTI_ADDRESS_THRESHOLD = 3
_MULTI_ADDRESS_WINDOW = timedelta(minutes=15)
_RETENTION = timedelta(days=30)
MAX_LOGIN_FAILURE_ADDRESSES = 64
MAX_FAMILIAR_ADDRESSES = 32


class AccountLoginFailure(Base):
    __tablename__ = "account_login_failures"
    __table_args__ = (
        CheckConstraint("length(address_digest) = 67", name="ck_login_failure_digest_length"),
        CheckConstraint("consecutive_failures BETWEEN 0 AND 4", name="ck_login_failure_streak"),
        CheckConstraint("lock_level BETWEEN 0 AND 3", name="ck_login_failure_lock_level"),
        Index("ix_login_failure_owner_time", "account_id", "last_failed_at"),
        Index("ix_login_failure_time", "last_failed_at"),
    )

    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True
    )
    address_digest: Mapped[str] = mapped_column(String(67), primary_key=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer(), nullable=False)
    lock_level: Mapped[int] = mapped_column(Integer(), nullable=False)
    last_failed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class AccountLoginFailureOverflow(Base):
    """Retain recent multi-address risk if every tracked failure slot is still active."""

    __tablename__ = "account_login_failure_overflow"
    __table_args__ = (Index("ix_login_failure_overflow_expires", "expires_at"),)

    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True
    )
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class AccountFamiliarAddress(Base):
    __tablename__ = "account_familiar_addresses"
    __table_args__ = (
        CheckConstraint("length(address_digest) = 67", name="ck_familiar_address_digest_length"),
        Index("ix_familiar_address_owner_time", "account_id", "last_succeeded_at"),
        Index("ix_familiar_address_time", "last_succeeded_at"),
    )

    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True
    )
    address_digest: Mapped[str] = mapped_column(String(67), primary_key=True)
    last_succeeded_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


@dataclass(frozen=True, slots=True)
class LoginRisk:
    locked_until: datetime | None
    step_up: bool


def login_address_digest(account_id: str, client_ip: str | None, signing_key: str) -> str | None:
    """Pseudonymize only a trusted, plain IP literal; unmapped identities are not stored.

    Changing the signing key makes older digests unlinkable to newly presented addresses.
    """
    if not isinstance(client_ip, str) or "%" in client_ip:
        return None
    try:
        address = ip_address(client_ip)
    except ValueError:
        return None
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_unspecified:
        return None
    key = hmac.digest(signing_key.encode("utf-8"), _ADDRESS_KEY_CONTEXT, "sha256")
    owner = account_id.encode("utf-8")
    message = len(owner).to_bytes(4, "big") + owner + bytes([address.version]) + address.packed
    return "v1:" + hmac.digest(key, message, "sha256").hex()


def assess_login_risk(
    session: Session, account_id: str, address_digest: str | None, *, now: datetime
) -> LoginRisk:
    """Use a pair lock before authentication; use step_up only after valid credentials."""
    locked_until = None
    if address_digest is not None:
        locked_until = session.scalar(
            select(AccountLoginFailure.locked_until).where(
                AccountLoginFailure.account_id == account_id,
                AccountLoginFailure.address_digest == address_digest,
                AccountLoginFailure.locked_until > now,
            )
        )
    overflow_until = session.scalar(
        select(AccountLoginFailureOverflow.expires_at).where(
            AccountLoginFailureOverflow.account_id == account_id,
            AccountLoginFailureOverflow.expires_at > now,
        )
    )
    if overflow_until is not None:
        return LoginRisk(locked_until, step_up=True)
    recent_pairs = session.scalars(
        select(AccountLoginFailure.address_digest)
        .where(
            AccountLoginFailure.account_id == account_id,
            AccountLoginFailure.last_failed_at > now - _MULTI_ADDRESS_WINDOW,
        )
        .limit(_MULTI_ADDRESS_THRESHOLD)
    ).all()
    return LoginRisk(locked_until, step_up=len(recent_pairs) == _MULTI_ADDRESS_THRESHOLD)


def _make_failure_slot(session: Session, account_id: str, now: datetime) -> bool:
    state = AccountLoginFailure
    count = session.scalar(
        select(func.count()).select_from(state).where(state.account_id == account_id)
    )
    if count < MAX_LOGIN_FAILURE_ADDRESSES:
        return True

    oldest_inactive = session.scalar(
        select(state)
        .where(
            state.account_id == account_id,
            state.last_failed_at <= now - _MULTI_ADDRESS_WINDOW,
            (state.locked_until.is_(None) | (state.locked_until <= now)),
        )
        .order_by(state.last_failed_at, state.address_digest)
        .limit(1)
        .with_for_update()
    )
    if oldest_inactive is not None:
        session.delete(oldest_inactive)
        return True

    # Do not let a new address evict a real lock or make the rolling evidence vanish.
    overflow = session.get(AccountLoginFailureOverflow, account_id, with_for_update=True)
    expires_at = now + _MULTI_ADDRESS_WINDOW
    if overflow is None:
        session.add(AccountLoginFailureOverflow(account_id=account_id, expires_at=expires_at))
    else:
        overflow.expires_at = expires_at
    return False


def record_login_failure(
    session: Session, account_id: str, address_digest: str | None, *, now: datetime
) -> LoginRisk:
    """Record a failed login proof against its trusted address, unless already locked."""
    if address_digest is None:
        return assess_login_risk(session, account_id, None, now=now)
    state = session.get(AccountLoginFailure, (account_id, address_digest), with_for_update=True)
    if state is None:
        if not _make_failure_slot(session, account_id, now):
            return assess_login_risk(session, account_id, address_digest, now=now)
        state = AccountLoginFailure(
            account_id=account_id,
            address_digest=address_digest,
            consecutive_failures=0,
            lock_level=0,
            last_failed_at=now,
        )
        session.add(state)
    elif state.locked_until is not None and state.locked_until > now:
        return assess_login_risk(session, account_id, address_digest, now=now)
    elif state.last_failed_at <= now - _RETENTION:
        state.consecutive_failures = state.lock_level = 0
        state.locked_until = None

    state.last_failed_at = now
    state.consecutive_failures += 1
    if state.consecutive_failures == _FAILURES_PER_LOCK:
        state.consecutive_failures = 0
        state.lock_level = min(state.lock_level + 1, len(_LOCK_MINUTES))
        state.locked_until = now + timedelta(minutes=_LOCK_MINUTES[state.lock_level - 1])

    return assess_login_risk(session, account_id, address_digest, now=now)


def record_login_success(
    session: Session, account_id: str, address_digest: str | None, *, now: datetime
) -> bool:
    """Reset the successful pair and return whether this completed login used a new address."""
    if address_digest is None:
        return False
    session.execute(
        delete(AccountLoginFailure).where(
            AccountLoginFailure.account_id == account_id,
            AccountLoginFailure.address_digest == address_digest,
        )
    )
    familiar = session.get(
        AccountFamiliarAddress, (account_id, address_digest), with_for_update=True
    )
    cutoff = now - _RETENTION
    if familiar is not None and familiar.last_succeeded_at > cutoff:
        familiar.last_succeeded_at = now
        return False

    addresses = AccountFamiliarAddress
    has_previous = (
        session.scalar(
            select(addresses.address_digest)
            .where(addresses.account_id == account_id, addresses.last_succeeded_at > cutoff)
            .limit(1)
        )
        is not None
    )
    if familiar is not None:
        familiar.last_succeeded_at = now
        return has_previous

    count = session.scalar(
        select(func.count()).select_from(addresses).where(addresses.account_id == account_id)
    )
    if count >= MAX_FAMILIAR_ADDRESSES:
        oldest = session.scalar(
            select(addresses)
            .where(addresses.account_id == account_id)
            .order_by(addresses.last_succeeded_at, addresses.address_digest)
            .limit(1)
            .with_for_update()
        )
        if oldest is not None:
            session.delete(oldest)
    session.add(
        AccountFamiliarAddress(
            account_id=account_id, address_digest=address_digest, last_succeeded_at=now
        )
    )
    return has_previous


def purge_login_risk(session: Session, *, now: datetime) -> int:
    """Delete expired pair and familiarity state plus obsolete overflow markers."""
    cutoff = now - _RETENTION
    # Keep the same write order as authentication when deleting across tables.
    failures = session.execute(
        delete(AccountLoginFailure).where(AccountLoginFailure.last_failed_at <= cutoff)
    )
    overflow = session.execute(
        delete(AccountLoginFailureOverflow).where(AccountLoginFailureOverflow.expires_at <= now)
    )
    familiar = session.execute(
        delete(AccountFamiliarAddress).where(AccountFamiliarAddress.last_succeeded_at <= cutoff)
    )
    return failures.rowcount + overflow.rowcount + familiar.rowcount
