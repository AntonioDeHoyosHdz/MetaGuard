"""Private, owner-bound delivery queue for generic security notifications."""

from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import datetime, timedelta
from typing import Protocol
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    delete,
    literal,
    or_,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Mapped, Session, mapped_column

from metaguard_api.accounts import Account, UTCDateTime
from metaguard_api.database import Base

SECURITY_ALERT_SUBJECT = "MetaGuard | Alerta de seguridad"
SECURITY_ALERT_TEXT = (
    "Detectamos actividad inusual relacionada con tu cuenta de MetaGuard.\n\n"
    "Si no la reconoces, abre MetaGuard como lo haces normalmente y revisa "
    "el historial de seguridad de tu cuenta.\n"
    "No respondas a este correo ni compartas tus contraseñas o códigos.\n"
)

_COOLDOWN = timedelta(minutes=15)
_DELIVERY_TTL = timedelta(minutes=10)
_LEASE_DURATION = timedelta(minutes=2)
_RETRY_DELAYS = (timedelta(seconds=30), timedelta(minutes=1))
_MAX_ATTEMPTS = len(_RETRY_DELAYS) + 1
_MAX_BATCH = 10
_MAX_PURGE = 100


class SecurityAlertSender(Protocol):
    def send_security_alert(self, email: str) -> None: ...


class _SessionFactory(Protocol):
    def begin(self) -> AbstractContextManager[Session]: ...


class SecurityAlertOutbox(Base):
    """One row per owner; the row holds the cooldown after delivery has ended."""

    __tablename__ = "security_alert_outbox"
    __table_args__ = (
        CheckConstraint("attempts BETWEEN 0 AND 3", name="ck_security_alert_attempts"),
        Index("ix_security_alert_ready", "finished", "available_at", "account_id"),
        Index("ix_security_alert_cooldown", "cooldown_until", "account_id"),
    )

    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True
    )
    cooldown_until: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    available_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    lease_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    attempts: Mapped[int] = mapped_column(nullable=False)
    finished: Mapped[bool] = mapped_column(Boolean, nullable=False)


def enqueue_security_alert(session: Session, account_id: str, *, now: datetime) -> bool:
    """Accept a verified owner into the outbox; the caller owns commit/rollback."""
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert = postgres_insert
    elif dialect == "sqlite":
        insert = sqlite_insert
    else:
        raise ValueError("Unsupported security alert database dialect")

    cooldown = now + _COOLDOWN
    expires_at = now + _DELIVERY_TTL
    statement = insert(SecurityAlertOutbox).from_select(
        ["account_id", "cooldown_until", "expires_at", "available_at", "attempts", "finished"],
        select(
            Account.id,
            literal(cooldown, UTCDateTime()),
            literal(expires_at, UTCDateTime()),
            literal(now, UTCDateTime()),
            literal(0),
            literal(False),
        ).where(Account.id == account_id, Account.email_verified_at.is_not(None)),
    )
    statement = statement.on_conflict_do_update(
        index_elements=[SecurityAlertOutbox.account_id],
        set_={
            "cooldown_until": statement.excluded.cooldown_until,
            "expires_at": statement.excluded.expires_at,
            "available_at": statement.excluded.available_at,
            "lease_id": None,
            "attempts": 0,
            "finished": False,
        },
        where=(SecurityAlertOutbox.cooldown_until <= now)
        & or_(SecurityAlertOutbox.finished, SecurityAlertOutbox.expires_at <= now),
    ).returning(SecurityAlertOutbox.account_id)
    return session.scalar(statement) is not None


def _claim_batch(
    session: Session, *, now: datetime, size: int, lease_id: str
) -> list[tuple[str, int]]:
    ready = (
        SecurityAlertOutbox.finished.is_(False),
        SecurityAlertOutbox.attempts < _MAX_ATTEMPTS,
        SecurityAlertOutbox.available_at <= now,
        SecurityAlertOutbox.expires_at > now,
    )
    candidates = (
        select(SecurityAlertOutbox.account_id)
        .where(*ready)
        .order_by(SecurityAlertOutbox.available_at, SecurityAlertOutbox.account_id)
        .limit(size)
    )
    if session.get_bind().dialect.name == "postgresql":
        candidates = candidates.with_for_update(skip_locked=True)
    # On SQLite this is one write statement, not a read followed by a lock upgrade.
    claimed = session.execute(
        update(SecurityAlertOutbox)
        .where(SecurityAlertOutbox.account_id.in_(candidates), *ready)
        .values(
            lease_id=lease_id,
            available_at=now + _LEASE_DURATION,
            attempts=SecurityAlertOutbox.attempts + 1,
        )
        .returning(SecurityAlertOutbox.account_id, SecurityAlertOutbox.attempts)
    )
    return [(account_id, attempts) for account_id, attempts in claimed]


def _finish(
    session: Session,
    account_id: str,
    lease_id: str,
    attempts: int,
    *,
    now: datetime,
    delivered: bool,
    retry: bool,
) -> bool:
    patch = {"lease_id": None, "finished": not retry or attempts >= _MAX_ATTEMPTS}
    if not patch["finished"]:
        patch["available_at"] = now + _RETRY_DELAYS[attempts - 1]
    if delivered:
        patch["cooldown_until"] = now + _COOLDOWN
    # A later claimant may already own the row; an obsolete result cannot update it.
    result = session.execute(
        update(SecurityAlertOutbox)
        .where(
            SecurityAlertOutbox.account_id == account_id,
            SecurityAlertOutbox.lease_id == lease_id,
        )
        .values(**patch)
        .returning(SecurityAlertOutbox.account_id)
    )
    return result.scalar_one_or_none() is not None


def dispatch_security_alerts(
    session_factory: _SessionFactory,
    sender: SecurityAlertSender,
    *,
    now: datetime | Callable[[], datetime],
    batch_size: int = 4,
) -> int:
    """Deliver at most one bounded batch; pass a live clock for worker use.

    Claims and lookups commit before transport. A crash after SMTP accepts a
    message but before completion commits can cause bounded redelivery.
    """
    clock = now if callable(now) else lambda: now
    size = min(max(batch_size, 0), _MAX_BATCH)
    if size == 0:
        return 0
    lease_id = uuid4().hex
    claimed_at = clock()
    with session_factory.begin() as session:
        claimed = _claim_batch(session, now=claimed_at, size=size, lease_id=lease_id)

    accepted = 0
    for account_id, attempts in claimed:
        current = max(claimed_at, clock())
        with session_factory.begin() as session:
            recipient = session.execute(
                select(Account.email)
                .select_from(SecurityAlertOutbox)
                .outerjoin(
                    Account,
                    (Account.id == SecurityAlertOutbox.account_id)
                    & Account.email_verified_at.is_not(None),
                )
                .where(
                    SecurityAlertOutbox.account_id == account_id,
                    SecurityAlertOutbox.lease_id == lease_id,
                    SecurityAlertOutbox.available_at > current,
                    SecurityAlertOutbox.expires_at > current,
                )
            ).one_or_none()
        if recipient is None:
            continue
        (email,) = recipient
        delivered = False
        if email is not None:
            try:
                sender.send_security_alert(email)
                delivered = True
            except Exception:
                # SMTP errors may contain provider credentials or recipient data.
                pass
        with session_factory.begin() as session:
            recorded = _finish(
                session,
                account_id,
                lease_id,
                attempts,
                # A wall-clock rollback must not shorten cooldown or make retries immediate.
                now=max(current, clock()),
                delivered=delivered,
                retry=email is not None and not delivered,
            )
        if delivered and recorded:
            accepted += 1
    return accepted


def purge_expired_security_alerts(session: Session, *, now: datetime) -> int:
    """Delete at most one batch of expired rows without weakening owner cooldowns."""
    expired = SecurityAlertOutbox.expires_at <= now, SecurityAlertOutbox.cooldown_until <= now
    candidates = (
        select(SecurityAlertOutbox.account_id)
        .where(*expired)
        .order_by(SecurityAlertOutbox.cooldown_until, SecurityAlertOutbox.account_id)
        .limit(_MAX_PURGE)
    )
    if session.get_bind().dialect.name == "postgresql":
        candidates = candidates.with_for_update(skip_locked=True)
    result = session.execute(
        delete(SecurityAlertOutbox).where(SecurityAlertOutbox.account_id.in_(candidates), *expired)
    )
    return result.rowcount
