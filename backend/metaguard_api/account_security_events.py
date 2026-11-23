"""Minimized account-visible history; separate from ownerless diagnostics."""

from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import BoundedSemaphore
from uuid import uuid4

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    delete,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import insert as insert_postgresql
from sqlalchemy.dialects.sqlite import insert as insert_sqlite
from sqlalchemy.orm import Mapped, Session, mapped_column
from starlette.background import BackgroundTask

from metaguard_api.database import Base

_RETENTION = timedelta(days=30)
_PACE_SECONDS = 600
_READ_LIMIT = 50
_WRITES = BoundedSemaphore(4)


class AccountSecurityEventKind(StrEnum):
    LOGIN_FAILED = "login_failed"
    MFA_FAILED = "mfa_failed"
    UPLOAD_TYPE_MISMATCH = "upload_type_mismatch"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    NEW_IP_LOGIN = "new_ip_login"
    DANGEROUS_CONTENT_DETECTED = "dangerous_content_detected"
    LEAKED_PASSWORD_REJECTED = "leaked_password_rejected"


_KIND_SQL = ", ".join(f"'{kind.value}'" for kind in AccountSecurityEventKind)


class AccountSecurityEvent(Base):
    __tablename__ = "account_security_events"
    __table_args__ = (
        CheckConstraint(f"kind IN ({_KIND_SQL})", name="ck_account_security_event_kind"),
        CheckConstraint(
            f"created_at >= 0 AND pace_window = created_at / {_PACE_SECONDS}",
            name="ck_account_security_event_pace_window",
        ),
        UniqueConstraint("account_id", "kind", "pace_window", name="uq_account_event_pace"),
        Index("ix_account_event_history", "account_id", "created_at", "id"),
        Index("ix_account_event_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    pace_window: Mapped[int] = mapped_column(BigInteger, nullable=False)


def save_account_event(
    session: Session, account_id: str, kind: AccountSecurityEventKind, *, now: datetime
) -> bool:
    """Persist the first event of each kind per owner in a ten-minute UTC window."""
    if not isinstance(kind, AccountSecurityEventKind):
        raise ValueError("Unsupported account security event")
    created_at = int(now.timestamp())
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert = insert_postgresql
    elif dialect == "sqlite":
        insert = insert_sqlite
    else:
        raise ValueError("Unsupported security event storage")
    statement = (
        insert(AccountSecurityEvent)
        .values(
            id=str(uuid4()),
            account_id=account_id,
            kind=kind.value,
            created_at=created_at,
            pace_window=created_at // _PACE_SECONDS,
        )
        .on_conflict_do_nothing(index_elements=["account_id", "kind", "pace_window"])
        .returning(AccountSecurityEvent.id)
    )
    return session.scalar(statement) is not None


def list_account_events(
    session: Session, account_id: str, *, now: datetime
) -> Sequence[AccountSecurityEvent]:
    cutoff = int((now - _RETENTION).timestamp())
    latest = int(now.timestamp())
    return session.scalars(
        select(AccountSecurityEvent)
        .where(
            AccountSecurityEvent.account_id == account_id,
            AccountSecurityEvent.created_at > cutoff,
            AccountSecurityEvent.created_at <= latest,
        )
        .order_by(AccountSecurityEvent.created_at.desc(), AccountSecurityEvent.id.desc())
        .limit(_READ_LIMIT)
    ).all()


def account_event_resource(event: AccountSecurityEvent) -> dict[str, str]:
    return {
        "kind": event.kind,
        "created_at": datetime.fromtimestamp(event.created_at, UTC).isoformat(),
    }


def purge_expired_account_events(session: Session, *, now: datetime) -> int:
    cutoff = int((now - _RETENTION).timestamp())
    result = session.execute(
        delete(AccountSecurityEvent).where(AccountSecurityEvent.created_at <= cutoff)
    )
    return result.rowcount


def record_account_event(
    begin: Callable[[], AbstractContextManager[Session]],
    account_id: str,
    kind: AccountSecurityEventKind,
    now: datetime,
) -> None:
    """Best effort in a fresh transaction, after the business response has been sent."""
    if not _WRITES.acquire(blocking=False):
        return
    try:
        with begin() as session:
            if session.get_bind().dialect.name == "postgresql":
                session.execute(text("SET LOCAL statement_timeout = '250ms'"))
            save_account_event(session, account_id, kind, now=now)
    except Exception:
        # No detail or owner identifier should escape through diagnostics or the response.
        pass
    finally:
        _WRITES.release()


def account_event_task(
    begin: Callable[[], AbstractContextManager[Session]],
    account_id: str,
    kind: AccountSecurityEventKind,
    now: datetime,
) -> BackgroundTask:
    return BackgroundTask(record_account_event, begin, account_id, kind, now)
