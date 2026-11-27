"""Minimized system security events; no user data or request payloads."""

from enum import StrEnum
from uuid import uuid4

from sqlalchemy import BigInteger, CheckConstraint, Index, String, delete
from sqlalchemy.orm import Mapped, Session, mapped_column

from metaguard_api.database import Base, Database

_RETENTION_SECONDS = 30 * 24 * 60 * 60


class SecurityEventType(StrEnum):
    PASSWORD_BREACH_CHECK_UNAVAILABLE = "password_breach_check_unavailable"


class SystemSecurityEvent(Base):
    __tablename__ = "system_security_events"
    __table_args__ = (
        CheckConstraint(
            "event_type IN ('password_breach_check_unavailable')",
            name="ck_system_security_event_type",
        ),
        CheckConstraint("created_at >= 0", name="ck_system_security_event_time"),
        Index("ix_system_security_events_created_at", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


def _validate_time(now: int) -> int:
    if type(now) is not int or not 0 <= now <= 2**63 - 1:
        raise ValueError("Expected a valid UTC epoch timestamp")
    return now


def record_event(session: Session, event_type: SecurityEventType, *, now: int) -> None:
    """Record only approved generic events; caller commits or rolls back."""
    timestamp = _validate_time(now)
    if not isinstance(event_type, SecurityEventType):
        raise ValueError("Unsupported security event type")
    session.add(
        SystemSecurityEvent(id=str(uuid4()), event_type=event_type.value, created_at=timestamp)
    )
    session.flush()


def purge_expired_events(session: Session, *, now: int) -> int:
    """Remove events at least 30 days old; caller controls the transaction."""
    cutoff = _validate_time(now) - _RETENTION_SECONDS
    if cutoff < 0:
        return 0
    result = session.execute(
        delete(SystemSecurityEvent).where(SystemSecurityEvent.created_at <= cutoff)
    )
    return result.rowcount


def record_password_check_outage(database: Database, event: str, *, now: int) -> None:
    """Commit an approved outage event separately from any account transaction."""
    if event != SecurityEventType.PASSWORD_BREACH_CHECK_UNAVAILABLE.value:
        raise ValueError("Unsupported security event type")
    with database.transaction() as session:
        record_event(session, SecurityEventType.PASSWORD_BREACH_CHECK_UNAVAILABLE, now=now)
