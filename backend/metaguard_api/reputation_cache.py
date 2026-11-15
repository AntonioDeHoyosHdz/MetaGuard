"""Minimal, unlinked reputation cache; no file bytes or provider payloads."""

import re
from enum import StrEnum

from sqlalchemy import BigInteger, CheckConstraint, Index, LargeBinary, String, delete, select
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Mapped, Session, mapped_column

from metaguard_api.database import Base

_TTL_SECONDS = 24 * 60 * 60
_MAX_TIME = (2**63) - 1 - _TTL_SECONDS


class CacheVerdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNDETECTED = "undetected"
    NO_RECORD = "no_record"


class ReputationEntry(Base):
    __tablename__ = "reputation_cache"
    __table_args__ = (
        CheckConstraint("length(digest) = 32", name="ck_reputation_digest_length"),
        CheckConstraint(
            "verdict IN ('malicious', 'suspicious', 'undetected', 'no_record')",
            name="ck_reputation_verdict",
        ),
        Index("ix_reputation_cache_expires_at", "expires_at"),
    )

    digest: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


def _digest(value: str) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("Expected a lowercase SHA-256 digest")
    return bytes.fromhex(value)


def _time(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_TIME:
        raise ValueError("Expected a valid UTC epoch timestamp")
    return value


def save_verdict(session: Session, digest: str, verdict: CacheVerdict, *, now: int) -> None:
    """Atomically insert or refresh a verdict within the caller's transaction."""
    digest_bytes = _digest(digest)
    expires_at = _time(now) + _TTL_SECONDS
    if not isinstance(verdict, CacheVerdict):
        raise ValueError("Expected a supported cache verdict")
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert = postgres_insert
    elif dialect == "sqlite":
        insert = sqlite_insert
    else:
        raise ValueError("Unsupported database dialect")
    statement = insert(ReputationEntry).values(
        digest=digest_bytes, verdict=verdict.value, expires_at=expires_at
    )
    statement = statement.on_conflict_do_update(
        index_elements=[ReputationEntry.digest],
        set_={"verdict": statement.excluded.verdict, "expires_at": statement.excluded.expires_at},
        where=ReputationEntry.expires_at < statement.excluded.expires_at,
    )
    session.execute(statement)


def get_verdict(session: Session, digest: str, *, now: int) -> CacheVerdict | None:
    """Return a non-expired verdict; an expired entry is never returned."""
    value = session.scalar(
        select(ReputationEntry.verdict).where(
            ReputationEntry.digest == _digest(digest), ReputationEntry.expires_at > _time(now)
        )
    )
    return CacheVerdict(value) if value is not None else None


def purge_expired(session: Session, *, now: int) -> int:
    """Delete expired entries within the caller's transaction."""
    result = session.execute(
        delete(ReputationEntry).where(ReputationEntry.expires_at <= _time(now))
    )
    return result.rowcount
