"""Minimal, unlinked reputation cache; no file bytes or provider payloads."""

import json
import re
from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Index,
    LargeBinary,
    SmallInteger,
    String,
    and_,
    case,
    delete,
    or_,
    select,
)
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Mapped, Session, mapped_column

from metaguard_api.database import Base

_TTL_SECONDS = 24 * 60 * 60
_MAX_TIME = (2**63) - 1 - _TTL_SECONDS
_ANALYSIS_STAT_KEYS = frozenset(
    {
        "confirmed-timeout",
        "failure",
        "harmless",
        "malicious",
        "suspicious",
        "timeout",
        "type-unsupported",
        "undetected",
    }
)


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
        CheckConstraint(
            "analysis_stats_json IS NULL OR length(analysis_stats_json) <= 256",
            name="ck_reputation_stats_size",
        ),
        Index("ix_reputation_cache_expires_at", "expires_at"),
    )

    digest: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    analysis_stats_json: Mapped[str | None] = mapped_column(String(256), nullable=True)
    last_analysis_date: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


class VirusTotalQuota(Base):
    """One aggregate quota row shared by every API worker using the database."""

    __tablename__ = "virustotal_request_quota"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_virustotal_quota_singleton"),
        CheckConstraint("day_count BETWEEN 0 AND 500", name="ck_virustotal_day_count"),
    )

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    recent_1: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    recent_2: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    recent_3: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    recent_4: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    day_window: Mapped[int] = mapped_column(BigInteger, nullable=False)
    day_count: Mapped[int] = mapped_column(SmallInteger, nullable=False)


@dataclass(frozen=True, slots=True)
class CachedVerdict:
    verdict: CacheVerdict
    last_analysis_stats: dict[str, int] | None
    last_analysis_date: int | None


def _digest(value: str) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("Expected a lowercase SHA-256 digest")
    return bytes.fromhex(value)


def _time(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_TIME:
        raise ValueError("Expected a valid UTC epoch timestamp")
    return value


def _validated_stats(stats: dict[str, int] | None) -> str | None:
    if stats is None:
        return None
    if not isinstance(stats, dict) or not stats or not set(stats) <= _ANALYSIS_STAT_KEYS:
        raise ValueError("Expected minimized VirusTotal analysis statistics")
    if any(type(value) is not int or value < 0 for value in stats.values()):
        raise ValueError("Expected non-negative analysis statistics")
    serialized = json.dumps(stats, sort_keys=True, separators=(",", ":"))
    if len(serialized) > 256:
        raise ValueError("Analysis statistics exceed the cache limit")
    return serialized


def save_verdict(
    session: Session,
    digest: str,
    verdict: CacheVerdict,
    *,
    now: int,
    last_analysis_stats: dict[str, int] | None = None,
    last_analysis_date: int | None = None,
) -> None:
    """Atomically insert or refresh a verdict within the caller's transaction."""
    digest_bytes = _digest(digest)
    expires_at = _time(now) + _TTL_SECONDS
    if not isinstance(verdict, CacheVerdict):
        raise ValueError("Expected a supported cache verdict")
    stats_json = _validated_stats(last_analysis_stats)
    if last_analysis_date is not None:
        _time(last_analysis_date)
    if verdict is CacheVerdict.NO_RECORD and (
        stats_json is not None or last_analysis_date is not None
    ):
        raise ValueError("A missing record cannot contain analysis data")
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert = postgres_insert
    elif dialect == "sqlite":
        insert = sqlite_insert
    else:
        raise ValueError("Unsupported database dialect")
    statement = insert(ReputationEntry).values(
        digest=digest_bytes,
        verdict=verdict.value,
        expires_at=expires_at,
        analysis_stats_json=stats_json,
        last_analysis_date=last_analysis_date,
    )
    statement = statement.on_conflict_do_update(
        index_elements=[ReputationEntry.digest],
        set_={
            "verdict": statement.excluded.verdict,
            "expires_at": statement.excluded.expires_at,
            "analysis_stats_json": statement.excluded.analysis_stats_json,
            "last_analysis_date": statement.excluded.last_analysis_date,
        },
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


def get_cached_verdict(session: Session, digest: str, *, now: int) -> CachedVerdict | None:
    row = session.scalar(
        select(ReputationEntry).where(
            ReputationEntry.digest == _digest(digest), ReputationEntry.expires_at > _time(now)
        )
    )
    if row is None:
        return None
    stats = json.loads(row.analysis_stats_json) if row.analysis_stats_json is not None else None
    if row.verdict != CacheVerdict.NO_RECORD.value and stats is None:
        return None
    return CachedVerdict(CacheVerdict(row.verdict), stats, row.last_analysis_date)


def reserve_virustotal_request(session: Session, *, now: int) -> bool:
    """Atomically reserve one account-wide request within 60 seconds and a UTC day."""
    current_time = _time(now)
    day_window = current_time // (24 * 60 * 60)
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert = postgres_insert
    elif dialect == "sqlite":
        insert = sqlite_insert
    else:
        raise ValueError("Unsupported database dialect")

    slots = [
        VirusTotalQuota.recent_1,
        VirusTotalQuota.recent_2,
        VirusTotalQuota.recent_3,
        VirusTotalQuota.recent_4,
    ]
    active = [and_(column.is_not(None), column > current_time - 60) for column in slots]
    statement = insert(VirusTotalQuota).values(
        id=1,
        recent_1=current_time,
        recent_2=None,
        recent_3=None,
        recent_4=None,
        day_window=day_window,
        day_count=1,
    )
    same_day = VirusTotalQuota.day_window == day_window
    updated_slots = {
        f"recent_{index + 1}": case(
            (active[index], slots[index]),
            *((and_(*active[:index]), current_time),) if index else (),
            else_=None if index else current_time,
        )
        for index in range(4)
    }
    statement = statement.on_conflict_do_update(
        index_elements=[VirusTotalQuota.id],
        set_={
            **updated_slots,
            "day_window": case((same_day, VirusTotalQuota.day_window), else_=day_window),
            "day_count": case((same_day, VirusTotalQuota.day_count + 1), else_=1),
        },
        where=and_(
            *(or_(column.is_(None), column <= current_time) for column in slots),
            VirusTotalQuota.day_window <= day_window,
            or_(~same_day, VirusTotalQuota.day_count < 500),
            or_(~active[0], ~active[1], ~active[2], ~active[3]),
        ),
    ).returning(VirusTotalQuota.id)
    return session.execute(statement).scalar_one_or_none() is not None


def purge_expired(session: Session, *, now: int) -> int:
    """Delete expired entries within the caller's transaction."""
    result = session.execute(
        delete(ReputationEntry).where(ReputationEntry.expires_at <= _time(now))
    )
    return result.rowcount
