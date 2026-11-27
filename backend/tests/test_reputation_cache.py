import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from metaguard_api.database import Base
from metaguard_api.reputation_cache import (
    CachedVerdict,
    CacheVerdict,
    get_cached_verdict,
    get_verdict,
    purge_expired,
    save_verdict,
)


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        yield db
    engine.dispose()


def test_cache_expires_after_24_hours_and_upserts(session) -> None:
    digest = "a" * 64
    save_verdict(session, digest, CacheVerdict.UNDETECTED, now=100)
    assert get_verdict(session, digest, now=100 + 86_399) == CacheVerdict.UNDETECTED
    assert get_verdict(session, digest, now=100 + 86_400) is None
    save_verdict(session, digest, CacheVerdict.SUSPICIOUS, now=200)
    assert get_verdict(session, digest, now=200) == CacheVerdict.SUSPICIOUS
    assert get_verdict(session, digest, now=200 + 86_400) is None


def test_purge_removes_only_expired_entries(session) -> None:
    save_verdict(session, "a" * 64, CacheVerdict.NO_RECORD, now=100)
    save_verdict(session, "b" * 64, CacheVerdict.MALICIOUS, now=200)
    assert purge_expired(session, now=100 + 86_400) == 1
    assert get_verdict(session, "a" * 64, now=100) is None
    assert get_verdict(session, "b" * 64, now=200) == CacheVerdict.MALICIOUS


@pytest.mark.parametrize("digest", ["a" * 63, "g" * 64, "A" * 64, "file-name.jpg"])
def test_invalid_digest_is_rejected_without_writing(session, digest) -> None:
    with pytest.raises(ValueError):
        save_verdict(session, digest, CacheVerdict.NO_RECORD, now=100)
    assert purge_expired(session, now=100_000) == 0


def test_arbitrary_provider_payload_and_invalid_time_are_rejected(session) -> None:
    with pytest.raises(ValueError):
        save_verdict(session, "a" * 64, '{"filename":"secret"}', now=100)
    with pytest.raises(ValueError):
        save_verdict(session, "a" * 64, CacheVerdict.NO_RECORD, now=-1)
    assert purge_expired(session, now=100_000) == 0


def test_stale_or_same_time_updates_do_not_overwrite_newer_verdict(session) -> None:
    digest = "a" * 64
    save_verdict(session, digest, CacheVerdict.MALICIOUS, now=200)
    save_verdict(session, digest, CacheVerdict.UNDETECTED, now=100)
    save_verdict(session, digest, CacheVerdict.UNDETECTED, now=200)
    assert get_verdict(session, digest, now=200) == CacheVerdict.MALICIOUS


@pytest.mark.parametrize(
    ("digest", "verdict"), [(b"short", "malicious"), (b"a" * 32, "private content")]
)
def test_database_constraints_reject_invalid_data(session, digest, verdict) -> None:
    with pytest.raises(IntegrityError):
        session.execute(
            text("INSERT INTO reputation_cache (digest, verdict, expires_at) VALUES (:d, :v, 10)"),
            {"d": digest, "v": verdict},
        )
    session.rollback()


def test_cache_contains_only_minimal_fields() -> None:
    assert set(Base.metadata.tables["reputation_cache"].columns.keys()) == {
        "digest",
        "verdict",
        "expires_at",
        "analysis_stats_json",
        "last_analysis_date",
    }
    assert set(Base.metadata.tables["virustotal_request_quota"].columns.keys()) == {
        "id",
        "recent_1",
        "recent_2",
        "recent_3",
        "recent_4",
        "day_window",
        "day_count",
    }


def test_cache_round_trips_only_minimized_analysis_statistics(session) -> None:
    digest = "e" * 64
    stats = {"malicious": 1, "undetected": 9}
    save_verdict(
        session,
        digest,
        CacheVerdict.MALICIOUS,
        now=100,
        last_analysis_stats=stats,
        last_analysis_date=90,
    )

    assert get_cached_verdict(session, digest, now=100) == CachedVerdict(
        CacheVerdict.MALICIOUS, stats, 90
    )


def test_cache_rejects_unapproved_statistics_or_provider_payload(session) -> None:
    for stats in ({"filename": 1}, {"malicious": True}, {"malicious": -1}, {}):
        with pytest.raises(ValueError):
            save_verdict(
                session,
                "f" * 64,
                CacheVerdict.MALICIOUS,
                now=100,
                last_analysis_stats=stats,
            )


def test_rejected_write_preserves_existing_entry(session) -> None:
    digest = "a" * 64
    save_verdict(session, digest, CacheVerdict.MALICIOUS, now=100)
    with pytest.raises(ValueError):
        save_verdict(session, digest, "private provider payload", now=200)
    assert get_verdict(session, digest, now=200) == CacheVerdict.MALICIOUS


def test_cache_writes_follow_caller_transaction(session) -> None:
    digest = "c" * 64
    save_verdict(session, digest, CacheVerdict.SUSPICIOUS, now=100)
    session.rollback()
    assert get_verdict(session, digest, now=100) is None
