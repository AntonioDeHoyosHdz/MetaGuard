import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from metaguard_api.database import Base
from metaguard_api.system_security_events import (
    SecurityEventType,
    SystemSecurityEvent,
    purge_expired_events,
    record_event,
)


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as value:
        yield value
    engine.dispose()


def test_records_only_allowlisted_generic_event(session):
    record_event(session, SecurityEventType.PASSWORD_BREACH_CHECK_UNAVAILABLE, now=100)
    row = session.scalar(select(SystemSecurityEvent))
    assert row.event_type == "password_breach_check_unavailable"
    assert row.created_at == 100
    assert set(row.__table__.columns.keys()) == {"id", "event_type", "created_at"}
    session.rollback()
    assert session.scalar(select(SystemSecurityEvent)) is None


def test_purge_respects_30_day_boundary_and_rollback(session):
    record_event(session, SecurityEventType.PASSWORD_BREACH_CHECK_UNAVAILABLE, now=100)
    record_event(session, SecurityEventType.PASSWORD_BREACH_CHECK_UNAVAILABLE, now=101)
    session.commit()
    assert purge_expired_events(session, now=100 + 30 * 24 * 60 * 60) == 1
    assert len(session.scalars(select(SystemSecurityEvent)).all()) == 1
    session.rollback()
    assert len(session.scalars(select(SystemSecurityEvent)).all()) == 2


@pytest.mark.parametrize("now", [-1, True, 2**63, "1"])
def test_rejects_invalid_time(session, now):
    with pytest.raises(ValueError):
        record_event(session, SecurityEventType.PASSWORD_BREACH_CHECK_UNAVAILABLE, now=now)
    with pytest.raises(ValueError):
        purge_expired_events(session, now=now)
    assert session.scalar(select(SystemSecurityEvent)) is None


def test_rejects_unapproved_event_types(session):
    with pytest.raises(ValueError):
        record_event(session, "private input", now=100)
    assert session.scalar(select(SystemSecurityEvent)) is None


def test_screening_outage_can_record_only_generic_event(session):
    from metaguard_api.password_policy import PasswordScreeningResult, screen_password
    from metaguard_api.pwned_passwords import RangeServiceUnavailable

    def unavailable(*_args):
        raise RangeServiceUnavailable("synthetic outage")

    def report(event):
        record_event(session, SecurityEventType(event), now=100)

    result = screen_password(
        "correct horse battery staple",
        common_passwords=frozenset({"common password"}),
        lookup=unavailable,
        report_outage=report,
    )
    assert result == PasswordScreeningResult.ACCEPTED_REDUCED
    row = session.scalar(select(SystemSecurityEvent))
    assert row.event_type == "password_breach_check_unavailable"


def test_outage_reporter_commits_independently_of_registration(tmp_path):
    from metaguard_api.database import Database
    from metaguard_api.system_security_events import record_password_check_outage

    engine = create_engine(f"sqlite:///{(tmp_path / 'events.db').as_posix()}")
    Base.metadata.create_all(engine)
    database = Database(engine)
    try:
        with pytest.raises(RuntimeError, match="registration failed"):
            with database.transaction():
                record_password_check_outage(database, "password_breach_check_unavailable", now=100)
                raise RuntimeError("registration failed")
        with database.transaction() as session:
            assert (
                session.scalar(select(SystemSecurityEvent.event_type))
                == "password_breach_check_unavailable"
            )
        with pytest.raises(ValueError):
            record_password_check_outage(database, "unapproved", now=100)
    finally:
        database.close()
