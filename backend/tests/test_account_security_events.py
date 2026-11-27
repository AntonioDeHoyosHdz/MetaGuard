from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from metaguard_api.account_security_events import (
    AccountSecurityEvent,
    AccountSecurityEventKind,
    list_account_events,
    purge_expired_account_events,
    save_account_event,
)
from metaguard_api.accounts import Account
from metaguard_api.database import Base

NOW = datetime(2026, 11, 21, 12, tzinfo=UTC)
OWNER = "account-one"
OTHER = "account-two"


@pytest.fixture
def sessions():
    engine = create_engine("sqlite://")

    @event.listens_for(engine, "connect")
    def enable_fk(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    with factory.begin() as session:
        session.add_all(
            [
                Account(id=OWNER, email="one@example.test", password_hash="synthetic"),
                Account(id=OTHER, email="two@example.test", password_hash="synthetic"),
            ]
        )
    yield factory
    engine.dispose()


def test_pacing_is_per_kind_and_owner(sessions):
    with sessions.begin() as session:
        kind = AccountSecurityEventKind.LOGIN_FAILED
        first = NOW - timedelta(minutes=10)
        assert save_account_event(session, OWNER, kind, now=first)
        assert not save_account_event(session, OWNER, kind, now=first + timedelta(seconds=1))
        assert save_account_event(session, OTHER, kind, now=first)
        assert save_account_event(session, OWNER, AccountSecurityEventKind.MFA_FAILED, now=first)
        assert save_account_event(session, OWNER, kind, now=NOW)
        assert len(list_account_events(session, OWNER, now=NOW)) == 3


def test_history_caps_results_orders_latest_first_and_purges_at_the_boundary(sessions):
    with sessions.begin() as session:
        kind = AccountSecurityEventKind.LOGIN_FAILED
        for minutes in range(0, 550, 10):
            assert save_account_event(session, OWNER, kind, now=NOW - timedelta(minutes=minutes))
        expired = NOW - timedelta(days=30)
        assert save_account_event(session, OWNER, kind, now=expired)
        assert save_account_event(session, OTHER, kind, now=expired + timedelta(seconds=1))
        assert save_account_event(session, OTHER, AccountSecurityEventKind.MFA_FAILED, now=expired)
        rows = list_account_events(session, OWNER, now=NOW)
        assert len(rows) == 50
        assert [row.created_at for row in rows] == [
            int((NOW - timedelta(minutes=minutes)).timestamp()) for minutes in range(0, 500, 10)
        ]
        assert [row.kind for row in list_account_events(session, OTHER, now=NOW)] == [kind]
        assert purge_expired_account_events(session, now=NOW) == 2
        assert session.query(AccountSecurityEvent).count() == 56


def test_schema_rejects_arbitrary_kind_and_cascades_account_deletion(sessions):
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.execute(
            text(
                "INSERT INTO account_security_events "
                "(id, account_id, kind, created_at, pace_window) "
                "VALUES ('synthetic', :owner, 'unrecognized', 0, 0)"
            ),
            {"owner": OWNER},
        )
    with sessions.begin() as session:
        assert save_account_event(session, OWNER, AccountSecurityEventKind.LOGIN_FAILED, now=NOW)
        session.delete(session.get(Account, OWNER))
    with sessions.begin() as session:
        assert session.scalars(select(AccountSecurityEvent)).all() == []
