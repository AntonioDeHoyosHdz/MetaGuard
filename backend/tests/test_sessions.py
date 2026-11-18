"""Regression coverage for private opaque account sessions."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from sqlalchemy import create_engine, delete, select
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.orm import Session

from metaguard_api.accounts import Account, AccountSession
from metaguard_api.database import Base
from metaguard_api.sessions import (
    get_active_session,
    issue_session,
    revoke_session,
    verify_csrf_token,
)


@pytest.fixture
def session():
    engine = create_engine("sqlite://")

    @sqlalchemy_event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    now = datetime(2026, 11, 17, tzinfo=UTC)
    with Session(engine) as value:
        value.add(
            Account(
                id="account-1",
                email="test@example.test",
                password_hash="synthetic",
                email_verified_at=now,
            )
        )
        value.commit()
        yield value
        value.execute(delete(AccountSession))
        value.execute(delete(Account))
        value.commit()
    engine.dispose()


def test_issue_session_returns_independent_tokens_and_persists_only_digests(session):
    now = datetime(2026, 11, 17, tzinfo=UTC)
    expires_at = now + timedelta(hours=1)

    issued = issue_session(session, "account-1", now=now, expires_at=expires_at)

    stored = session.scalar(select(AccountSession))
    assert issued is not None
    assert len(issued.session_token) == len(issued.csrf_token) == 43
    assert issued.session_token != issued.csrf_token
    assert stored.token_digest == sha256(issued.session_token.encode("ascii")).hexdigest()
    assert stored.csrf_digest == sha256(issued.csrf_token.encode("ascii")).hexdigest()
    assert issued.session_token not in repr(issued)
    assert issued.csrf_token not in repr(issued)
    assert issued.expires_at == expires_at


def test_active_session_and_csrf_validation_are_bound_to_issued_session(session):
    now = datetime(2026, 11, 17, tzinfo=UTC)
    issued = issue_session(session, "account-1", now=now, expires_at=now + timedelta(hours=1))

    active = get_active_session(session, issued.session_token, now=now)

    assert active is not None
    assert active.account_id == "account-1"
    assert active.session_id
    assert verify_csrf_token(active, issued.csrf_token)
    assert not verify_csrf_token(active, "A" * 43)
    assert not verify_csrf_token(active, "invalid")
    assert not verify_csrf_token(None, issued.csrf_token)
    assert issued.session_token not in repr(active)
    assert issued.csrf_token not in repr(active)


def test_expired_or_revoked_sessions_are_not_active(session):
    now = datetime(2026, 11, 17, tzinfo=UTC)
    issued = issue_session(session, "account-1", now=now, expires_at=now + timedelta(minutes=1))

    assert get_active_session(session, issued.session_token, now=now + timedelta(minutes=1)) is None
    assert revoke_session(session, issued.session_token, now=now)
    assert not revoke_session(session, issued.session_token, now=now)
    assert get_active_session(session, issued.session_token, now=now) is None


def test_session_credentials_are_scoped_to_a_verified_account(session):
    now = datetime(2026, 11, 17, tzinfo=UTC)
    account = session.get(Account, "account-1")
    account.email_verified_at = None
    session.flush()

    assert issue_session(session, "account-1", now=now, expires_at=now + timedelta(hours=1)) is None
    assert session.scalar(select(AccountSession)) is None


def test_account_deletion_cascades_to_its_sessions(session):
    now = datetime(2026, 11, 17, tzinfo=UTC)
    issue_session(session, "account-1", now=now, expires_at=now + timedelta(hours=1))
    session.flush()

    session.delete(session.get(Account, "account-1"))
    session.flush()

    assert session.scalar(select(AccountSession)) is None


@pytest.mark.parametrize(
    ("account_id", "now", "expires_at"),
    [
        ("missing", datetime(2026, 11, 17, tzinfo=UTC), datetime(2026, 11, 18, tzinfo=UTC)),
        ("account-1", datetime(2026, 11, 17), datetime(2026, 11, 18, tzinfo=UTC)),
        ("account-1", datetime(2026, 11, 17, tzinfo=UTC), datetime(2026, 11, 17, tzinfo=UTC)),
    ],
)
def test_invalid_session_issue_request_is_rejected(session, account_id, now, expires_at):
    assert issue_session(session, account_id, now=now, expires_at=expires_at) is None
    assert session.scalar(select(AccountSession)) is None


def test_malformed_session_tokens_are_rejected(session):
    now = datetime(2026, 11, 17, tzinfo=UTC)

    for token in ("invalid", "A" * 42, "!" * 43, "\ud800" * 43):
        assert get_active_session(session, token, now=now) is None
        assert not revoke_session(session, token, now=now)

    assert session.scalar(select(AccountSession)) is None


def test_issue_and_revoke_respect_caller_transaction_rollback(session):
    now = datetime(2026, 11, 17, tzinfo=UTC)
    issued = issue_session(session, "account-1", now=now, expires_at=now + timedelta(hours=1))
    session.rollback()
    assert session.scalar(select(AccountSession)) is None

    issued = issue_session(session, "account-1", now=now, expires_at=now + timedelta(hours=1))
    session.commit()
    assert revoke_session(session, issued.session_token, now=now)
    session.rollback()
    stored = session.scalar(select(AccountSession))
    assert stored.revoked_at is None
