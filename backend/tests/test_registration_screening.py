from datetime import UTC, datetime, timedelta
from hashlib import sha1, sha256
from http.client import HTTPResponse
from io import BytesIO
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

import metaguard_api.registration_screening as screening
from metaguard_api.accounts import Account, EmailVerificationToken
from metaguard_api.database import Base, Database
from metaguard_api.pwned_passwords import RangeServiceUnavailable
from metaguard_api.registration import InvalidRegistrationInput
from metaguard_api.system_security_events import SystemSecurityEvent

NOW = datetime(2026, 1, 1, tzinfo=UTC)
PASSWORD = "synthetic strong password 123"
EMAIL = "person@example.test"


@pytest.fixture
def database(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    Base.metadata.create_all(engine)
    value = Database(engine)
    yield value
    value.close()


def register(session, database, *, password=PASSWORD):
    return screening.register_with_screening(
        session,
        database,
        EMAIL,
        password,
        common_passwords=frozenset({"common synthetic password"}),
        now=NOW,
        expires_at=NOW + timedelta(minutes=30),
        event_now=100,
    )


def test_online_registration_uses_fixed_transport_and_creates_token(database, monkeypatch):
    calls = []

    def lookup(prefix, headers):
        calls.append((prefix, headers))
        return "0" * 35 + ":1\n"

    monkeypatch.setattr(screening, "fetch_password_range", lookup)
    with Session(database.engine) as session:
        result = register(session, database)
        assert not result.protection_reduced
        stored = session.get(EmailVerificationToken, result.account.id)
        assert stored.token_digest == sha256(result.token.encode()).hexdigest()
        assert result.token not in repr(result)
        session.commit()
    prefix = sha1(PASSWORD.encode(), usedforsecurity=False).hexdigest().upper()[:5]
    assert calls == [(prefix, {"Add-Padding": "true"})]


def test_reduced_event_survives_caller_rollback(database, monkeypatch):
    def unavailable(*_args):
        raise RangeServiceUnavailable("unavailable")

    monkeypatch.setattr(screening, "fetch_password_range", unavailable)
    with Session(database.engine) as session:
        result = register(session, database)
        assert result.protection_reduced
        account_id = result.account.id
        session.rollback()
    with database.transaction() as observer:
        assert observer.get(Account, account_id) is None
        events = observer.scalars(select(SystemSecurityEvent)).all()
        assert len(events) == 1
        assert events[0].event_type == "password_breach_check_unavailable"
        assert events[0].created_at == 100


def test_event_failure_fails_closed(database, monkeypatch):
    def unavailable(*_args):
        raise RangeServiceUnavailable("unavailable")

    def failed_event(*_args, **_kwargs):
        raise RuntimeError("event unavailable")

    monkeypatch.setattr(screening, "fetch_password_range", unavailable)
    monkeypatch.setattr(screening, "record_password_check_outage", failed_event)
    with Session(database.engine) as session, pytest.raises(RuntimeError):
        register(session, database)
    with database.transaction() as session:
        assert session.scalar(select(Account)) is None


def test_invalid_response_and_common_password_do_not_register(database, monkeypatch):
    monkeypatch.setattr(screening, "fetch_password_range", lambda *_args: "malformed")
    with Session(database.engine) as session, pytest.raises(InvalidRegistrationInput):
        register(session, database)
    with Session(database.engine) as session, pytest.raises(InvalidRegistrationInput):
        register(session, database, password="common synthetic password")
    with database.transaction() as session:
        assert session.scalar(select(Account)) is None


def test_non_ascii_hibp_body_never_allows_reduced_fallback(database, monkeypatch):
    digest = sha1(PASSWORD.encode(), usedforsecurity=False).hexdigest().upper()
    body = f"{digest[5:]}:31\n".encode() + b"\xff"

    class Socket:
        def makefile(self, *_args, **_kwargs):
            return BytesIO(
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
            )

    response = HTTPResponse(Socket())
    response.begin()
    opener = MagicMock()
    opener.open.return_value = response
    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", lambda *_args: opener)
    with Session(database.engine) as session, pytest.raises(InvalidRegistrationInput):
        register(session, database)
    with database.transaction() as session:
        assert session.scalar(select(Account)) is None


def test_existing_caller_transaction_is_rejected_without_committing(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    database = Database(engine)
    monkeypatch.setattr(screening, "fetch_password_range", lambda *_args: "0" * 35 + ":1\n")
    try:
        with Session(engine) as session:
            session.add(Account(id="earlier", email="earlier@example.test", password_hash="x"))
            session.flush()
            with pytest.raises(ValueError, match="fresh"):
                register(session, database)
            session.rollback()
        with Session(engine) as observer:
            assert observer.get(Account, "earlier") is None
    finally:
        database.close()


def test_single_connection_pool_is_rejected_even_for_fresh_session():
    engine = create_engine("sqlite://")
    database = Database(engine)
    try:
        with Session(engine) as session, pytest.raises(ValueError, match="independent-connection"):
            register(session, database)
    finally:
        database.close()
