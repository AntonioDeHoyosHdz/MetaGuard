from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Barrier

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from metaguard_api.account_credentials import hash_password, verify_password
from metaguard_api.accounts import Account, EmailVerificationToken
from metaguard_api.database import Base
from metaguard_api.email_verification import (
    consume_email_verification,
    prepare_email_verification,
)


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as value:
        value.add(Account(id="account-1", email="test@example.test", password_hash="synthetic"))
        value.commit()
        yield value
    engine.dispose()


def test_preparation_persists_only_digest_and_consumption_verifies_once(session):
    now = datetime(2026, 11, 16, tzinfo=UTC)
    token = prepare_email_verification(
        session, "account-1", now=now, expires_at=now + timedelta(hours=1)
    )

    stored = session.scalar(select(EmailVerificationToken))
    assert token
    assert stored.token_digest == sha256(token.encode("utf-8")).hexdigest()
    assert token not in stored.token_digest
    assert consume_email_verification(session, token, now=now + timedelta(minutes=1))
    assert session.get(Account, "account-1").email_verified_at == now + timedelta(minutes=1)
    assert session.scalar(select(EmailVerificationToken)) is None
    assert not consume_email_verification(session, token, now=now + timedelta(minutes=2))


def test_expired_or_invalid_token_does_not_verify_account(session):
    now = datetime(2026, 11, 16, tzinfo=UTC)
    token = prepare_email_verification(
        session, "account-1", now=now, expires_at=now + timedelta(minutes=1)
    )

    assert not consume_email_verification(session, "invalid", now=now)
    assert not consume_email_verification(session, token, now=now + timedelta(minutes=1))
    assert session.get(Account, "account-1").email_verified_at is None


@pytest.mark.parametrize(
    "token",
    ["\ud800" * 43, "!" * 43, "a" * 42, "a" * 44],
)
def test_malformed_token_is_rejected_without_changing_account(session, token):
    now = datetime(2026, 11, 16, tzinfo=UTC)

    assert not consume_email_verification(session, token, now=now)
    assert session.get(Account, "account-1").email_verified_at is None


def test_replacement_invalidates_previous_token(session):
    now = datetime(2026, 11, 16, tzinfo=UTC)
    first = prepare_email_verification(
        session, "account-1", now=now, expires_at=now + timedelta(hours=1)
    )
    second = prepare_email_verification(
        session, "account-1", now=now, expires_at=now + timedelta(hours=2)
    )

    stored = list(session.scalars(select(EmailVerificationToken)))
    assert len(stored) == 1
    assert stored[0].token_digest == sha256(second.encode("utf-8")).hexdigest()
    assert not consume_email_verification(session, first, now=now)
    assert consume_email_verification(session, second, now=now)


def test_preparation_and_consumption_respect_caller_rollback(session):
    now = datetime(2026, 11, 16, tzinfo=UTC)
    token = prepare_email_verification(
        session, "account-1", now=now, expires_at=now + timedelta(hours=1)
    )
    session.rollback()
    assert session.scalar(select(EmailVerificationToken)) is None
    assert session.get(Account, "account-1").email_verified_at is None

    token = prepare_email_verification(
        session, "account-1", now=now, expires_at=now + timedelta(hours=1)
    )
    session.commit()
    assert consume_email_verification(session, token, now=now)
    session.rollback()
    assert session.get(Account, "account-1").email_verified_at is None
    assert session.scalar(select(EmailVerificationToken)) is not None


@pytest.mark.parametrize(
    ("account_id", "now", "expires_at"),
    [
        ("missing", datetime(2026, 11, 16, tzinfo=UTC), datetime(2026, 11, 17, tzinfo=UTC)),
        ("account-1", datetime(2026, 11, 16), datetime(2026, 11, 17, tzinfo=UTC)),
        ("account-1", datetime(2026, 11, 16, tzinfo=UTC), datetime(2026, 11, 16, tzinfo=UTC)),
    ],
)
def test_invalid_preparation_is_rejected(session, account_id, now, expires_at):
    assert prepare_email_verification(session, account_id, now=now, expires_at=expires_at) is None
    assert session.scalar(select(EmailVerificationToken)) is None


def test_already_verified_account_cannot_prepare_or_consume_another_token(session):
    now = datetime(2026, 11, 16, tzinfo=UTC)
    token = prepare_email_verification(
        session, "account-1", now=now, expires_at=now + timedelta(hours=1)
    )
    assert consume_email_verification(session, token, now=now)
    assert (
        prepare_email_verification(
            session, "account-1", now=now, expires_at=now + timedelta(hours=1)
        )
        is None
    )
    assert not consume_email_verification(session, token, now=now)


def test_resend_transactions_that_saw_the_same_token_cannot_both_replace_it(tmp_path, monkeypatch):
    from metaguard_api.email_verification import prepare_email_verification_resend

    engine = create_engine(f"sqlite:///{tmp_path / 'resend.db'}", connect_args={"timeout": 10})
    Base.metadata.create_all(engine)
    now = datetime(2026, 11, 16, tzinfo=UTC)
    password = "synthetic test password"
    dummy = hash_password("synthetic dummy password")
    barrier = Barrier(2)

    def verify_same_snapshot(value, encoded):
        barrier.wait(timeout=5)
        return verify_password(value, encoded)

    monkeypatch.setattr("metaguard_api.email_verification.verify_password", verify_same_snapshot)
    try:
        with Session(engine) as setup, setup.begin():
            setup.add(
                Account(
                    id="account-1", email="test@example.test", password_hash=hash_password(password)
                )
            )
            setup.flush()
            old_token = prepare_email_verification(
                setup, "account-1", now=now, expires_at=now + timedelta(hours=1)
            )

        def resend(_index):
            with Session(engine) as contender, contender.begin():
                return prepare_email_verification_resend(
                    contender,
                    "test@example.test",
                    password,
                    dummy_password_hash=dummy,
                    now=now + timedelta(minutes=2),
                    expires_at=now + timedelta(hours=1, minutes=2),
                )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(resend, range(2)))
        assert results.count(None) == 1
        replacement = next(token for token in results if token is not None)
        assert replacement != old_token
        with Session(engine) as observer, observer.begin():
            assert not consume_email_verification(observer, old_token, now=now)
            assert consume_email_verification(observer, replacement, now=now)
    finally:
        engine.dispose()


def test_concurrent_consumers_have_at_most_one_winner(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'verification.db'}", connect_args={"timeout": 10}
    )
    Base.metadata.create_all(engine)
    now = datetime(2026, 11, 16, tzinfo=UTC)
    barrier = Barrier(2)
    try:
        with Session(engine) as setup:
            setup.add(Account(id="account-1", email="test@example.test", password_hash="synthetic"))
            setup.commit()
            token = prepare_email_verification(
                setup, "account-1", now=now, expires_at=now + timedelta(hours=1)
            )
            setup.commit()

        def consume() -> bool:
            with Session(engine) as contender:
                with contender.begin():
                    barrier.wait(timeout=5)
                    return consume_email_verification(contender, token, now=now)

        with ThreadPoolExecutor(max_workers=2) as executor:
            assert sorted(executor.map(lambda _index: consume(), range(2))) == [False, True]

        with Session(engine) as observer:
            assert observer.get(Account, "account-1").email_verified_at == now
            assert observer.scalar(select(EmailVerificationToken)) is None
    finally:
        engine.dispose()
