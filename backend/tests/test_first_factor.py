from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

import metaguard_api.first_factor as first_factor
from metaguard_api.account_credentials import hash_password
from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account
from metaguard_api.database import Base
from metaguard_api.first_factor import (
    FirstFactorStatus,
    InvalidDummyPasswordHash,
    check_first_factor,
)


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as value:
            yield value
    finally:
        engine.dispose()


@pytest.fixture
def dummy_password_hash():
    return hash_password("not-a-user-password-for-dummy-check")


def add_account(
    session: Session,
    *,
    password: str,
    verified: bool = True,
    with_totp: bool = False,
) -> Account:
    account = Account(
        id="account-1",
        email="person@example.test",
        password_hash=hash_password(password),
        email_verified_at=datetime.now(UTC) if verified else None,
    )
    session.add(account)
    if with_totp:
        session.add(
            AccountTotp(
                account_id=account.id,
                encrypted_secret=b"x" * 30,
                key_version=1,
            )
        )
    session.commit()
    return account


def test_verified_password_is_only_a_first_factor(session, dummy_password_hash):
    account = add_account(session, password="correct synthetic account password")

    result = check_first_factor(
        session,
        "person@example.test",
        "correct synthetic account password",
        dummy_password_hash=dummy_password_hash,
    )

    assert result.status is FirstFactorStatus.PASSWORD_VERIFIED
    assert result.account_id == account.id
    assert not session.dirty and not session.new and not session.deleted


def test_unverified_account_is_rejected_without_exposing_account_id(session, dummy_password_hash):
    add_account(session, password="correct synthetic account password", verified=False)

    result = check_first_factor(
        session,
        "person@example.test",
        "correct synthetic account password",
        dummy_password_hash=dummy_password_hash,
    )

    assert result.status is FirstFactorStatus.REJECTED
    assert result.account_id is None


def test_totp_account_requires_second_factor_and_is_not_authenticated(session, dummy_password_hash):
    account = add_account(
        session,
        password="correct synthetic account password",
        with_totp=True,
    )

    result = check_first_factor(
        session,
        "person@example.test",
        "correct synthetic account password",
        dummy_password_hash=dummy_password_hash,
    )

    assert result.status is FirstFactorStatus.MFA_REQUIRED
    assert result.account_id == account.id
    stored = session.get(AccountTotp, account.id)
    assert stored is not None and stored.last_accepted_step is None
    assert not session.dirty and not session.new and not session.deleted


def test_unknown_identity_uses_dummy_hash_and_returns_generic_rejection(
    session, dummy_password_hash, monkeypatch
):
    calls = []
    verify = first_factor.verify_password

    def spy(password, encoded):
        calls.append(encoded)
        return verify(password, encoded)

    monkeypatch.setattr(first_factor, "verify_password", spy)
    result = check_first_factor(
        session,
        "missing@example.test",
        "some synthetic password",
        dummy_password_hash=dummy_password_hash,
    )

    assert calls == [dummy_password_hash]
    assert result.status is FirstFactorStatus.REJECTED
    assert result.account_id is None


def test_unapproved_stored_hash_falls_back_to_dummy_and_rejects(
    session, dummy_password_hash, monkeypatch
):
    account = add_account(session, password="correct synthetic account password")
    prefix, salt, digest = account.password_hash.rsplit("$", maxsplit=2)
    account.password_hash = f"{prefix}${salt}${digest[:-1]}B"
    session.commit()
    calls = []
    verify = first_factor.verify_password

    def spy(password, encoded):
        calls.append(encoded)
        return verify(password, encoded)

    monkeypatch.setattr(first_factor, "verify_password", spy)
    result = check_first_factor(
        session,
        "person@example.test",
        "correct synthetic account password",
        dummy_password_hash=dummy_password_hash,
    )

    assert calls == [dummy_password_hash]
    assert result.status is FirstFactorStatus.REJECTED
    assert result.account_id is None


def test_wrong_password_and_unknown_identity_have_same_public_outcome(session, dummy_password_hash):
    add_account(session, password="correct synthetic account password")
    before = session.execute(select(Account.id, Account.email, Account.password_hash)).all()

    wrong = check_first_factor(
        session,
        "person@example.test",
        "incorrect synthetic password",
        dummy_password_hash=dummy_password_hash,
    )
    missing = check_first_factor(
        session,
        "missing@example.test",
        "incorrect synthetic password",
        dummy_password_hash=dummy_password_hash,
    )

    assert wrong == missing
    assert wrong.status is FirstFactorStatus.REJECTED
    assert wrong.account_id is None
    assert session.execute(select(Account.id, Account.email, Account.password_hash)).all() == before


def test_pending_account_is_not_autoflushed_or_authenticated(session, dummy_password_hash):
    session.add(
        Account(
            id="pending-account",
            email="pending@example.test",
            password_hash=hash_password("correct synthetic account password"),
            email_verified_at=datetime.now(UTC),
        )
    )

    result = check_first_factor(
        session,
        "pending@example.test",
        "correct synthetic account password",
        dummy_password_hash=dummy_password_hash,
    )

    assert result.status is FirstFactorStatus.REJECTED
    assert result.account_id is None
    assert len(session.new) == 1


def test_unapproved_dummy_hash_is_a_configuration_error(session):
    prefix, salt, digest = hash_password("dummy source password").rsplit("$", maxsplit=2)
    noncanonical_hash = f"{prefix}${salt}${digest[:-1]}B"
    with pytest.raises(InvalidDummyPasswordHash):
        check_first_factor(
            session,
            "missing@example.test",
            "some synthetic password",
            dummy_password_hash=noncanonical_hash,
        )


@pytest.mark.parametrize(
    "email",
    [
        "Person@example.test",
        "missing-at-sign",
        "@example.test",
        "person@",
        "person\x00@example.test",
        "person\ud800@example.test",
    ],
    ids=["noncanonical-case", "missing-at", "empty-local", "empty-domain", "nul", "surrogate"],
)
def test_invalid_email_uses_dummy_hash_without_database_lookup(
    session, dummy_password_hash, monkeypatch, email
):
    calls = []
    verify = first_factor.verify_password

    def spy(password, encoded):
        calls.append(encoded)
        return verify(password, encoded)

    monkeypatch.setattr(first_factor, "verify_password", spy)
    monkeypatch.setattr(
        session,
        "execute",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("Invalid email must not reach database binding")
        ),
    )
    result = check_first_factor(
        session,
        email,
        "some synthetic password",
        dummy_password_hash=dummy_password_hash,
    )

    assert calls == [dummy_password_hash]
    assert result.status is FirstFactorStatus.REJECTED
