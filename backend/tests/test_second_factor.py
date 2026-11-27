from datetime import UTC, datetime

import pyotp
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from metaguard_api.account_credentials import hash_password
from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account
from metaguard_api.database import Base
from metaguard_api.second_factor import check_second_factor
from metaguard_api.totp_secrets import encrypt_totp_secret

PASSWORD = "correct synthetic account password"
SECRET = "JBSWY3DPEHPK3PXP"
KEY = bytes(32)


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as value:
        value.add(
            Account(
                id="a",
                email="test@example.test",
                password_hash=hash_password(PASSWORD),
                email_verified_at=datetime.now(UTC),
            )
        )
        value.add(
            AccountTotp(
                account_id="a",
                encrypted_secret=encrypt_totp_secret(KEY, "a", SECRET),
                key_version=1,
            )
        )
        value.commit()
        yield value
    engine.dispose()


@pytest.fixture
def dummy_hash():
    return hash_password("synthetic dummy password")


def check(session, dummy_hash, *, email="test@example.test", password=PASSWORD, code=None):
    return check_second_factor(
        session,
        email,
        password,
        code or pyotp.TOTP(SECRET).at(90),
        dummy_password_hash=dummy_hash,
        key=KEY,
        key_version=1,
        now=90,
    )


def test_correct_factors_are_provisional_and_replay_fails(session, dummy_hash):
    assert check(session, dummy_hash) == "a"
    assert session.scalar(select(AccountTotp.last_accepted_step)) == 3
    assert check(session, dummy_hash) is None
    session.rollback()
    assert session.scalar(select(AccountTotp.last_accepted_step)) is None
    assert check(session, dummy_hash) == "a"


@pytest.mark.parametrize(
    "email,password,code",
    [
        ("unknown@example.test", PASSWORD, "123456"),
        ("test@example.test", "wrong password", "123456"),
        ("test@example.test", PASSWORD, "not-a-code"),
    ],
)
def test_invalid_factors_do_not_consume_step(session, dummy_hash, email, password, code):
    assert check(session, dummy_hash, email=email, password=password, code=code) is None
    assert session.scalar(select(AccountTotp.last_accepted_step)) is None


def test_account_without_totp_does_not_succeed(session, dummy_hash):
    session.delete(session.get(AccountTotp, "a"))
    session.commit()
    assert check(session, dummy_hash) is None


def test_unverified_email_does_not_consume_step(session, dummy_hash):
    session.get(Account, "a").email_verified_at = None
    session.commit()
    assert check(session, dummy_hash) is None
    assert session.scalar(select(AccountTotp.last_accepted_step)) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("email_verified_at", None),
        ("password_hash", "pending replacement"),
    ],
)
def test_pending_security_changes_fail_closed_without_flushing(session, dummy_hash, field, value):
    account = session.get(Account, "a")
    setattr(account, field, value)
    assert check(session, dummy_hash) is None
    assert account in session.dirty
    session.rollback()
    assert session.scalar(select(AccountTotp.last_accepted_step)) is None
