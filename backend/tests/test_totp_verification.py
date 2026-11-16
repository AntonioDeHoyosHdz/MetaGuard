import pyotp
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account
from metaguard_api.database import Base
from metaguard_api.totp_secrets import encrypt_totp_secret
from metaguard_api.totp_verification import consume_totp


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as value:
        value.add(Account(id="account-1", email="test@example.test", password_hash="synthetic"))
        value.add(
            AccountTotp(
                account_id="account-1",
                encrypted_secret=encrypt_totp_secret(bytes(32), "account-1", "JBSWY3DPEHPK3PXP"),
                key_version=1,
            )
        )
        value.commit()
        yield value
    engine.dispose()


def test_valid_code_consumed_once_and_later_step_accepted(session):
    code = pyotp.TOTP("JBSWY3DPEHPK3PXP").at(90)
    assert consume_totp(session, "account-1", code, key=bytes(32), key_version=1, now=90)
    assert not consume_totp(session, "account-1", code, key=bytes(32), key_version=1, now=90)
    assert session.scalar(select(AccountTotp.last_accepted_step)) == 3
    next_code = pyotp.TOTP("JBSWY3DPEHPK3PXP").at(120)
    assert consume_totp(session, "account-1", next_code, key=bytes(32), key_version=1, now=120)


def test_invalid_code_or_unknown_account_does_not_change_state(session):
    for account, code in [("missing", "123456"), ("account-1", "xxxxxx"), ("account-1", "12345")]:
        assert not consume_totp(session, account, code, key=bytes(32), key_version=1, now=90)
    assert session.scalar(select(AccountTotp.last_accepted_step)) is None


def test_wrong_key_version_fails_closed(session):
    code = pyotp.TOTP("JBSWY3DPEHPK3PXP").at(90)
    assert not consume_totp(session, "account-1", code, key=bytes(32), key_version=2, now=90)
    assert session.scalar(select(AccountTotp.last_accepted_step)) is None


def test_rollback_does_not_consume_step(session):
    code = pyotp.TOTP("JBSWY3DPEHPK3PXP").at(90)
    assert consume_totp(session, "account-1", code, key=bytes(32), key_version=1, now=90)
    session.rollback()
    assert consume_totp(session, "account-1", code, key=bytes(32), key_version=1, now=90)


def test_wrong_key_and_clock_regression_fail_closed(session):
    code = pyotp.TOTP("JBSWY3DPEHPK3PXP").at(90)
    assert not consume_totp(session, "account-1", code, key=bytes([1]) * 32, key_version=1, now=90)
    assert consume_totp(session, "account-1", code, key=bytes(32), key_version=1, now=90)
    old_code = pyotp.TOTP("JBSWY3DPEHPK3PXP").at(60)
    assert not consume_totp(session, "account-1", old_code, key=bytes(32), key_version=1, now=60)
    assert session.scalar(select(AccountTotp.last_accepted_step)) == 3
