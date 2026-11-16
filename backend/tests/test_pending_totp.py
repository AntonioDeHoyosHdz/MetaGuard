import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from metaguard_api.accounts import Account
from metaguard_api.database import Base
from metaguard_api.pending_totp import PendingTotp, stage_totp
from metaguard_api.totp_secrets import decrypt_totp_secret


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as value:
        value.add(Account(id="account-1", email="test@example.test", password_hash="synthetic"))
        value.commit()
        yield value
    engine.dispose()


def test_stage_encrypts_without_activating(session):
    from metaguard_api.account_totp import AccountTotp

    assert stage_totp(
        session,
        "account-1",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        key=bytes(32),
        key_version=1,
        now=90,
        expires_at=120,
    )
    record = session.scalar(select(PendingTotp))
    assert (
        decrypt_totp_secret(bytes(32), "account-1", record.encrypted_secret)
        == "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    )
    assert record.expires_at == 120
    assert session.scalar(select(AccountTotp)) is None


def test_rejects_invalid_expiry_or_missing_account(session):
    assert not stage_totp(
        session,
        "missing",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        key=bytes(32),
        key_version=1,
        now=90,
        expires_at=120,
    )
    assert not stage_totp(
        session,
        "account-1",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        key=bytes(32),
        key_version=1,
        now=90,
        expires_at=90,
    )
    assert session.scalar(select(PendingTotp)) is None


def test_pending_can_be_staged_only_once(session):
    assert stage_totp(
        session,
        "account-1",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        key=bytes(32),
        key_version=1,
        now=90,
        expires_at=120,
    )
    assert not stage_totp(
        session,
        "account-1",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        key=bytes(32),
        key_version=1,
        now=90,
        expires_at=120,
    )


def test_expired_pending_is_removed_only_at_expiry_and_can_be_replaced(session):
    from metaguard_api.pending_totp import remove_expired_pending

    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    assert stage_totp(
        session, "account-1", secret, key=bytes(32), key_version=1, now=90, expires_at=120
    )
    session.commit()
    assert not remove_expired_pending(session, "account-1", now=119)
    assert not remove_expired_pending(session, "other", now=120)
    assert remove_expired_pending(session, "account-1", now=120)
    session.rollback()
    assert session.scalar(select(PendingTotp)) is not None
    assert remove_expired_pending(session, "account-1", now=120)
    assert stage_totp(
        session, "account-1", secret, key=bytes(32), key_version=1, now=120, expires_at=150
    )
    assert not remove_expired_pending(session, "account-1", now=120)
    assert session.scalar(select(PendingTotp.expires_at)) == 150


@pytest.mark.parametrize("now", [-1, True, 2**63, "120"])
def test_invalid_cleanup_time_fails_closed(session, now):
    from metaguard_api.pending_totp import remove_expired_pending

    assert not remove_expired_pending(session, "account-1", now=now)


def test_cleanup_never_removes_other_account_or_invalid_time(session):
    from metaguard_api.pending_totp import remove_expired_pending

    session.add(Account(id="account-2", email="two@example.test", password_hash="synthetic"))
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    assert stage_totp(
        session, "account-2", secret, key=bytes(32), key_version=1, now=1, expires_at=2
    )
    for now in [-1, True, 2**63, "2"]:
        assert not remove_expired_pending(session, "account-2", now=now)
    assert not remove_expired_pending(session, "account-1", now=2)
    assert session.scalar(select(PendingTotp.account_id)) == "account-2"
