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
