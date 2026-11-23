from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from sqlalchemy import create_engine, func, select

from metaguard_api.accounts import Account
from metaguard_api.database import Base, Database
from metaguard_api.login_email_challenge import (
    LoginEmailChallenge,
    LoginEmailProof,
    consume_login_email_challenge,
    prepare_login_email_challenge,
    purge_expired_login_email_challenges,
)
from metaguard_api.login_risk import login_address_digest

NOW = datetime(2026, 11, 21, tzinfo=UTC)
OWNER = "owner"


@pytest.fixture
def database():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    database = Database(engine)
    with database.transaction() as session:
        session.add(
            Account(
                id=OWNER,
                email="owner@example.invalid",
                password_hash="synthetic stored hash",
                email_verified_at=NOW,
            )
        )
    try:
        yield database
    finally:
        database.close()


def _address() -> str:
    digest = login_address_digest(OWNER, "192.0.2.10", "synthetic-signing-key")
    assert digest is not None
    return digest


def test_email_proofs_are_digest_only_bounded_and_not_redelivered_for_same_binding(database):
    csrf = "x" * 43
    address = _address()
    with database.transaction() as session:
        account = session.get(Account, OWNER)
        prepared = prepare_login_email_challenge(session, account, csrf, address, now=NOW)
        assert prepared is not None and prepared.code is not None
        assert prepared.code not in repr(prepared)
        repeated = prepare_login_email_challenge(session, account, csrf, address, now=NOW)
        assert repeated is not None and repeated.code is None
        stored = session.scalar(select(LoginEmailChallenge))
        assert stored.account_id == OWNER and stored.address_digest == address
        assert stored.csrf_digest == sha256(csrf.encode()).hexdigest()
        assert stored.code_digest == sha256(prepared.code.encode()).hexdigest()
        assert stored.password_version != account.password_hash
        assert stored.expires_at == NOW + timedelta(minutes=5)
        for n in range(7):
            assert prepare_login_email_challenge(session, account, str(n) * 43, address, now=NOW)
        assert prepare_login_email_challenge(session, account, "y" * 43, address, now=NOW) is None
        assert session.scalar(select(func.count()).select_from(LoginEmailChallenge)) == 8
        assert purge_expired_login_email_challenges(session, now=stored.expires_at) == 8


def test_consumption_rollback_keeps_proof_usable_until_a_successful_commit(database):
    csrf = "x" * 43
    address = _address()
    with database.transaction() as session:
        account = session.get(Account, OWNER)
        prepared = prepare_login_email_challenge(session, account, csrf, address, now=NOW)
        assert prepared is not None and prepared.code is not None
    with pytest.raises(RuntimeError, match="session failed"):
        with database.transaction() as session:
            account = session.get(Account, OWNER)
            assert (
                consume_login_email_challenge(
                    session, account, csrf, address, prepared.code, now=NOW
                )
                is LoginEmailProof.VERIFIED
            )
            session.flush()
            raise RuntimeError("session failed")
    with database.transaction() as session:
        account = session.get(Account, OWNER)
        assert (
            consume_login_email_challenge(session, account, csrf, address, prepared.code, now=NOW)
            is LoginEmailProof.VERIFIED
        )
    with database.transaction() as session:
        account = session.get(Account, OWNER)
        assert (
            consume_login_email_challenge(session, account, csrf, address, prepared.code, now=NOW)
            is LoginEmailProof.REJECTED
        )
