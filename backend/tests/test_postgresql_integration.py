"""Opt-in integration checks for the local disposable PostgreSQL test database."""

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pyotp
import pytest
from sqlalchemy import delete, select

from metaguard_api.account_credentials import hash_password
from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account
from metaguard_api.database import DatabaseSettings, create_database
from metaguard_api.pending_totp import PendingTotp, confirm_totp, stage_totp
from metaguard_api.totp_verification import consume_totp

pytestmark = pytest.mark.skipif(
    os.environ.get("METAGUARD_RUN_POSTGRES_TESTS") != "1",
    reason="Requires explicit opt-in and a disposable local metaguard_test PostgreSQL database",
)


def test_postgres_account_totp_activation_and_replay_race() -> None:
    settings = DatabaseSettings()
    if settings.host not in {"127.0.0.1", "localhost", "::1"} or settings.name != "metaguard_test":
        pytest.fail("PostgreSQL integration tests only allow loopback metaguard_test.")

    database = create_database(settings, connect_timeout_seconds=3)
    account_id = str(uuid4())
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    key = bytes(range(32))
    try:
        with database.transaction() as session:
            session.add(
                Account(
                    id=account_id,
                    email=f"{account_id}@example.test",
                    password_hash=hash_password("Synthetic PostgreSQL test password!"),
                )
            )
        with database.transaction() as session:
            assert stage_totp(
                session, account_id, secret, key=key, key_version=1, now=90, expires_at=300
            )
        with database.transaction() as session:
            assert confirm_totp(
                session,
                account_id,
                pyotp.TOTP(secret).at(90),
                key=key,
                key_version=1,
                now=90,
            )
        with database.transaction() as session:
            assert not consume_totp(
                session,
                account_id,
                pyotp.TOTP(secret).at(90),
                key=key,
                key_version=1,
                now=90,
            )
            assert consume_totp(
                session,
                account_id,
                pyotp.TOTP(secret).at(120),
                key=key,
                key_version=1,
                now=120,
            )

        barrier = Barrier(2)

        def consume_same_step() -> bool:
            with database.transaction() as session:
                barrier.wait(timeout=5)
                return consume_totp(
                    session,
                    account_id,
                    pyotp.TOTP(secret).at(150),
                    key=key,
                    key_version=1,
                    now=150,
                )

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(lambda _index: consume_same_step(), range(2))) == [False, True]

        with database.transaction() as session:
            assert (
                session.scalar(
                    select(AccountTotp.last_accepted_step).where(
                        AccountTotp.account_id == account_id
                    )
                )
                == 5
            )
            assert (
                session.scalar(
                    select(PendingTotp.account_id).where(PendingTotp.account_id == account_id)
                )
                is None
            )
    finally:
        with database.transaction() as session:
            session.execute(delete(Account).where(Account.id == account_id))
        database.close()
