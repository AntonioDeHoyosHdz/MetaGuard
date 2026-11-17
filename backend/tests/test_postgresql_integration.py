"""Opt-in integration checks for the local disposable PostgreSQL test database."""

import os
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from threading import Barrier
from uuid import uuid4

import pyotp
import pytest
from sqlalchemy import delete, select

from metaguard_api.account_credentials import hash_password, verify_password
from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account, EmailVerificationToken
from metaguard_api.database import DatabaseSettings, create_database
from metaguard_api.email_verification import consume_email_verification, prepare_email_verification
from metaguard_api.pending_totp import PendingTotp, confirm_totp, stage_totp
from metaguard_api.registration import RegistrationConflict, register_account
from metaguard_api.registration_verification import register_account_with_email_verification
from metaguard_api.totp_verification import consume_totp

pytestmark = pytest.mark.skipif(
    os.environ.get("METAGUARD_RUN_POSTGRES_TESTS") != "1",
    reason="Requires explicit opt-in and a disposable local metaguard_test PostgreSQL database",
)


def _create_disposable_database():
    settings = DatabaseSettings()
    if settings.host not in {"127.0.0.1", "localhost", "::1"} or settings.name != "metaguard_test":
        pytest.fail("PostgreSQL integration tests only allow loopback metaguard_test.")
    return create_database(settings, connect_timeout_seconds=3)


def _register(session, email: str, password: str) -> Account:
    return register_account(
        session,
        email,
        password,
        common_passwords=frozenset({"common synthetic password"}),
        lookup=lambda _prefix, _headers: "0" * 35 + ":0\n",
        report_outage=lambda _reason: pytest.fail("Unexpected password lookup outage."),
    )


def test_postgres_registration_persists_argon2_hash() -> None:
    database = _create_disposable_database()
    email = f"{uuid4()}@example.test"
    password = f"Synthetic PostgreSQL credential {uuid4()}!"
    account_id: str | None = None
    try:
        with database.transaction() as session:
            account = _register(session, email, password)
            account_id = account.id
            assert account.password_hash != password

        with database.transaction() as session:
            stored_hash = session.scalar(
                select(Account.password_hash).where(Account.id == account_id)
            )
        assert stored_hash is not None
        assert stored_hash.startswith("$argon2id$")
        assert stored_hash != password
        assert verify_password(password, stored_hash)
    finally:
        if account_id is not None:
            with database.transaction() as session:
                session.execute(delete(Account).where(Account.id == account_id))
        database.close()


def test_postgres_registration_duplicate_is_generic_and_transaction_remains_usable() -> None:
    database = _create_disposable_database()
    email = f"{uuid4()}@example.test"
    other_email = f"{uuid4()}@example.test"
    password = f"Synthetic PostgreSQL credential {uuid4()}!"
    other_password = f"Synthetic PostgreSQL credential {uuid4()}!"
    created_ids: list[str] = []
    try:
        with database.transaction() as session:
            existing = _register(session, email, password)
            created_ids.append(existing.id)

        with database.transaction() as session:
            with pytest.raises(RegistrationConflict) as error:
                _register(session, email, password)
            assert str(error.value) == "Registration could not be completed"
            assert email not in str(error.value)
            created_after_duplicate = _register(session, other_email, other_password)
            created_ids.append(created_after_duplicate.id)

        with database.transaction() as session:
            assert session.scalar(select(Account.id).where(Account.email == other_email)) == (
                created_after_duplicate.id
            )
    finally:
        if created_ids:
            with database.transaction() as session:
                session.execute(delete(Account).where(Account.id.in_(created_ids)))
        database.close()


def test_postgres_registration_respects_caller_rollback() -> None:
    from sqlalchemy.orm import Session

    database = _create_disposable_database()
    email = f"{uuid4()}@example.test"
    password = f"Synthetic PostgreSQL credential {uuid4()}!"
    account_id: str | None = None
    try:
        with Session(database.engine) as session:
            account = _register(session, email, password)
            account_id = account.id
            session.rollback()

        with database.transaction() as observer:
            assert observer.scalar(select(Account.id).where(Account.id == account_id)) is None
    finally:
        if account_id is not None:
            with database.transaction() as session:
                session.execute(delete(Account).where(Account.id == account_id))
        database.close()


def test_postgres_registration_verification_composes_and_rolls_back() -> None:
    from datetime import UTC, datetime, timedelta

    from sqlalchemy.orm import Session

    database = _create_disposable_database()
    email = f"{uuid4()}@example.test"
    password = f"Synthetic PostgreSQL credential {uuid4()}!"
    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=30)
    account_id: str | None = None
    account_ids: set[str] = set()
    try:
        with database.transaction() as session:
            account, token = register_account_with_email_verification(
                session,
                email,
                password,
                now=now,
                expires_at=expires_at,
                common_passwords=frozenset({"common synthetic password"}),
                lookup=lambda _prefix, _headers: "0" * 35 + ":0\n",
                report_outage=lambda _reason: pytest.fail("Unexpected password lookup outage."),
            )
            account_id = account.id
            account_ids.add(account_id)
            stored = session.get(EmailVerificationToken, account.id)
            assert stored is not None
            assert stored.token_digest == sha256(token.encode("ascii")).hexdigest()
            assert stored.token_digest != token
            assert stored.expires_at == expires_at

        rolled_back_email = f"{uuid4()}@example.test"
        with Session(database.engine) as writer:
            rolled_back_account, rolled_back_token = register_account_with_email_verification(
                writer,
                rolled_back_email,
                f"Synthetic PostgreSQL credential {uuid4()}!",
                now=now,
                expires_at=expires_at,
                common_passwords=frozenset({"common synthetic password"}),
                lookup=lambda _prefix, _headers: "0" * 35 + ":0\n",
                report_outage=lambda _reason: pytest.fail("Unexpected password lookup outage."),
            )
            rolled_back_account_id = rolled_back_account.id
            account_ids.add(rolled_back_account_id)
            writer.flush()
            stored_rollback_token = writer.get(EmailVerificationToken, rolled_back_account_id)
            assert stored_rollback_token is not None
            assert (
                stored_rollback_token.token_digest
                == sha256(rolled_back_token.encode("ascii")).hexdigest()
            )
            writer.rollback()

        assert rolled_back_token
        with database.transaction() as observer:
            assert (
                observer.scalar(select(Account.id).where(Account.email == rolled_back_email))
                is None
            )
            assert (
                observer.scalar(
                    select(EmailVerificationToken.account_id).where(
                        EmailVerificationToken.account_id == rolled_back_account_id
                    )
                )
                is None
            )
    finally:
        try:
            if account_ids:
                with database.transaction() as session:
                    session.execute(
                        delete(EmailVerificationToken).where(
                            EmailVerificationToken.account_id.in_(account_ids)
                        )
                    )
                    session.execute(delete(Account).where(Account.id.in_(account_ids)))
        finally:
            database.close()


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


def test_postgres_email_verification_digest_consume_and_race() -> None:
    from datetime import UTC, datetime, timedelta

    settings = DatabaseSettings()
    if settings.host not in {"127.0.0.1", "localhost", "::1"} or settings.name != "metaguard_test":
        pytest.fail("PostgreSQL integration tests only allow loopback metaguard_test.")
    database = create_database(settings, connect_timeout_seconds=3)
    account_id = str(uuid4())
    now = datetime.now(UTC)
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
            token = prepare_email_verification(
                session, account_id, now=now, expires_at=now + timedelta(minutes=30)
            )
        assert token is not None
        with database.transaction() as session:
            stored = session.get(EmailVerificationToken, account_id)
            assert stored is not None
            assert stored.token_digest == sha256(token.encode("utf-8")).hexdigest()
            assert stored.token_digest != token

        barrier = Barrier(2)

        def consume() -> bool:
            with database.transaction() as session:
                barrier.wait(timeout=5)
                return consume_email_verification(session, token, now=now + timedelta(minutes=1))

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(lambda _index: consume(), range(2))) == [False, True]
        with database.transaction() as session:
            account = session.get(Account, account_id)
            assert account is not None and account.email_verified_at == now + timedelta(minutes=1)
            assert session.get(EmailVerificationToken, account_id) is None
    finally:
        with database.transaction() as session:
            session.execute(delete(Account).where(Account.id == account_id))
        database.close()
