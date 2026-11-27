from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from metaguard_api.accounts import Account, EmailVerificationToken
from metaguard_api.database import Base
from metaguard_api.registration import RegistrationError
from metaguard_api.registration_verification import (
    register_account_with_email_verification,
)


def dependencies():
    return {
        "common_passwords": frozenset({"known-common-password"}),
        "lookup": lambda _prefix, _headers: "0" * 35 + ":1\n",
        "report_outage": lambda _event: None,
    }


@pytest.fixture
def engine(tmp_path):
    value = create_engine(f"sqlite:///{tmp_path / 'registration-verification.db'}")
    Base.metadata.create_all(value)
    yield value
    value.dispose()


def test_registration_and_verification_share_caller_transaction(engine):
    now = datetime(2026, 11, 16, tzinfo=UTC)
    expires_at = now + timedelta(minutes=30)
    password = "long synthetic registration password"

    with Session(engine) as session, session.begin():
        account, token = register_account_with_email_verification(
            session,
            "person@example.test",
            password,
            now=now,
            expires_at=expires_at,
            **dependencies(),
        )

        stored_account = session.get(Account, account.id)
        stored_token = session.get(EmailVerificationToken, account.id)
        assert stored_account is not None
        assert stored_account.password_hash.startswith("$argon2id$")
        assert stored_account.password_hash != password
        assert stored_token is not None
        assert stored_token.token_digest == sha256(token.encode("ascii")).hexdigest()
        assert stored_token.token_digest != token
        assert stored_token.expires_at == expires_at


def test_token_preparation_failure_rolls_back_both_records(engine):
    now = datetime(2026, 11, 16, tzinfo=UTC)

    with Session(engine) as writer:
        with pytest.raises(RegistrationError):
            with writer.begin():
                register_account_with_email_verification(
                    writer,
                    "person@example.test",
                    "long synthetic registration password",
                    now=now,
                    expires_at=now,
                    **dependencies(),
                )

    with Session(engine) as observer:
        assert observer.scalar(select(Account)) is None
        assert observer.scalar(select(EmailVerificationToken)) is None


def test_caller_rollback_removes_flushed_registration_and_verification(engine):
    now = datetime(2026, 11, 16, tzinfo=UTC)
    account_id = None

    with Session(engine) as writer:
        account, token = register_account_with_email_verification(
            writer,
            "person@example.test",
            "long synthetic registration password",
            now=now,
            expires_at=now + timedelta(minutes=30),
            **dependencies(),
        )
        account_id = account.id
        writer.flush()

        stored_token = writer.get(EmailVerificationToken, account_id)
        assert token
        assert stored_token is not None
        writer.rollback()

    with Session(engine) as observer:
        assert observer.get(Account, account_id) is None
        assert observer.get(EmailVerificationToken, account_id) is None
