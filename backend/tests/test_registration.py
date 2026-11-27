import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session

from metaguard_api.accounts import Account
from metaguard_api.database import Base
from metaguard_api.registration import (
    InvalidRegistrationInput,
    RegistrationConflict,
    register_account,
)


@pytest.fixture
def session():
    engine = create_engine("sqlite://")

    @event.listens_for(engine, "connect")
    def disable_legacy_transaction_control(connection, _record):
        connection.isolation_level = None

    @event.listens_for(engine, "begin")
    def begin_transaction(connection):
        connection.exec_driver_sql("BEGIN")

    Base.metadata.create_all(engine)
    with Session(engine) as value:
        yield value
    engine.dispose()


def dependencies(
    *, report_outage=lambda event: None, lookup=lambda prefix, headers: "0" * 35 + ":1\n"
):
    return {
        "common_passwords": frozenset({"known-common-password"}),
        "lookup": lookup,
        "report_outage": report_outage,
    }


def test_register_persists_only_argon2_hash(session):
    password = "long synthetic registration password"
    account = register_account(session, "person@example.test", password, **dependencies())

    stored = session.scalar(select(Account).where(Account.id == account.id))
    assert stored is account
    assert stored.email == "person@example.test"
    assert stored.password_hash.startswith("$argon2id$")
    assert stored.password_hash != password


def test_screening_rejection_does_not_write_account(session):
    with pytest.raises(InvalidRegistrationInput):
        register_account(
            session,
            "person@example.test",
            "known-common-password",
            **dependencies(),
        )

    assert session.scalar(select(Account)) is None


def test_outage_event_failure_fails_closed_before_account_write(session):
    events = []

    def fail_event(event):
        events.append(event)
        raise RuntimeError("event storage unavailable")

    def unavailable_lookup(prefix, headers):
        raise OSError("offline")

    with pytest.raises(RuntimeError, match="event storage unavailable"):
        register_account(
            session,
            "person@example.test",
            "long synthetic registration password",
            **dependencies(report_outage=fail_event, lookup=unavailable_lookup),
        )

    assert events == ["password_breach_check_unavailable"]
    assert session.scalar(select(Account)) is None


def test_duplicate_is_generic_and_outer_transaction_remains_usable(session):
    params = dependencies()
    register_account(session, "person@example.test", "first synthetic password long", **params)

    with pytest.raises(RegistrationConflict) as error:
        register_account(session, "person@example.test", "second synthetic password long", **params)

    assert str(error.value) == "Registration could not be completed"
    assert "person@example.test" not in str(error.value)
    assert "synthetic" not in str(error.value)
    assert (
        register_account(
            session, "other@example.test", "third synthetic password long", **params
        ).email
        == "other@example.test"
    )
    assert session.scalar(select(Account).where(Account.email == "person@example.test")) is not None


def test_caller_rollback_removes_registered_account(session):
    account = register_account(
        session,
        "person@example.test",
        "long synthetic registration password",
        **dependencies(),
    )
    assert session.get(Account, account.id) is not None
    session.rollback()

    assert session.scalar(select(Account)) is None


def test_noncanonical_email_is_rejected_without_normalization(session):
    with pytest.raises(InvalidRegistrationInput):
        register_account(
            session,
            "Person@example.test",
            "long synthetic registration password",
            **dependencies(),
        )
    assert session.scalar(select(Account)) is None


def test_caller_rollback_on_default_sqlite_transaction_control(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'registration.db'}")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as writer:
            register_account(
                writer,
                "person@example.test",
                "long synthetic registration password",
                **dependencies(),
            )
            writer.rollback()

        with Session(engine) as verifier:
            assert verifier.scalar(select(Account)) is None
    finally:
        engine.dispose()
