from datetime import UTC, datetime, timedelta
from importlib import import_module

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, delete, func, inspect, select
from sqlalchemy.orm import Session

from metaguard_api import login_risk
from metaguard_api.accounts import Account
from metaguard_api.database import Base, Database
from metaguard_api.login_risk import (
    AccountFamiliarAddress,
    AccountLoginFailure,
    AccountLoginFailureOverflow,
    assess_login_risk,
    login_address_digest,
    purge_login_risk,
    record_login_failure,
    record_login_success,
)

NOW = datetime(2026, 11, 21, 15, tzinfo=UTC)
OWNER = "owner"
OTHER_OWNER = "other-owner"
KEY = "synthetic-test-key"


def _digest(host: int, owner: str = OWNER) -> str:
    digest = login_address_digest(owner, f"192.0.2.{host}", KEY)
    assert digest is not None
    return digest


@pytest.fixture
def database():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    database = Database(engine)
    try:
        with database.transaction() as session:
            session.add_all(
                Account(id=owner, email=f"{owner}@example.invalid", password_hash="unused")
                for owner in (OWNER, OTHER_OWNER)
            )
        yield database
    finally:
        database.close()


def test_address_digest_canonicalization_and_owner_binding():
    digest = _digest(10)
    assert digest.startswith("v1:") and len(digest) == 67
    assert digest == login_address_digest(OWNER, "::ffff:192.0.2.10", KEY)
    assert digest == login_address_digest(OWNER, "::FFFF:C000:20A", KEY)
    assert login_address_digest(OWNER, "2001:DB8:0:0:0:0:0:1", KEY) == login_address_digest(
        OWNER, "2001:db8::1", KEY
    )
    assert digest != _digest(10, OTHER_OWNER)
    assert digest != login_address_digest(OWNER, "192.0.2.10", "other-key")


@pytest.mark.parametrize(
    "address",
    [
        None,
        "",
        "unknown",
        "fe80::1%eth0",
        "192.0.2.10:80",
        " 192.0.2.10 ",
        "0.0.0.0",
        "::",
        "::ffff:0.0.0.0",
    ],
)
def test_invalid_address_never_becomes_a_shared_identifier(address):
    assert login_address_digest(OWNER, address, KEY) is None


def test_pair_lock_progresses_and_ignored_calls_do_not_renew_or_count(database):
    candidate = _digest(10)
    legitimate = _digest(11)
    now = NOW
    for lock_minutes in (1, 5, 15, 15):
        for _ in range(4):
            with database.transaction() as session:
                assert record_login_failure(session, OWNER, candidate, now=now).locked_until is None

        with database.transaction() as session:
            until = now + timedelta(minutes=lock_minutes)
            assert record_login_failure(session, OWNER, candidate, now=now).locked_until == until
            assert assess_login_risk(session, OWNER, legitimate, now=now).locked_until is None
            assert (
                assess_login_risk(
                    session, OTHER_OWNER, _digest(10, OTHER_OWNER), now=now
                ).locked_until
                is None
            )

        almost = until - timedelta(microseconds=1)
        for _ in range(6):
            with database.transaction() as session:
                assert (
                    record_login_failure(session, OWNER, candidate, now=almost).locked_until
                    == until
                )
        with database.transaction() as session:
            assert assess_login_risk(session, OWNER, candidate, now=until).locked_until is None
        now = until


def test_aggregate_risk_is_rolling_and_never_a_global_lock(database):
    address_a, address_b, address_c, legitimate = map(_digest, (10, 11, 12, 13))
    with database.transaction() as session:
        assert not record_login_success(session, OWNER, legitimate, now=NOW)
        assert not record_login_failure(session, OWNER, address_a, now=NOW).step_up
        assert not record_login_failure(
            session, OWNER, address_b, now=NOW + timedelta(minutes=1)
        ).step_up
        assert record_login_failure(
            session, OWNER, address_c, now=NOW + timedelta(minutes=2)
        ).step_up
        now = NOW + timedelta(minutes=15) - timedelta(microseconds=1)
        decision = assess_login_risk(session, OWNER, legitimate, now=now)
        assert decision.step_up and decision.locked_until is None
        assert assess_login_risk(session, OWNER, None, now=now).step_up
        assert not assess_login_risk(
            session, OTHER_OWNER, _digest(10, OTHER_OWNER), now=now
        ).step_up
        assert not assess_login_risk(
            session, OWNER, legitimate, now=NOW + timedelta(minutes=15)
        ).step_up


def test_completed_login_resets_only_its_pair_and_establishes_familiarity(database):
    first, second = _digest(10), _digest(11)
    with database.transaction() as session:
        for _ in range(5):
            record_login_failure(session, OWNER, first, now=NOW)
        for _ in range(4):
            record_login_failure(session, OWNER, second, now=NOW)
        assert not record_login_success(session, OWNER, None, now=NOW)

    now = NOW + timedelta(minutes=1)
    with database.transaction() as session:
        assert not record_login_success(session, OWNER, first, now=now)
        for _ in range(4):
            assert record_login_failure(session, OWNER, first, now=now).locked_until is None
        assert record_login_failure(session, OWNER, first, now=now).locked_until == now + timedelta(
            minutes=1
        )
        assert record_login_failure(session, OWNER, second, now=now).locked_until is not None

    now += timedelta(minutes=1)
    with database.transaction() as session:
        assert record_login_success(session, OWNER, second, now=now)
        assert not record_login_success(session, OWNER, second, now=now)
        assert not record_login_success(session, OWNER, first, now=now)
        assert not record_login_success(session, OTHER_OWNER, _digest(20, OTHER_OWNER), now=now)


def test_retention_boundary_defines_familiarity_and_purges_expired_state(database):
    first, second = _digest(10), _digest(11)
    with database.transaction() as session:
        assert not record_login_success(session, OWNER, first, now=NOW)
        record_login_failure(session, OWNER, first, now=NOW)
        record_login_failure(session, OWNER, second, now=NOW + timedelta(microseconds=1))
        assert not record_login_failure(session, OWNER, None, now=NOW).step_up
        assert session.scalar(select(func.count()).select_from(AccountLoginFailure)) == 2

    with database.transaction() as session:
        now = NOW + timedelta(days=30)
        purge_login_risk(session, now=now)
        assert session.scalar(select(func.count()).select_from(AccountLoginFailure)) == 1
        assert session.scalar(select(func.count()).select_from(AccountFamiliarAddress)) == 0
        assert not record_login_success(session, OWNER, second, now=now)


def test_new_success_requires_another_recent_completed_address(database):
    first, second = _digest(10), _digest(11)
    with database.transaction() as session:
        assert not record_login_success(session, OWNER, first, now=NOW)
        assert not record_login_success(session, OWNER, second, now=NOW + timedelta(days=30))


def test_flood_preserves_live_locks_familiarity_and_rolling_risk(database, monkeypatch):
    monkeypatch.setattr(login_risk, "MAX_LOGIN_FAILURE_ADDRESSES", 3)
    monkeypatch.setattr(login_risk, "MAX_FAMILIAR_ADDRESSES", 2)
    first, second, third, crowded_out, legitimate, another_legitimate = map(
        _digest, (10, 11, 12, 13, 14, 15)
    )
    with database.transaction() as session:
        assert not record_login_success(session, OWNER, legitimate, now=NOW)
        for _ in range(5):
            record_login_failure(session, OWNER, first, now=NOW)
        record_login_failure(session, OWNER, second, now=NOW)
        record_login_failure(session, OWNER, third, now=NOW)
        assert record_login_failure(session, OWNER, crowded_out, now=NOW).step_up
        assert session.scalar(select(func.count()).select_from(AccountLoginFailure)) == 3
        assert assess_login_risk(session, OWNER, first, now=NOW).locked_until == NOW + timedelta(
            minutes=1
        )
        assert not record_login_success(session, OWNER, legitimate, now=NOW)
        assert record_login_success(session, OWNER, another_legitimate, now=NOW)
        assert record_login_success(session, OWNER, second, now=NOW + timedelta(minutes=1))
        assert session.scalar(select(func.count()).select_from(AccountFamiliarAddress)) == 2
        assert assess_login_risk(
            session, OWNER, legitimate, now=NOW + timedelta(minutes=14)
        ).step_up
        now = NOW + timedelta(minutes=15)
        assert not assess_login_risk(session, OWNER, legitimate, now=now).step_up
        purge_login_risk(session, now=now)
        assert session.scalar(select(func.count()).select_from(AccountLoginFailureOverflow)) == 0
        record_login_failure(session, OWNER, crowded_out, now=now)
        assert session.get(AccountLoginFailure, (OWNER, crowded_out)) is not None


def test_migration_is_additive_and_cascades_on_account_deletion():
    migration = import_module("migrations.versions.0015_login_risk")
    assert migration.down_revision == "0014_security_alerts"
    with create_engine("sqlite://").begin() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys = ON")
        Account.__table__.create(connection)
        connection.execute(
            Account.__table__.insert(),
            [
                {"id": owner, "email": f"{owner}@example.invalid", "password_hash": "unused"}
                for owner in (OWNER, OTHER_OWNER)
            ],
        )
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
            tables = (AccountLoginFailure, AccountFamiliarAddress, AccountLoginFailureOverflow)
            for model in tables:
                columns = inspect(connection).get_columns(model.__tablename__)
                assert {column["name"] for column in columns} == {
                    column.name for column in model.__table__.c
                }
                assert inspect(connection).get_foreign_keys(model.__tablename__)[0]["options"] == {
                    "ondelete": "CASCADE"
                }
            with Session(connection) as session:
                record_login_success(session, OWNER, _digest(10), now=NOW)
                record_login_failure(session, OWNER, _digest(10), now=NOW)
                session.add(
                    AccountLoginFailureOverflow(
                        account_id=OWNER, expires_at=NOW + timedelta(minutes=15)
                    )
                )
                session.commit()
            assert [
                connection.scalar(select(func.count()).select_from(model)) for model in tables
            ] == [1, 1, 1]
            connection.execute(delete(Account).where(Account.id == OWNER))
            assert [
                connection.scalar(select(func.count()).select_from(model)) for model in tables
            ] == [0, 0, 0]
            migration.downgrade()
        assert inspect(connection).get_table_names() == ["accounts"]
        assert connection.scalar(select(Account.id)) == OTHER_OWNER
