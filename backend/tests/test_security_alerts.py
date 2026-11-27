from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine, delete, event, func, select, update
from sqlalchemy.orm import sessionmaker

from metaguard_api.accounts import Account
from metaguard_api.security_alerts import (
    SecurityAlertOutbox,
    dispatch_security_alerts,
    enqueue_security_alert,
    purge_expired_security_alerts,
)

NOW = datetime(2026, 11, 21, tzinfo=UTC)
EMAIL = "owner@example.test"


@pytest.fixture
def sessions(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'alerts.sqlite').as_posix()}")

    @event.listens_for(engine, "connect")
    def _foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys = ON")

    Account.__table__.create(engine)
    SecurityAlertOutbox.__table__.create(engine)
    try:
        yield sessionmaker(engine)
    finally:
        engine.dispose()


def _owner(sessions, account_id="owner", email=EMAIL, *, verified=True):
    with sessions.begin() as session:
        session.add(
            Account(
                id=account_id,
                email=email,
                email_verified_at=NOW if verified else None,
                password_hash="unused-synthetic-hash",
            )
        )


def _enqueue(sessions, account_id="owner", *, now=NOW):
    with sessions.begin() as session:
        return enqueue_security_alert(session, account_id, now=now)


def test_enqueues_only_verified_owners_with_no_private_payload_and_obeys_rollback(sessions):
    _owner(sessions)
    _owner(sessions, "unverified", "other@example.test", verified=False)

    assert not _enqueue(sessions, "missing")
    assert not _enqueue(sessions, "unverified")
    with sessions() as session:
        assert enqueue_security_alert(session, "owner", now=NOW)
        session.rollback()

    assert _enqueue(sessions)
    with sessions.begin() as session:
        assert session.scalar(select(func.count()).select_from(SecurityAlertOutbox)) == 1
        row = session.execute(select(SecurityAlertOutbox.__table__)).mappings().one()
        assert EMAIL not in row.values()
        assert not {"email", "ip", "payload"} & row.keys()


def test_concurrent_enqueue_coalesces_and_delivery_extends_rolling_cooldown(sessions):
    _owner(sessions)
    start = Barrier(2)

    def competitor():
        start.wait(timeout=5)
        return _enqueue(sessions)

    with ThreadPoolExecutor(max_workers=2) as pool:
        workers = [pool.submit(competitor) for _ in range(2)]
        assert sorted(worker.result(timeout=5) for worker in workers) == [False, True]

    sender = Mock()
    assert dispatch_security_alerts(sessions, sender, now=NOW + timedelta(minutes=2)) == 1
    sender.send_security_alert.assert_called_once_with(EMAIL)
    assert not _enqueue(sessions, now=NOW + timedelta(minutes=16, seconds=59))
    assert _enqueue(sessions, now=NOW + timedelta(minutes=17))


def test_recipient_is_currently_verified_and_account_deletion_cascades(sessions):
    _owner(sessions, "changed")
    _owner(sessions, "unverified", "unverified@example.test")
    _owner(sessions, "deleted", "deleted@example.test")
    for account_id in ("changed", "unverified", "deleted"):
        assert _enqueue(sessions, account_id)

    with sessions.begin() as session:
        session.execute(
            update(Account).where(Account.id == "changed").values(email="current@example.test")
        )
        session.execute(
            update(Account).where(Account.id == "unverified").values(email_verified_at=None)
        )
        session.execute(delete(Account).where(Account.id == "deleted"))
        assert session.get(SecurityAlertOutbox, "deleted") is None

    sender = Mock()
    assert dispatch_security_alerts(sessions, sender, now=NOW) == 1
    sender.send_security_alert.assert_called_once_with("current@example.test")


def test_backward_clock_after_submission_does_not_shorten_owner_cooldown(sessions):
    _owner(sessions)
    assert _enqueue(sessions)
    readings = iter((NOW, NOW, NOW - timedelta(minutes=5)))

    assert dispatch_security_alerts(sessions, Mock(), now=lambda: next(readings)) == 1
    assert not _enqueue(sessions, now=NOW + timedelta(minutes=10))
    assert _enqueue(sessions, now=NOW + timedelta(minutes=15))


def test_claim_is_committed_and_no_database_write_lock_is_held_during_transport(sessions):
    _owner(sessions)
    assert _enqueue(sessions)
    sender = Mock()
    rival_sender = Mock()

    def send(email):
        assert email == EMAIL
        # A competing worker must be able to write without taking the claimed item.
        assert dispatch_security_alerts(sessions, rival_sender, now=NOW) == 0
        with sessions.begin() as session:
            session.execute(update(Account).where(Account.id == "owner").values(email=EMAIL))

    sender.send_security_alert.side_effect = send
    assert dispatch_security_alerts(sessions, sender, now=NOW) == 1
    sender.send_security_alert.assert_called_once()
    rival_sender.send_security_alert.assert_not_called()


def test_abandoned_claim_is_reclaimed_without_allowing_a_stale_completion(sessions):
    _owner(sessions)
    assert _enqueue(sessions)
    crashed = Mock()
    crashed.send_security_alert.side_effect = KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        dispatch_security_alerts(sessions, crashed, now=NOW)

    recovered = Mock()
    assert dispatch_security_alerts(sessions, recovered, now=NOW + timedelta(seconds=1)) == 0
    assert dispatch_security_alerts(sessions, recovered, now=NOW + timedelta(minutes=3)) == 1
    assert dispatch_security_alerts(sessions, recovered, now=NOW + timedelta(minutes=6)) == 0
    recovered.send_security_alert.assert_called_once_with(EMAIL)

    assert _enqueue(sessions, now=NOW + timedelta(minutes=19))
    abandoned = Mock()
    abandoned.send_security_alert.side_effect = lambda _email: dispatch_security_alerts(
        sessions, recovered, now=NOW + timedelta(minutes=22)
    )
    assert dispatch_security_alerts(sessions, abandoned, now=NOW + timedelta(minutes=19)) == 0
    assert recovered.send_security_alert.call_count == 2


def test_failure_retries_with_backoff_but_never_persists_or_logs_provider_details(sessions, caplog):
    _owner(sessions)
    assert _enqueue(sessions)
    sender = Mock()
    sender.send_security_alert.side_effect = RuntimeError(f"provider secret {EMAIL}")

    for seconds, attempts in ((0, 1), (1, 1), (30, 2), (31, 2), (90, 3), (240, 3)):
        assert dispatch_security_alerts(sessions, sender, now=NOW + timedelta(seconds=seconds)) == 0
        assert sender.send_security_alert.call_count == attempts
    assert "provider secret" not in caplog.text
    assert EMAIL not in caplog.text


def test_delivery_ttl_and_purge_preserve_cooldown(sessions):
    _owner(sessions)
    assert _enqueue(sessions)
    sender = Mock()

    expiration = NOW + timedelta(minutes=10)
    assert dispatch_security_alerts(sessions, sender, now=expiration) == 0
    sender.send_security_alert.assert_not_called()
    with sessions.begin() as session:
        assert purge_expired_security_alerts(session, now=expiration) == 0
        assert purge_expired_security_alerts(session, now=NOW + timedelta(minutes=15)) == 1
        assert session.get(SecurityAlertOutbox, "owner") is None


def test_dispatch_limits_batch_and_refreshes_clock_between_recipients(sessions):
    for index in range(12):
        account_id = f"owner-{index:02}"
        _owner(sessions, account_id, f"{account_id}@example.test")
        assert _enqueue(sessions, account_id)

    sender = Mock()
    assert dispatch_security_alerts(sessions, sender, now=NOW, batch_size=200) == 10
    assert sender.send_security_alert.call_count == 10
    current_time = NOW

    def send(_email):
        nonlocal current_time
        current_time = NOW + timedelta(minutes=10)

    sender.send_security_alert.side_effect = send
    assert dispatch_security_alerts(sessions, sender, now=lambda: current_time) == 1
    assert sender.send_security_alert.call_count == 11
