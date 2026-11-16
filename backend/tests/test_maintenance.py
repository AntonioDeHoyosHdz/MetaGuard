import signal
import subprocess
import sys

import pytest
from sqlalchemy import create_engine

from metaguard_api.database import Base, Database
from metaguard_api.maintenance import _StopFlag, _wait_for_interval, main
from metaguard_api.reputation_cache import CacheVerdict, get_verdict, save_verdict


def test_command_help_is_available_without_database() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "metaguard_api.maintenance", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "purge-reputation" in result.stdout


def test_invalid_command_never_opens_database(monkeypatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Database must not be opened")

    monkeypatch.setattr("metaguard_api.maintenance.create_database", fail)
    with pytest.raises(SystemExit) as result:
        main(["not-a-command"])
    assert result.value.code == 2


def test_purge_command_commits_only_expired_entries(tmp_path, monkeypatch, capsys) -> None:
    url = f"sqlite:///{tmp_path / 'cache.sqlite'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    db = Database(engine)
    with db.transaction() as session:
        save_verdict(session, "a" * 64, CacheVerdict.NO_RECORD, now=100)
        save_verdict(session, "b" * 64, CacheVerdict.MALICIOUS, now=200)
    monkeypatch.setattr("metaguard_api.maintenance.create_database", lambda *_args, **_kwargs: db)
    monkeypatch.setattr("metaguard_api.maintenance.time.time", lambda: 86_500)

    assert main(["purge-reputation"]) == 0
    assert capsys.readouterr().out == "Purged 1 expired reputation cache entries.\n"
    check_db = Database(create_engine(url))
    with check_db.transaction() as session:
        assert get_verdict(session, "a" * 64, now=100) is None
        assert get_verdict(session, "b" * 64, now=200) == CacheVerdict.MALICIOUS
    check_db.close()


def test_purge_failure_rolls_back_and_hides_details(tmp_path, monkeypatch, capsys) -> None:
    url = f"sqlite:///{tmp_path / 'cache.sqlite'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    db = Database(engine)
    with db.transaction() as session:
        save_verdict(session, "a" * 64, CacheVerdict.NO_RECORD, now=100)
        from metaguard_api.system_security_events import (
            SecurityEventType,
            record_event,
        )

        record_event(session, SecurityEventType.PASSWORD_BREACH_CHECK_UNAVAILABLE, now=100)

    def fail_after_delete(session, *, now):
        from metaguard_api.reputation_cache import purge_expired

        purge_expired(session, now=now)
        from metaguard_api.system_security_events import purge_expired_events

        purge_expired_events(session, now=now)
        raise RuntimeError("sensitive error details")

    monkeypatch.setattr("metaguard_api.maintenance.create_database", lambda *_args, **_kwargs: db)
    monkeypatch.setattr("metaguard_api.maintenance.purge_expired", fail_after_delete)
    monkeypatch.setattr("metaguard_api.maintenance.time.time", lambda: 100_000)
    assert main(["purge-maintenance"]) == 1
    assert "sensitive" not in capsys.readouterr().err
    check_db = Database(create_engine(url))
    with check_db.transaction() as session:
        assert get_verdict(session, "a" * 64, now=100) == CacheVerdict.NO_RECORD
        from sqlalchemy import select

        from metaguard_api.system_security_events import SystemSecurityEvent

        assert len(session.scalars(select(SystemSecurityEvent)).all()) == 1
    check_db.close()


def test_scheduler_retries_failed_runs_and_stops(monkeypatch) -> None:
    runs = iter([1, 0])
    calls = []
    waits = []

    def purge_once():
        result = next(runs)
        calls.append(result)
        return result

    def wait(stop, seconds):
        waits.append(seconds)
        if len(waits) == 2:
            stop.requested = True

    monkeypatch.setattr("metaguard_api.maintenance._wait_for_interval", wait)
    monkeypatch.setattr("metaguard_api.maintenance.purge_maintenance_once", purge_once)
    assert main(["schedule-reputation", "--interval-seconds", "60"]) == 0
    assert calls == [1, 0]
    assert waits == [60, 60]


@pytest.mark.parametrize("interval", ["0", "3601", "invalid"])
def test_scheduler_rejects_invalid_interval_without_connecting(monkeypatch, interval) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Database must not be opened")

    monkeypatch.setattr("metaguard_api.maintenance.create_database", fail)
    with pytest.raises(SystemExit) as result:
        main(["schedule-reputation", "--interval-seconds", interval])
    assert result.value.code == 2


def test_scheduler_stops_on_sigterm_and_restores_handler(monkeypatch) -> None:
    previous = signal.getsignal(signal.SIGTERM)
    stops = []

    def wait(stop, _seconds):
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        stops.append(stop.requested)

    monkeypatch.setattr("metaguard_api.maintenance._wait_for_interval", wait)
    monkeypatch.setattr("metaguard_api.maintenance.purge_maintenance_once", lambda: 0)
    assert main(["schedule-reputation"]) == 0
    assert stops == [True]
    assert signal.getsignal(signal.SIGTERM) == previous


def test_wait_uses_monotonic_time_and_one_second_sleeps(monkeypatch) -> None:
    ticks = iter([100.0, 100.0, 101.0, 102.0])
    sleeps = []
    monkeypatch.setattr("metaguard_api.maintenance.time.monotonic", lambda: next(ticks))
    monkeypatch.setattr("metaguard_api.maintenance.time.sleep", sleeps.append)
    _wait_for_interval(_StopFlag(), 2)
    assert sleeps == [1, 1]


def test_real_sigterm_during_wait_exits_without_deadlock() -> None:
    code = """
import inspect, signal, sys
from metaguard_api import maintenance
calls = []
maintenance.purge_maintenance_once = lambda: calls.append(1) or 0
previous = signal.getsignal(signal.SIGTERM)
source, offset = inspect.getsourcelines(maintenance._wait_for_interval)
sleep_line = offset + next(i for i, line in enumerate(source) if 'time.sleep(' in line)
def trace(frame, event, arg):
    if (event == 'line' and frame.f_code is maintenance._wait_for_interval.__code__
            and frame.f_lineno == sleep_line):
        sys.settrace(None)
        signal.raise_signal(signal.SIGTERM)
    return trace
sys.settrace(trace)
assert maintenance.main(['schedule-reputation']) == 0
assert calls == [1]
assert signal.getsignal(signal.SIGTERM) == previous
"""
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=15
    )
    assert result.returncode == 0, result.stderr


def test_purge_command_also_enforces_security_event_retention(tmp_path, monkeypatch, capsys):
    from sqlalchemy import select

    from metaguard_api.system_security_events import (
        SecurityEventType,
        SystemSecurityEvent,
        record_event,
    )

    url = f"sqlite:///{tmp_path / 'retention.sqlite'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    db = Database(engine)
    with db.transaction() as session:
        record_event(session, SecurityEventType.PASSWORD_BREACH_CHECK_UNAVAILABLE, now=100)
        record_event(session, SecurityEventType.PASSWORD_BREACH_CHECK_UNAVAILABLE, now=200)
    monkeypatch.setattr("metaguard_api.maintenance.create_database", lambda *_args, **_kwargs: db)
    monkeypatch.setattr("metaguard_api.maintenance.time.time", lambda: 100 + 30 * 24 * 60 * 60)

    assert main(["purge-maintenance"]) == 0
    output = capsys.readouterr().out
    assert "Purged 0 expired reputation cache entries." in output
    assert "1 expired system security events" in output
    check_db = Database(create_engine(url))
    with check_db.transaction() as session:
        assert len(session.scalars(select(SystemSecurityEvent)).all()) == 1
        assert session.scalar(select(SystemSecurityEvent.created_at)) == 200
    check_db.close()


def test_legacy_reputation_purge_does_not_require_security_event_schema(
    tmp_path, monkeypatch, capsys
):
    from metaguard_api.reputation_cache import ReputationEntry

    url = f"sqlite:///{tmp_path / 'legacy.sqlite'}"
    engine = create_engine(url)
    ReputationEntry.__table__.create(engine)
    db = Database(engine)
    monkeypatch.setattr("metaguard_api.maintenance.create_database", lambda *_args, **_kwargs: db)
    assert main(["purge-reputation"]) == 0
    assert capsys.readouterr().out == "Purged 0 expired reputation cache entries.\n"
    db.close()


def test_schedule_maintenance_alias_runs_joint_retention(monkeypatch):
    calls = []

    def stop_after_first_run(stop, _seconds):
        stop.requested = True

    monkeypatch.setattr("metaguard_api.maintenance._wait_for_interval", stop_after_first_run)
    monkeypatch.setattr(
        "metaguard_api.maintenance.purge_maintenance_once", lambda: calls.append("joint") or 0
    )
    assert main(["schedule-maintenance"]) == 0
    assert calls == ["joint"]
