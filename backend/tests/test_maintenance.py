import asyncio
import signal
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from threading import Event, RLock, current_thread
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine

from metaguard_api.database import Base, Database
from metaguard_api.file_maintenance import run_maintenance_cycle, run_maintenance_loop
from metaguard_api.file_routes import FileRuntime
from metaguard_api.file_storage import InMemoryTemporaryFileStore
from metaguard_api.main import create_app
from metaguard_api.maintenance import _StopFlag, _wait_for_interval, main
from metaguard_api.reputation_cache import CacheVerdict, get_verdict, save_verdict
from metaguard_api.settings import Settings

_NOW = datetime(2026, 1, 1, tzinfo=UTC)
_KEY = b"k" * 32


def _process_runtime(store):
    return SimpleNamespace(store=store, _uploads={}, _lock=RLock())


def test_app_lifespan_does_not_start_maintenance_without_file_dependencies(monkeypatch):
    started = []

    async def worker(*_args, **_kwargs):
        started.append(True)

    monkeypatch.setattr("metaguard_api.main.run_maintenance_loop", worker)
    app = create_app(Settings(_env_file=None, environment="test"))

    async def exercise_lifespan():
        async with app.router.lifespan_context(app):
            await asyncio.sleep(0)

    asyncio.run(exercise_lifespan())
    assert started == []


def test_app_lifespan_does_not_start_maintenance_without_database(monkeypatch):
    started = []

    async def worker(*_args, **_kwargs):
        started.append(True)

    monkeypatch.setattr("metaguard_api.main.run_maintenance_loop", worker)
    runtime = FileRuntime(
        store=InMemoryTemporaryFileStore(max_bytes=128),
        storage_key=_KEY,
        processing_client=object(),
    )
    app = create_app(Settings(_env_file=None, environment="test"), file_runtime=runtime)

    async def exercise_lifespan():
        async with app.router.lifespan_context(app):
            await asyncio.sleep(0)

    asyncio.run(exercise_lifespan())
    assert started == []


def test_app_lifespan_cancels_maintenance_worker_on_shutdown(monkeypatch):
    started = asyncio.Event()
    stopped = asyncio.Event()

    async def worker(*_args, **_kwargs):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    monkeypatch.setattr("metaguard_api.main.run_maintenance_loop", worker)
    database = Database(create_engine("sqlite:///:memory:"))
    runtime = FileRuntime(
        store=InMemoryTemporaryFileStore(max_bytes=128),
        storage_key=_KEY,
        processing_client=object(),
        database=database,
    )
    app = create_app(Settings(_env_file=None, environment="test"), file_runtime=runtime)

    async def exercise_lifespan():
        async with app.router.lifespan_context(app):
            await asyncio.wait_for(started.wait(), timeout=1)
            task = app.state.maintenance_task
        assert stopped.is_set()
        assert task.cancelled()

    try:
        asyncio.run(exercise_lifespan())
    finally:
        database.close()


def test_app_shutdown_waits_for_inflight_purge_thread(monkeypatch):
    purge_started = Event()
    release_purge = Event()
    purge_active = Event()
    purge_thread_exited = Event()
    lifespan_exited = Event()
    late_mutations = []
    mutation_threads = []

    def blocking_purge():
        purge_active.set()
        try:
            mutation_threads.append(current_thread().ident)
            purge_started.set()
            if not release_purge.wait(timeout=3):
                raise RuntimeError("Synthetic purge release timed out")
            if lifespan_exited.is_set():
                late_mutations.append("mutation after lifespan exit")
            return 0
        finally:
            purge_active.clear()
            purge_thread_exited.set()

    monkeypatch.setattr("metaguard_api.main.purge_maintenance_for_api", blocking_purge)
    database = Database(create_engine("sqlite:///:memory:"))
    runtime = FileRuntime(
        store=InMemoryTemporaryFileStore(max_bytes=128),
        storage_key=_KEY,
        processing_client=object(),
        database=database,
    )
    app = create_app(Settings(_env_file=None, environment="test"), file_runtime=runtime)

    async def exercise_lifespan():
        context = app.router.lifespan_context(app)
        await context.__aenter__()
        shutdown_task = None
        returned_early = False
        try:
            assert await asyncio.to_thread(purge_started.wait, 1)
            shutdown_task = asyncio.create_task(context.__aexit__(None, None, None))
            await asyncio.wait({shutdown_task}, timeout=0.05)
            returned_early = shutdown_task.done()
            if returned_early:
                lifespan_exited.set()
        finally:
            release_purge.set()
            if shutdown_task is not None:
                await asyncio.wait_for(shutdown_task, timeout=1)
            elif not app.state.maintenance_task.done():
                await context.__aexit__(None, None, None)
            lifespan_exited.set()

        return returned_early

    try:
        returned_early = asyncio.run(exercise_lifespan())
    finally:
        release_purge.set()
        database.close()

    assert not returned_early
    assert len(mutation_threads) == 1
    assert purge_thread_exited.is_set()
    assert not purge_active.is_set()
    assert late_mutations == []
    assert app.state.maintenance_task.done()
    assert app.state.maintenance_task.cancelled()


def test_api_purge_sets_a_bounded_postgres_statement_timeout(monkeypatch, capsys):
    from metaguard_api import maintenance

    statements = []

    class PostgresDialect:
        name = "postgresql"

    class FakeSession:
        def get_bind(self):
            return SimpleNamespace(dialect=PostgresDialect())

        def execute(self, statement):
            statements.append(str(statement))

    class FakeDatabase:
        def transaction(self):
            class Transaction:
                def __enter__(self):
                    return FakeSession()

                def __exit__(self, *_args):
                    return False

            return Transaction()

        def close(self):
            pass

    monkeypatch.setattr(
        "metaguard_api.maintenance.create_database", lambda *_a, **_k: FakeDatabase()
    )
    monkeypatch.setattr("metaguard_api.maintenance.purge_expired", lambda *_a, **_k: 0)
    monkeypatch.setattr("metaguard_api.maintenance.purge_expired_events", lambda *_a, **_k: 0)
    monkeypatch.setattr("metaguard_api.maintenance.purge_expired_reports", lambda *_a, **_k: 0)
    monkeypatch.setattr(
        "metaguard_api.maintenance.purge_password_reset_proofs", lambda *_a, **_k: 0
    )
    monkeypatch.setattr(
        "metaguard_api.maintenance.purge_expired_account_events", lambda *_a, **_k: 0
    )
    for helper in (
        "purge_expired_login_email_challenges",
        "purge_login_risk",
        "purge_expired_security_alerts",
    ):
        monkeypatch.setattr(maintenance, helper, lambda *_a, **_k: 0)

    assert maintenance.purge_maintenance_for_api() == 0
    assert statements == ["SET LOCAL statement_timeout = '5000ms'"]
    assert "Purged 0 expired file reports." in capsys.readouterr().out


def test_concurrent_maintenance_cycles_are_idempotent_and_use_each_process_store(caplog):
    first_store = InMemoryTemporaryFileStore(max_bytes=128)
    second_store = InMemoryTemporaryFileStore(max_bytes=128)
    for store, suffix in ((first_store, "first"), (second_store, "second")):
        assert store.put(
            f"expired-{suffix}",
            "owner",
            b"expired content",
            key=_KEY,
            now=_NOW - timedelta(minutes=10),
        )
        assert store.put(f"active-{suffix}", "owner", b"active content", key=_KEY, now=_NOW)
    database_rows = {"expired-cache-report-event"}
    calls = []
    database_lock = RLock()

    def purge_database():
        with database_lock:
            calls.append(len(database_rows))
            database_rows.clear()
        return 0

    first_runtime = _process_runtime(first_store)
    second_runtime = _process_runtime(second_store)
    first_runtime._uploads = {
        "expired-first": SimpleNamespace(expires_at=_NOW),
        "active-first": SimpleNamespace(expires_at=_NOW + timedelta(minutes=1)),
    }
    second_runtime._uploads = {
        "expired-second": SimpleNamespace(expires_at=_NOW),
        "active-second": SimpleNamespace(expires_at=_NOW + timedelta(minutes=1)),
    }

    async def exercise():
        await asyncio.gather(
            run_maintenance_cycle(purge_database, first_runtime, now=_NOW),
            run_maintenance_cycle(purge_database, second_runtime, now=_NOW),
        )

    asyncio.run(exercise())
    assert sorted(calls) == [0, 1]
    assert database_rows == set()
    assert first_store.size_bytes == len(b"active content")
    assert second_store.size_bytes == len(b"active content")
    assert first_store.get("active-first", "owner", key=_KEY, now=_NOW) == b"active content"
    assert second_store.get("active-second", "owner", key=_KEY, now=_NOW) == b"active content"
    assert set(first_runtime._uploads) == {"active-first"}
    assert set(second_runtime._uploads) == {"active-second"}
    assert "active content" not in caplog.text
    assert "expired content" not in caplog.text
    assert _KEY.hex() not in caplog.text


def test_database_failure_does_not_prevent_file_cleanup_or_log_sensitive_details(caplog):
    store = InMemoryTemporaryFileStore(max_bytes=128)
    assert store.put(
        "expired-file",
        "owner",
        b"secret file content",
        key=_KEY,
        now=_NOW - timedelta(minutes=10),
    )

    def fail_database_purge():
        raise RuntimeError("secret key content must not be logged")

    asyncio.run(run_maintenance_cycle(fail_database_purge, _process_runtime(store), now=_NOW))
    assert store.size_bytes == 0
    assert "secret" not in caplog.text
    assert "key content" not in caplog.text


def test_maintenance_worker_retries_after_failure_on_the_next_interval():
    results = iter([1, 0])
    calls = []
    waits = []

    def purge_database():
        result = next(results)
        calls.append(result)
        return result

    async def sleep(seconds):
        waits.append(seconds)
        if len(waits) == 2:
            raise asyncio.CancelledError

    async def exercise():
        with pytest.raises(asyncio.CancelledError):
            await run_maintenance_loop(
                purge_database,
                None,
                interval_seconds=60,
                clock=lambda: _NOW,
                sleep=sleep,
            )

    asyncio.run(exercise())
    assert calls == [1, 0]
    assert waits == [60, 60]


def test_clock_failure_does_not_skip_persisted_purge(caplog):
    calls = []

    def purge_database():
        calls.append("purged")
        return 0

    def fail_clock():
        raise RuntimeError("sensitive clock failure")

    async def sleep(_seconds):
        raise asyncio.CancelledError

    async def exercise():
        with pytest.raises(asyncio.CancelledError):
            await run_maintenance_loop(
                purge_database,
                None,
                clock=fail_clock,
                sleep=sleep,
            )

    asyncio.run(exercise())
    assert calls == ["purged"]
    assert "sensitive" not in caplog.text


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
    assert "Purged 0 expired file reports." in output
    check_db = Database(create_engine(url))
    with check_db.transaction() as session:
        assert len(session.scalars(select(SystemSecurityEvent)).all()) == 1
        assert session.scalar(select(SystemSecurityEvent.created_at)) == 200
    check_db.close()


def test_joint_maintenance_expires_login_proofs_risk_and_security_alerts(monkeypatch, capsys):
    from sqlalchemy import func, select

    from metaguard_api.accounts import Account
    from metaguard_api.login_email_challenge import (
        LoginEmailChallenge,
        prepare_login_email_challenge,
    )
    from metaguard_api.login_risk import (
        AccountFamiliarAddress,
        AccountLoginFailure,
        login_address_digest,
        record_login_failure,
        record_login_success,
    )
    from metaguard_api.maintenance import purge_maintenance_for_api
    from metaguard_api.security_alerts import SecurityAlertOutbox, enqueue_security_alert

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = Database(engine)
    stale = _NOW - timedelta(days=30)
    address = login_address_digest("owner", "192.0.2.50", "synthetic-test-key")
    assert address is not None
    with db.transaction() as session:
        owner = Account(
            id="owner",
            email="owner@example.invalid",
            password_hash="synthetic stored hash",
            email_verified_at=stale,
        )
        session.add(owner)
        session.flush()
        assert prepare_login_email_challenge(session, owner, "a" * 43, address, now=stale)
        assert not record_login_success(session, owner.id, address, now=stale)
        record_login_failure(session, owner.id, address, now=stale)
        assert enqueue_security_alert(session, owner.id, now=stale)

    monkeypatch.setattr("metaguard_api.maintenance.time.time", lambda: _NOW.timestamp())
    assert purge_maintenance_for_api(database=db) == 0
    output = capsys.readouterr().out
    assert "Purged 1 expired email login challenges." in output
    assert "Purged 2 expired login risk entries." in output
    assert "Purged 1 expired security alert entries." in output
    with db.transaction() as session:
        for table in (
            LoginEmailChallenge,
            AccountFamiliarAddress,
            AccountLoginFailure,
            SecurityAlertOutbox,
        ):
            assert session.scalar(select(func.count()).select_from(table)) == 0
        assert session.get(Account, "owner") is not None
    db.close()


def test_maintenance_purges_expired_reports_and_preserves_active_reports(
    tmp_path, monkeypatch, capsys
):
    from uuid import uuid4

    from metaguard_api.accounts import Account
    from metaguard_api.reports import FileReport

    url = f"sqlite:///{tmp_path / 'report-retention.sqlite'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    db = Database(engine)
    owner_id = str(uuid4())
    with db.transaction() as session:
        session.add(
            Account(
                id=owner_id,
                email="reports@example.test",
                password_hash="synthetic-hash",
            )
        )
        session.add_all(
            [
                FileReport(
                    id=str(uuid4()),
                    owner_id=owner_id,
                    report_json="{}",
                    created_at=1,
                    expires_at=99,
                ),
                FileReport(
                    id=str(uuid4()),
                    owner_id=owner_id,
                    report_json="{}",
                    created_at=1,
                    expires_at=101,
                ),
            ]
        )
    monkeypatch.setattr("metaguard_api.maintenance.create_database", lambda *_args, **_kwargs: db)
    monkeypatch.setattr("metaguard_api.maintenance.time.time", lambda: 100)

    assert main(["purge-maintenance"]) == 0
    assert "Purged 1 expired file reports." in capsys.readouterr().out
    check_db = Database(create_engine(url))
    with check_db.transaction() as session:
        assert len(session.query(FileReport).all()) == 1
    check_db.close()


def test_report_purge_failure_rolls_back_joint_maintenance(tmp_path, monkeypatch, capsys):
    from uuid import uuid4

    from metaguard_api.accounts import Account
    from metaguard_api.reports import FileReport, purge_expired_reports
    from metaguard_api.system_security_events import (
        SecurityEventType,
        SystemSecurityEvent,
        record_event,
    )

    url = f"sqlite:///{tmp_path / 'report-rollback.sqlite'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    db = Database(engine)
    owner_id = str(uuid4())
    with db.transaction() as session:
        session.add(
            Account(
                id=owner_id,
                email="rollback@example.test",
                password_hash="synthetic-hash",
            )
        )
        session.add(
            FileReport(
                id=str(uuid4()),
                owner_id=owner_id,
                report_json="{}",
                created_at=1,
                expires_at=99,
            )
        )
        record_event(session, SecurityEventType.PASSWORD_BREACH_CHECK_UNAVAILABLE, now=1)

    def fail_after_report_delete(session, *, now):
        purge_expired_reports(session, now=now)
        raise RuntimeError("synthetic report purge failure")

    monkeypatch.setattr("metaguard_api.maintenance.create_database", lambda *_args, **_kwargs: db)
    monkeypatch.setattr("metaguard_api.maintenance.purge_expired_reports", fail_after_report_delete)
    monkeypatch.setattr("metaguard_api.maintenance.time.time", lambda: 100)

    assert main(["purge-maintenance"]) == 1
    assert "synthetic" not in capsys.readouterr().err
    check_db = Database(create_engine(url))
    with check_db.transaction() as session:
        assert session.query(FileReport).count() == 1
        assert session.query(SystemSecurityEvent).count() == 1
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
