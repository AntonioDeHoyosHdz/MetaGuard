import asyncio
import logging
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from metaguard_api.accounts import Account
from metaguard_api.auth_routes import AuthRuntime
from metaguard_api.database import Base
from metaguard_api.main import create_app
from metaguard_api.security_alert_dispatch import run_security_alert_dispatch_loop
from metaguard_api.security_alerts import enqueue_security_alert


def test_dispatch_retry_logs_only_a_fixed_message(caplog):
    calls = 0

    def dispatch():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("synthetic-private-recipient@example.test")

    async def sleep(seconds):
        assert seconds == 5
        if calls == 2:
            raise asyncio.CancelledError

    with caplog.at_level(logging.WARNING), pytest.raises(asyncio.CancelledError):
        asyncio.run(run_security_alert_dispatch_loop(dispatch, sleep=sleep))

    assert calls == 2
    assert caplog.messages == ["Scheduled security alert dispatch failed."]


def test_dispatch_shutdown_waits_for_in_flight_bounded_batch():
    started, release, finished = (Event() for _ in range(3))

    def dispatch():
        started.set()
        if release.wait(3):
            finished.set()

    async def verify():
        task = asyncio.create_task(run_security_alert_dispatch_loop(dispatch))
        try:
            assert await asyncio.to_thread(started.wait, 3)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert finished.is_set()

    asyncio.run(verify())


def test_app_dispatches_only_with_an_explicit_alert_sender(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'alert.db'}")
    try:
        Base.metadata.create_all(engine)
        sessions = sessionmaker(engine)
        now = datetime(2026, 11, 21, tzinfo=UTC)
        with sessions.begin() as session:
            session.add(
                Account(
                    id="owner",
                    email="activity@example.test",
                    password_hash="unused",
                    email_verified_at=now,
                )
            )
            session.flush()
            assert enqueue_security_alert(session, "owner", now=now)
        auth = AuthRuntime(
            session_factory=sessions,
            rate_limiter=None,
            signing_key="synthetic-key",
            issuer="test",
            audience="test",
            dummy_password_hash="unused",
            totp_encryption_key=None,
            totp_key_version=None,
            session_lifetime=timedelta(minutes=15),
            mfa_challenge_lifetime=timedelta(minutes=5),
            now=lambda: now,
        )
        with TestClient(create_app(auth_runtime=auth)) as disabled:
            assert disabled.app.state.security_alert_task is None

        delivered = Event()
        recipients = []

        class Capture:
            def send_security_alert(self, email):
                recipients.append(email)
                delivered.set()

        with TestClient(create_app(auth_runtime=auth, security_alert_sender=Capture())) as enabled:
            assert delivered.wait(3)
            assert recipients == ["activity@example.test"]
        assert enabled.app.state.security_alert_task.cancelled()
    finally:
        engine.dispose()
