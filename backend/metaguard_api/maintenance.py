"""Explicit maintenance commands; importing this module does not connect to a database."""

import argparse
import signal
import sys
import time
from datetime import UTC, datetime

from sqlalchemy import text

from metaguard_api.account_security_events import purge_expired_account_events
from metaguard_api.database import Database, DatabaseSettings, create_database
from metaguard_api.login_email_challenge import purge_expired_login_email_challenges
from metaguard_api.login_risk import purge_login_risk
from metaguard_api.password_reset import purge_password_reset_proofs
from metaguard_api.reports import purge_expired_reports
from metaguard_api.reputation_cache import purge_expired
from metaguard_api.security_alerts import purge_expired_security_alerts
from metaguard_api.system_security_events import purge_expired_events


def _purge_once(
    *,
    joint: bool,
    statement_timeout_ms: int | None = None,
    database: Database | None = None,
) -> int:
    """Run selected retention deletes in one transaction with generic errors."""
    try:
        if statement_timeout_ms is not None and (
            type(statement_timeout_ms) is not int or not 1 <= statement_timeout_ms <= 30_000
        ):
            raise ValueError("Invalid maintenance statement timeout")
        active_database = (
            database
            if database is not None
            else create_database(DatabaseSettings(), connect_timeout_seconds=3)
        )
        try:
            with active_database.transaction() as session:
                if (
                    statement_timeout_ms is not None
                    and session.get_bind().dialect.name == "postgresql"
                ):
                    session.execute(
                        text(f"SET LOCAL statement_timeout = '{statement_timeout_ms}ms'")
                    )
                current_time = time.time()
                now = int(current_time)
                deleted = purge_expired(session, now=now)
                if joint:
                    deleted_events = purge_expired_events(session, now=now)
                    deleted_reports = purge_expired_reports(session, now=now)
                    utc_now = datetime.fromtimestamp(current_time, tz=UTC)
                    deleted_password_resets = purge_password_reset_proofs(session, now=utc_now)
                    deleted_login_challenges = purge_expired_login_email_challenges(
                        session, now=utc_now
                    )
                    deleted_login_risk = purge_login_risk(session, now=utc_now)
                    deleted_account_events = purge_expired_account_events(session, now=utc_now)
                    deleted_security_alerts = purge_expired_security_alerts(session, now=utc_now)
        finally:
            if database is None:
                active_database.close()
    except Exception:
        message = (
            "Scheduled maintenance failed." if joint else "Reputation cache maintenance failed."
        )
        print(message, file=sys.stderr)
        return 1
    print(f"Purged {deleted} expired reputation cache entries.")
    if joint:
        print(f"Purged {deleted_events} expired system security events.")
        print(f"Purged {deleted_reports} expired file reports.")
        print(f"Purged {deleted_password_resets} expired password reset proofs.")
        print(f"Purged {deleted_account_events} expired account security events.")
        if deleted_login_challenges:
            print(f"Purged {deleted_login_challenges} expired email login challenges.")
        if deleted_login_risk:
            print(f"Purged {deleted_login_risk} expired login risk entries.")
        if deleted_security_alerts:
            print(f"Purged {deleted_security_alerts} expired security alert entries.")
    return 0


def purge_once() -> int:
    """Preserve the legacy cache-only command and output."""
    return _purge_once(joint=False)


def purge_maintenance_once() -> int:
    """Atomically purge matching cache, events, reports, and reset proof entries."""
    return _purge_once(joint=True)


def purge_maintenance_for_api(*, database: Database | None = None) -> int:
    """Run the joint purge with a server-side bound for API shutdown safety."""
    return _purge_once(
        joint=True,
        statement_timeout_ms=5000,
        database=database,
    )


def _purge_interval(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Interval must be an integer from 1 to 3600") from None
    if not 1 <= seconds <= 3600:
        raise argparse.ArgumentTypeError("Interval must be an integer from 1 to 3600")
    return seconds


class _StopFlag:
    def __init__(self) -> None:
        self.requested = False

    def request(self, *_args: object) -> None:
        # A signal handler must not acquire a lock held by the interrupted thread.
        self.requested = True


def _wait_for_interval(stop: _StopFlag, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    while not stop.requested:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 1))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run MetaGuard maintenance tasks.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("purge-reputation", help="Delete expired cache entries once.")
    commands.add_parser(
        "purge-maintenance", help="Delete expired cache, events, reports, and reset proofs once."
    )
    scheduled = commands.add_parser(
        "schedule-reputation",
        aliases=["schedule-maintenance"],
        help="Run expiration and retention maintenance periodically.",
    )
    scheduled.add_argument("--interval-seconds", type=_purge_interval, default=60)
    args = parser.parse_args(argv)

    if args.command == "purge-reputation":
        return purge_once()
    if args.command == "purge-maintenance":
        return purge_maintenance_once()

    stop = _StopFlag()
    previous = signal.signal(signal.SIGTERM, stop.request)
    try:
        while not stop.requested:
            purge_maintenance_once()
            _wait_for_interval(stop, args.interval_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGTERM, previous)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
