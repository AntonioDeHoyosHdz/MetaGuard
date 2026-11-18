"""Explicit maintenance commands; importing this module does not connect to a database."""

import argparse
import signal
import sys
import time

from metaguard_api.database import DatabaseSettings, create_database
from metaguard_api.reports import purge_expired_reports
from metaguard_api.reputation_cache import purge_expired
from metaguard_api.system_security_events import purge_expired_events


def _purge_once(*, include_security_events: bool, include_file_reports: bool = False) -> int:
    """Run selected retention deletes in one transaction with generic errors."""
    try:
        database = create_database(DatabaseSettings(), connect_timeout_seconds=3)
        try:
            with database.transaction() as session:
                now = int(time.time())
                deleted = purge_expired(session, now=now)
                deleted_events = (
                    purge_expired_events(session, now=now) if include_security_events else 0
                )
                deleted_reports = (
                    purge_expired_reports(session, now=now) if include_file_reports else 0
                )
        finally:
            database.close()
    except Exception:
        message = (
            "Scheduled maintenance failed."
            if include_security_events
            else "Reputation cache maintenance failed."
        )
        print(message, file=sys.stderr)
        return 1
    print(f"Purged {deleted} expired reputation cache entries.")
    if include_security_events:
        print(f"Purged {deleted_events} expired system security events.")
    if include_file_reports:
        print(f"Purged {deleted_reports} expired file reports.")
    return 0


def purge_once() -> int:
    """Preserve the legacy cache-only command and output."""
    return _purge_once(include_security_events=False)


def purge_maintenance_once() -> int:
    """Atomically purge cache, expired system events, and file reports."""
    return _purge_once(include_security_events=True, include_file_reports=True)


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
        "purge-maintenance", help="Delete expired cache entries and system events once."
    )
    scheduled = commands.add_parser(
        "schedule-reputation",
        aliases=["schedule-maintenance"],
        help="Run reputation and security-event retention periodically.",
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
