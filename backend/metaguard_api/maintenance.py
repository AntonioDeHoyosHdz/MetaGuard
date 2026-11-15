"""Explicit maintenance commands; importing this module does not connect to a database."""

import argparse
import signal
import sys
import time

from metaguard_api.database import DatabaseSettings, create_database
from metaguard_api.reputation_cache import purge_expired


def purge_once() -> int:
    """Run one transaction, reporting failures without sensitive details."""
    try:
        database = create_database(DatabaseSettings(), connect_timeout_seconds=3)
        try:
            with database.transaction() as session:
                deleted = purge_expired(session, now=int(time.time()))
        finally:
            database.close()
    except Exception:
        print("Reputation cache maintenance failed.", file=sys.stderr)
        return 1
    print(f"Purged {deleted} expired reputation cache entries.")
    return 0


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
    scheduled = commands.add_parser("schedule-reputation", help="Run the purge periodically.")
    scheduled.add_argument("--interval-seconds", type=_purge_interval, default=60)
    args = parser.parse_args(argv)

    if args.command == "purge-reputation":
        return purge_once()

    stop = _StopFlag()
    previous = signal.signal(signal.SIGTERM, stop.request)
    try:
        while not stop.requested:
            purge_once()
            _wait_for_interval(stop, args.interval_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGTERM, previous)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
