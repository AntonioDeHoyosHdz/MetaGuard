"""Explicit maintenance commands; importing this module does not connect to a database."""

import argparse
import sys
import time

from metaguard_api.database import DatabaseSettings, create_database
from metaguard_api.reputation_cache import purge_expired


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run MetaGuard maintenance tasks.")
    parser.add_argument(
        "command", choices=["purge-reputation"], help="Delete expired cache entries."
    )
    parser.parse_args(argv)

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


if __name__ == "__main__":
    raise SystemExit(main())
