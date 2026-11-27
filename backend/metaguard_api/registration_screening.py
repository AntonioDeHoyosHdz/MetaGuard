"""Private registration wiring; no public endpoint or delivery guarantee."""

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.orm import Session
from sqlalchemy.pool import SingletonThreadPool, StaticPool

from metaguard_api.accounts import Account
from metaguard_api.database import Database
from metaguard_api.pwned_passwords import fetch_password_range
from metaguard_api.registration_verification import register_account_with_email_verification
from metaguard_api.system_security_events import record_password_check_outage


@dataclass(frozen=True, slots=True)
class ScreenedRegistration:
    """Provisional registration and one-time token; commit before delivery."""

    account: Account
    token: str = field(repr=False)
    protection_reduced: bool = False


def register_with_screening(
    session: Session,
    event_database: Database,
    email: str,
    password: str,
    *,
    common_passwords: frozenset[str],
    now: datetime,
    expires_at: datetime,
    event_now: int,
) -> ScreenedRegistration:
    """Use fixed HIBP transport and independently persist reduced-mode events.

    The caller provides a fresh session bound to the event database engine;
    registration begins its transaction after outage reporting. Single-connection
    pools are unsupported. The caller owns commit or rollback of the result.
    No maintained list, mail transport, session or public route is supplied.
    """
    if (
        session.in_transaction()
        or session.get_bind() is not event_database.engine
        or isinstance(event_database.engine.pool, (SingletonThreadPool, StaticPool))
    ):
        raise ValueError("A fresh session and an independent-connection pool are required")
    reduced = False

    def report_outage(event: str) -> None:
        nonlocal reduced
        record_password_check_outage(event_database, event, now=event_now)
        reduced = True

    account, token = register_account_with_email_verification(
        session,
        email,
        password,
        common_passwords=common_passwords,
        lookup=fetch_password_range,
        report_outage=report_outage,
        now=now,
        expires_at=expires_at,
    )
    return ScreenedRegistration(account, token, reduced)
