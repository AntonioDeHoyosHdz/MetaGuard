"""Private registration with email-verification preparation; no delivery or route."""

from collections.abc import Callable
from datetime import datetime

from sqlalchemy.orm import Session

from metaguard_api.accounts import Account
from metaguard_api.email_verification import prepare_email_verification
from metaguard_api.registration import RegistrationError, register_account


def register_account_with_email_verification(
    session: Session,
    email: str,
    password: str,
    *,
    common_passwords: frozenset[str],
    lookup: Callable[[str, dict[str, str]], str],
    report_outage: Callable[[str], None],
    now: datetime,
    expires_at: datetime,
) -> tuple[Account, str]:
    """Compose private account creation and token preparation in caller transaction.

    The caller supplies the clock values and controls commit or rollback. The raw
    verification token is returned once in memory; only its digest is persisted.
    No savepoint is opened here, so an exception lets the caller-owned transaction
    roll back both the account and any token record.
    """
    account = register_account(
        session,
        email,
        password,
        common_passwords=common_passwords,
        lookup=lookup,
        report_outage=report_outage,
    )
    token = prepare_email_verification(
        session,
        account.id,
        now=now,
        expires_at=expires_at,
    )
    if token is None:
        raise RegistrationError("Registration could not be completed")
    return account, token
