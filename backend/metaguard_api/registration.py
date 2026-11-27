"""Private registration orchestration; no HTTP route or authentication flow."""

from collections.abc import Callable
from uuid import uuid4

from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from metaguard_api.account_credentials import hash_password
from metaguard_api.accounts import Account
from metaguard_api.password_policy import PasswordScreeningResult, screen_password


class InvalidRegistrationInput(ValueError):
    """The supplied identity or password did not satisfy registration policy."""


class RegistrationConflict(RuntimeError):
    """Registration could not be completed for a generic persistence conflict."""


class RegistrationError(RuntimeError):
    """Registration could not be completed without exposing sensitive details."""


def register_account(
    session: Session,
    email: str,
    password: str,
    *,
    common_passwords: frozenset[str],
    lookup: Callable[[str, dict[str, str]], str],
    report_outage: Callable[[str], None],
) -> Account:
    """Add an account to the caller-owned transaction after password screening.

    Email verification and normalization are intentionally outside this service:
    only a bounded, already-lowercase identity is accepted. The caller controls
    transaction commit or rollback and must not grant access before its commit.
    """
    if (
        not isinstance(email, str)
        or not 3 <= len(email) <= 254
        or email != email.lower()
        or email.strip() != email
    ):
        raise InvalidRegistrationInput("Invalid registration input")

    screening = screen_password(
        password,
        common_passwords=common_passwords,
        lookup=lookup,
        report_outage=report_outage,
    )
    if screening == PasswordScreeningResult.REJECTED:
        raise InvalidRegistrationInput("Invalid registration input")

    account_id = str(uuid4())
    password_hash = hash_password(password)
    insert = {
        "sqlite": sqlite_insert,
        "postgresql": postgresql_insert,
    }.get(session.get_bind().dialect.name)
    if insert is None:
        raise RegistrationError("Registration could not be completed")

    statement = (
        insert(Account)
        .values(id=account_id, email=email, password_hash=password_hash)
        .on_conflict_do_nothing(index_elements=[Account.email])
        .returning(Account)
    )
    try:
        account = session.scalars(statement).one_or_none()
    except Exception:
        raise RegistrationError("Registration could not be completed") from None
    if account is None:
        raise RegistrationConflict("Registration could not be completed")
    return account
