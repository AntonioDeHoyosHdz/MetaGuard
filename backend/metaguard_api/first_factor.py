"""Private first-factor check; it does not create an authenticated session."""

from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.orm import Session

from metaguard_api.account_credentials import is_approved_password_hash, verify_password
from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account


class FirstFactorStatus(StrEnum):
    REJECTED = "rejected"
    MFA_REQUIRED = "mfa_required"
    PASSWORD_VERIFIED = "password_verified"


@dataclass(frozen=True, slots=True)
class FirstFactorResult:
    status: FirstFactorStatus
    account_id: str | None = None


class InvalidDummyPasswordHash(ValueError):
    """The caller did not provide a hash using the approved Argon2id profile."""


def _valid_email(email: object) -> bool:
    if (
        not isinstance(email, str)
        or not 3 <= len(email) <= 254
        or email != email.lower()
        or email.strip() != email
        or email.count("@") != 1
        or "\x00" in email
    ):
        return False
    local, domain = email.split("@", maxsplit=1)
    if not local or not domain:
        return False
    try:
        email.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def check_first_factor(
    session: Session,
    email: str,
    password: str,
    *,
    dummy_password_hash: str,
) -> FirstFactorResult:
    """Check credentials without committing, issuing a session, or consuming MFA.

    The caller supplies a non-user Argon2id hash using the approved password
    profile. Unknown or malformed identities use that hash to keep rejection
    work comparable to a normal password verification. A verified password is
    only the first factor; callers must not treat it as authenticated access.
    """
    if not is_approved_password_hash(dummy_password_hash):
        raise InvalidDummyPasswordHash("An approved dummy password hash is required")

    account = None
    if _valid_email(email):
        with session.no_autoflush:
            account = session.execute(
                select(Account.id, Account.password_hash, Account.email_verified_at).where(
                    Account.email == email
                )
            ).one_or_none()

    if account is None or not is_approved_password_hash(account.password_hash):
        verify_password(password, dummy_password_hash)
        return FirstFactorResult(FirstFactorStatus.REJECTED)

    account_id, password_hash, email_verified_at = account
    if not verify_password(password, password_hash) or email_verified_at is None:
        return FirstFactorResult(FirstFactorStatus.REJECTED)

    with session.no_autoflush:
        has_totp = (
            session.scalar(
                select(AccountTotp.account_id).where(AccountTotp.account_id == account_id)
            )
            is not None
        )
    if has_totp:
        return FirstFactorResult(FirstFactorStatus.MFA_REQUIRED, account_id)

    return FirstFactorResult(FirstFactorStatus.PASSWORD_VERIFIED, account_id)
