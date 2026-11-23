"""Private one-use email verification tokens; no public route or mail delivery."""

import secrets
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from metaguard_api.account_credentials import is_approved_password_hash, verify_password
from metaguard_api.accounts import Account, EmailVerificationToken
from metaguard_api.first_factor import _valid_email

_TOKEN_LENGTH = 43
_TOKEN_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _utc_datetime(value: datetime) -> datetime | None:
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        return None
    return value.astimezone(UTC)


def _lock_unverified_account(
    session: Session, account_id: str, *, expected_password_hash: str | None = None
) -> bool:
    """Serialize token preparation and consumption on the owning account row."""
    statement = update(Account).where(Account.id == account_id, Account.email_verified_at.is_(None))
    if expected_password_hash is not None:
        statement = statement.where(Account.password_hash == expected_password_hash)
    result = session.execute(statement.values(id=Account.id))
    return result.rowcount == 1


def _verification_expiration(now: datetime, expires_at: datetime) -> datetime | None:
    current_time = _utc_datetime(now)
    expiration = _utc_datetime(expires_at)
    if current_time is None or expiration is None or expiration <= current_time:
        return None
    return expiration


def prepare_email_verification(
    session: Session,
    account_id: str,
    *,
    now: datetime,
    expires_at: datetime,
) -> str | None:
    """Replace the account's pending token; caller owns commit and expiry policy."""
    expiration = _verification_expiration(now, expires_at)
    if not isinstance(account_id, str) or not 1 <= len(account_id) <= 36 or expiration is None:
        return None
    if not _lock_unverified_account(session, account_id):
        return None
    return _replace_email_verification(session, account_id, expiration)


def prepare_email_verification_resend(
    session: Session,
    email: str,
    password: str,
    *,
    dummy_password_hash: str,
    now: datetime,
    expires_at: datetime,
) -> str | None:
    """Authorize rotation without authenticating the account or granting a session."""
    expiration = _verification_expiration(now, expires_at)
    if expiration is None:
        return None
    account = (
        session.execute(
            select(
                Account.id,
                Account.password_hash,
                Account.email_verified_at,
                EmailVerificationToken.token_digest,
            )
            .outerjoin(EmailVerificationToken, EmailVerificationToken.account_id == Account.id)
            .where(Account.email == email)
        ).one_or_none()
        if _valid_email(email)
        else None
    )
    approved_hash = account is not None and is_approved_password_hash(account.password_hash)
    password_ok = verify_password(
        password, account.password_hash if approved_hash else dummy_password_hash
    )
    if not (
        account is not None and approved_hash and password_ok and account.email_verified_at is None
    ):
        return None
    if not _lock_unverified_account(
        session, account.id, expected_password_hash=account.password_hash
    ):
        return None

    # A concurrent resend may already have replaced this snapshot. Do not send a second
    # replacement for the same prior state, even from a different API process.
    current_digest = session.scalar(
        select(EmailVerificationToken.token_digest).where(
            EmailVerificationToken.account_id == account.id
        )
    )
    if current_digest != account.token_digest:
        return None
    return _replace_email_verification(session, account.id, expiration)


def _replace_email_verification(session: Session, account_id: str, expiration: datetime) -> str:
    token = secrets.token_urlsafe(32)
    token_digest = sha256(token.encode("ascii")).hexdigest()
    session.execute(
        delete(EmailVerificationToken)
        .where(EmailVerificationToken.account_id == account_id)
        .execution_options(synchronize_session=False)
    )
    session.add(
        EmailVerificationToken(
            account_id=account_id,
            token_digest=token_digest,
            expires_at=expiration,
        )
    )
    return token


class _VerificationRejected(Exception):
    """Roll back only the savepoint when the account state changed unexpectedly."""


def consume_email_verification(session: Session, token: str, *, now: datetime) -> bool:
    """Consume a matching, unexpired token and verify its account in caller transaction."""
    current_time = _utc_datetime(now)
    if (
        not isinstance(token, str)
        or len(token) != _TOKEN_LENGTH
        or any(character not in _TOKEN_ALPHABET for character in token)
        or current_time is None
    ):
        return False
    token_digest = sha256(token.encode("utf-8")).hexdigest()
    account_id = session.execute(
        update(Account)
        .where(
            Account.id.in_(
                select(EmailVerificationToken.account_id).where(
                    EmailVerificationToken.token_digest == token_digest,
                    EmailVerificationToken.expires_at > current_time,
                )
            ),
            Account.email_verified_at.is_(None),
        )
        .values(id=Account.id)
        .returning(Account.id)
        .execution_options(synchronize_session="fetch")
    ).scalar_one_or_none()
    if account_id is None:
        return False

    try:
        with session.begin_nested():
            verified_account_id = session.execute(
                update(Account)
                .where(
                    Account.id == account_id,
                    Account.email_verified_at.is_(None),
                )
                .values(email_verified_at=current_time)
                .returning(Account.id)
                .execution_options(synchronize_session="fetch")
            ).scalar_one_or_none()
            if verified_account_id is None:
                raise _VerificationRejected
            deleted_account_id = session.execute(
                delete(EmailVerificationToken)
                .where(
                    EmailVerificationToken.account_id == account_id,
                    EmailVerificationToken.token_digest == token_digest,
                    EmailVerificationToken.expires_at > current_time,
                )
                .returning(EmailVerificationToken.account_id)
                .execution_options(synchronize_session="fetch")
            ).scalar_one_or_none()
            if deleted_account_id is None:
                raise _VerificationRejected
    except _VerificationRejected:
        return False
    return True
