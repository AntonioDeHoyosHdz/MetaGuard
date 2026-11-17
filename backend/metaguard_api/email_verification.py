"""Private one-use email verification tokens; no public route or mail delivery."""

import secrets
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from metaguard_api.accounts import Account, EmailVerificationToken

_TOKEN_LENGTH = 43
_TOKEN_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _utc_datetime(value: datetime) -> datetime | None:
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        return None
    return value.astimezone(UTC)


def _lock_unverified_account(session: Session, account_id: str) -> bool:
    """Serialize token preparation and consumption on the owning account row."""
    result = session.execute(
        update(Account)
        .where(Account.id == account_id, Account.email_verified_at.is_(None))
        .values(id=Account.id)
    )
    return result.rowcount == 1


def prepare_email_verification(
    session: Session,
    account_id: str,
    *,
    now: datetime,
    expires_at: datetime,
) -> str | None:
    """Replace the account's pending token; caller owns commit and expiry policy."""
    current_time = _utc_datetime(now)
    expiration = _utc_datetime(expires_at)
    if (
        not isinstance(account_id, str)
        or not 1 <= len(account_id) <= 36
        or current_time is None
        or expiration is None
        or expiration <= current_time
    ):
        return None
    if not _lock_unverified_account(session, account_id):
        return None

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
