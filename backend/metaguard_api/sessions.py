"""Private opaque session primitives; no HTTP routes or cookie policy."""

import hmac
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from metaguard_api.accounts import Account, AccountSession

_TOKEN_LENGTH = 43
_TOKEN_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


@dataclass(frozen=True)
class IssuedSession:
    """Raw credentials are returned once to a trusted caller and hidden from repr."""

    session_token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    expires_at: datetime


@dataclass(frozen=True)
class ActiveSession:
    """Verified session identity with private CSRF digest for the caller's request."""

    session_id: str
    account_id: str
    expires_at: datetime
    _csrf_digest: str = field(repr=False, compare=False)


def _utc_datetime(value: datetime) -> datetime | None:
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        return None
    return value.astimezone(UTC)


def _token_digest(token: str) -> str | None:
    if (
        not isinstance(token, str)
        or len(token) != _TOKEN_LENGTH
        or any(character not in _TOKEN_ALPHABET for character in token)
    ):
        return None
    return sha256(token.encode("ascii")).hexdigest()


def issue_session(
    session: Session,
    account_id: str,
    *,
    now: datetime,
    expires_at: datetime,
) -> IssuedSession | None:
    """Prepare a session after authentication; the caller supplies expiry and transaction."""
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

    verified_account_id = session.execute(
        select(Account.id).where(
            Account.id == account_id,
            Account.email_verified_at.is_not(None),
        )
    ).scalar_one_or_none()
    if verified_account_id is None:
        return None

    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    session.add(
        AccountSession(
            id=str(uuid4()),
            account_id=account_id,
            token_digest=sha256(session_token.encode("ascii")).hexdigest(),
            csrf_digest=sha256(csrf_token.encode("ascii")).hexdigest(),
            created_at=current_time,
            expires_at=expiration,
        )
    )
    return IssuedSession(session_token, csrf_token, expiration)


def get_active_session(
    session: Session,
    session_token: str,
    *,
    now: datetime,
) -> ActiveSession | None:
    """Return an unexpired, unrevoked identity without exposing the token digest."""
    current_time = _utc_datetime(now)
    token_digest = _token_digest(session_token)
    if current_time is None or token_digest is None:
        return None

    stored = session.execute(
        select(AccountSession).where(
            AccountSession.token_digest == token_digest,
            AccountSession.expires_at > current_time,
            AccountSession.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
    if stored is None:
        return None
    return ActiveSession(
        session_id=stored.id,
        account_id=stored.account_id,
        expires_at=stored.expires_at,
        _csrf_digest=stored.csrf_digest,
    )


def verify_csrf_token(active_session: ActiveSession | None, csrf_token: str) -> bool:
    """Constant-time compare a request token with the digest bound to its session."""
    if not isinstance(active_session, ActiveSession):
        return False
    expected_digest = active_session._csrf_digest
    candidate_digest = _token_digest(csrf_token)
    return candidate_digest is not None and hmac.compare_digest(expected_digest, candidate_digest)


def revoke_session(session: Session, session_token: str, *, now: datetime) -> bool:
    """Revoke one active session atomically; the caller owns commit or rollback."""
    current_time = _utc_datetime(now)
    token_digest = _token_digest(session_token)
    if current_time is None or token_digest is None:
        return False

    revoked_id = session.execute(
        update(AccountSession)
        .where(
            AccountSession.token_digest == token_digest,
            AccountSession.expires_at > current_time,
            AccountSession.revoked_at.is_(None),
        )
        .values(revoked_at=current_time)
        .returning(AccountSession.id)
        .execution_options(synchronize_session=False)
    ).scalar_one_or_none()
    return revoked_id is not None
