"""Private JWT session primitives; no HTTP routes or cookie policy."""

import hmac
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import jwt
from sqlalchemy import CheckConstraint, ForeignKey, Index, String, delete, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column

from metaguard_api.accounts import Account, AccountSession, UTCDateTime
from metaguard_api.database import Base

_TOKEN_LENGTH = 43
_TOKEN_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_REQUIRED_CLAIMS = ["iss", "aud", "iat", "exp", "sub", "jti"]


class MfaLoginChallenge(Base):
    """Persist only one-use MFA challenge and issuing-CSRF digests."""

    __tablename__ = "mfa_login_challenges"
    __table_args__ = (
        CheckConstraint(
            "length(challenge_digest) = 64", name="ck_mfa_login_challenge_digest_length"
        ),
        CheckConstraint("length(csrf_digest) = 64", name="ck_mfa_login_csrf_digest_length"),
        Index("ix_mfa_login_challenges_expires_at", "expires_at"),
    )

    challenge_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    csrf_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


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
    if not isinstance(token, str) or not 1 <= len(token) <= 8192:
        return None
    try:
        return sha256(token.encode("ascii")).hexdigest()
    except UnicodeEncodeError:
        return None


def _valid_configuration(signing_key: str, issuer: str, audience: str) -> bool:
    if not isinstance(signing_key, str):
        return False
    try:
        key_length = len(signing_key.encode("utf-8"))
    except UnicodeEncodeError:
        return False
    return (
        key_length >= 32
        and isinstance(issuer, str)
        and bool(issuer)
        and isinstance(audience, str)
        and bool(audience)
    )


def create_mfa_login_challenge(
    session: Session,
    account_id: str,
    challenge_token: str,
    csrf_token: str,
    *,
    expires_at: datetime,
) -> bool:
    """Stage a challenge bound to its CSRF token; the caller owns the transaction."""
    challenge_digest = _token_digest(challenge_token)
    csrf_digest = _token_digest(csrf_token)
    expiration = _utc_datetime(expires_at)
    if (
        not isinstance(account_id, str)
        or not 1 <= len(account_id) <= 36
        or challenge_digest is None
        or csrf_digest is None
        or expiration is None
    ):
        return False
    session.add(
        MfaLoginChallenge(
            challenge_digest=challenge_digest,
            account_id=account_id,
            csrf_digest=csrf_digest,
            expires_at=expiration,
        )
    )
    return True


def consume_mfa_login_challenge(
    session: Session,
    challenge_token: str,
    csrf_token: str,
    *,
    now: datetime,
) -> str | None:
    """Atomically consume one unexpired challenge in the caller's transaction."""
    challenge_digest = _token_digest(challenge_token)
    csrf_digest = _token_digest(csrf_token)
    current_time = _utc_datetime(now)
    if challenge_digest is None or csrf_digest is None or current_time is None:
        return None
    return session.execute(
        delete(MfaLoginChallenge)
        .where(
            MfaLoginChallenge.challenge_digest == challenge_digest,
            MfaLoginChallenge.csrf_digest == csrf_digest,
            MfaLoginChallenge.expires_at > current_time,
        )
        .returning(MfaLoginChallenge.account_id)
        .execution_options(synchronize_session=False)
    ).scalar_one_or_none()


def get_mfa_login_challenge_expiry(
    session: Session,
    account_id: str,
    challenge_token: str,
    csrf_token: str,
    *,
    now: datetime,
) -> datetime | None:
    """Read an unexpired, browser-bound challenge without consuming it."""
    challenge_digest = _token_digest(challenge_token)
    csrf_digest = _token_digest(csrf_token)
    current_time = _utc_datetime(now)
    if challenge_digest is None or csrf_digest is None or current_time is None:
        return None
    return session.scalar(
        select(MfaLoginChallenge.expires_at).where(
            MfaLoginChallenge.account_id == account_id,
            MfaLoginChallenge.challenge_digest == challenge_digest,
            MfaLoginChallenge.csrf_digest == csrf_digest,
            MfaLoginChallenge.expires_at > current_time,
        )
    )


def _decode_claims(
    token: str,
    *,
    signing_key: str,
    issuer: str,
    audience: str,
    now: datetime,
) -> dict | None:
    if not _valid_configuration(signing_key, issuer, audience):
        return None
    current_time = _utc_datetime(now)
    if current_time is None or _token_digest(token) is None:
        return None

    try:
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["HS256"],
            issuer=issuer,
            audience=audience,
            options={"require": _REQUIRED_CLAIMS, "verify_exp": False, "verify_iat": False},
        )
    except (jwt.InvalidTokenError, TypeError, ValueError, OverflowError):
        return None

    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, (int, float))
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or not isinstance(claims.get("sub"), str)
        or not claims["sub"]
        or not isinstance(claims.get("jti"), str)
        or not claims["jti"]
    ):
        return None
    try:
        issued_time = datetime.fromtimestamp(issued_at, UTC)
        expiration = datetime.fromtimestamp(expires_at, UTC)
    except (OverflowError, OSError, ValueError):
        return None
    if issued_time > current_time or expiration <= current_time or expiration <= issued_time:
        return None
    return claims


def issue_session(
    session: Session,
    account_id: str,
    *,
    signing_key: str,
    issuer: str,
    audience: str,
    now: datetime,
    expires_at: datetime,
) -> IssuedSession | None:
    """Prepare a signed JWT session; the caller supplies policy and transaction."""
    current_time = _utc_datetime(now)
    expiration = _utc_datetime(expires_at)
    if (
        not isinstance(account_id, str)
        or not 1 <= len(account_id) <= 36
        or current_time is None
        or expiration is None
        or expiration <= current_time
        or not _valid_configuration(signing_key, issuer, audience)
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

    session_id = str(uuid4())
    session_token = jwt.encode(
        {
            "iss": issuer,
            "aud": audience,
            "iat": current_time.timestamp(),
            "exp": expiration.timestamp(),
            "sub": account_id,
            "jti": session_id,
        },
        signing_key,
        algorithm="HS256",
    )
    csrf_token = secrets.token_urlsafe(32)
    session.add(
        AccountSession(
            id=session_id,
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
    signing_key: str,
    issuer: str,
    audience: str,
    now: datetime,
    lock_for_update: bool = False,
) -> ActiveSession | None:
    """Verify fixed-algorithm JWT claims and require a live, unrevoked DB row."""
    claims = _decode_claims(
        session_token,
        signing_key=signing_key,
        issuer=issuer,
        audience=audience,
        now=now,
    )
    token_digest = _token_digest(session_token)
    current_time = _utc_datetime(now)
    if claims is None or token_digest is None or current_time is None:
        return None

    statement = select(AccountSession).where(
        AccountSession.id == claims["jti"],
        AccountSession.account_id == claims["sub"],
        AccountSession.token_digest == token_digest,
        AccountSession.expires_at > current_time,
        AccountSession.revoked_at.is_(None),
    )
    if lock_for_update:
        statement = statement.with_for_update()
    stored = session.execute(statement).scalar_one_or_none()
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


def revoke_session(
    session: Session,
    session_token: str,
    *,
    signing_key: str,
    issuer: str,
    audience: str,
    now: datetime,
) -> bool:
    """Conditionally revoke a valid JWT; the caller owns commit or rollback."""
    claims = _decode_claims(
        session_token,
        signing_key=signing_key,
        issuer=issuer,
        audience=audience,
        now=now,
    )
    current_time = _utc_datetime(now)
    token_digest = _token_digest(session_token)
    if claims is None or current_time is None or token_digest is None:
        return False

    revoked_id = session.execute(
        update(AccountSession)
        .where(
            AccountSession.id == claims["jti"],
            AccountSession.account_id == claims["sub"],
            AccountSession.token_digest == token_digest,
            AccountSession.expires_at > current_time,
            AccountSession.revoked_at.is_(None),
        )
        .values(revoked_at=current_time)
        .returning(AccountSession.id)
        .execution_options(synchronize_session=False)
    ).scalar_one_or_none()
    return revoked_id is not None
