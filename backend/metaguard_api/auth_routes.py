"""Public authentication routes with caller-injected infrastructure."""

import hmac
import secrets
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Protocol

import jwt
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from metaguard_api.account_credentials import is_approved_password_hash
from metaguard_api.email_verification import consume_email_verification
from metaguard_api.first_factor import (
    FirstFactorStatus,
    InvalidDummyPasswordHash,
    check_first_factor,
)
from metaguard_api.registration import (
    InvalidRegistrationInput,
    RegistrationConflict,
)
from metaguard_api.registration_verification import register_account_with_email_verification
from metaguard_api.second_factor import check_second_factor
from metaguard_api.sessions import (
    consume_mfa_login_challenge,
    create_mfa_login_challenge,
    get_active_session,
    issue_session,
    revoke_session,
    verify_csrf_token,
)
from metaguard_api.settings import Settings

SESSION_COOKIE = "__Host-metaguard_session"
CSRF_COOKIE = "__Host-metaguard_csrf"
MFA_COOKIE = "__Host-metaguard_mfa"
CSRF_HEADER = "X-CSRF-Token"
_CSRF_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


class RateLimiter(Protocol):
    """Injected limiter; identity is minimized and client IP is never proxy-derived here."""

    def allow(self, action: str, client_ip: str, identity: str) -> bool: ...


class SessionFactory(Protocol):
    def begin(self) -> AbstractContextManager[Session]: ...


class EmailSender(Protocol):
    """Injected delivery boundary; verification tokens are passed only here."""

    def send_verification(self, email: str, token: str) -> None: ...


class _RejectAuthentication(Exception):
    """Rollback a provisional MFA-step update before returning a generic denial."""


@dataclass(frozen=True, slots=True)
class AuthRuntime:
    """Trusted runtime dependencies; no database or secret is read by this module."""

    session_factory: SessionFactory = field(repr=False, compare=False)
    rate_limiter: RateLimiter | None = field(repr=False, compare=False)
    signing_key: str = field(repr=False, compare=False)
    issuer: str
    audience: str
    dummy_password_hash: str = field(repr=False, compare=False)
    totp_encryption_key: bytes | None = field(repr=False, compare=False)
    totp_key_version: int | None
    session_lifetime: timedelta
    mfa_challenge_lifetime: timedelta
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    common_passwords: frozenset[str] | None = field(default=None, repr=False, compare=False)
    password_lookup: Callable[[str, dict[str, str]], str] | None = field(
        default=None, repr=False, compare=False
    )
    report_password_outage: Callable[[str], None] | None = field(
        default=None, repr=False, compare=False
    )
    email_sender: EmailSender | None = field(default=None, repr=False, compare=False)
    email_verification_lifetime: timedelta | None = None


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class MfaLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=1024)
    code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


class RegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class EmailVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, max_length=128)


def _error(status: int, code: str, message: str):
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message}},
        headers={"Cache-Control": "no-store"},
    )


def _runtime_ready(runtime: AuthRuntime | None) -> bool:
    if not isinstance(runtime, AuthRuntime):
        return False
    try:
        key_bytes = runtime.signing_key.encode("utf-8")
    except (AttributeError, UnicodeError):
        return False
    return (
        len(key_bytes) >= 32
        and bool(runtime.issuer)
        and bool(runtime.audience)
        and is_approved_password_hash(runtime.dummy_password_hash)
        and isinstance(runtime.totp_encryption_key, bytes)
        and len(runtime.totp_encryption_key) == 32
        and type(runtime.totp_key_version) is int
        and runtime.totp_key_version > 0
        and isinstance(runtime.session_lifetime, timedelta)
        and runtime.session_lifetime.total_seconds() >= 1
        and isinstance(runtime.mfa_challenge_lifetime, timedelta)
        and runtime.mfa_challenge_lifetime.total_seconds() >= 1
        and callable(getattr(runtime.session_factory, "begin", None))
        and runtime.rate_limiter is not None
        and callable(getattr(runtime.rate_limiter, "allow", None))
        and callable(runtime.now)
    )


def _registration_runtime_ready(runtime: AuthRuntime | None) -> bool:
    return (
        _runtime_ready(runtime)
        and isinstance(runtime.common_passwords, frozenset)
        and bool(runtime.common_passwords)
        and all(isinstance(value, str) and value for value in runtime.common_passwords)
        and callable(runtime.password_lookup)
        and callable(runtime.report_password_outage)
        and callable(getattr(runtime.email_sender, "send_verification", None))
        and isinstance(runtime.email_verification_lifetime, timedelta)
        and runtime.email_verification_lifetime.total_seconds() >= 1
    )


def _current_time(runtime: AuthRuntime) -> datetime | None:
    try:
        value = runtime.now()
        if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
            return None
        return value.astimezone(UTC)
    except (OverflowError, TypeError, ValueError):
        return None


def _client_ip(request: Request) -> str:
    return request.client.host if request.client is not None else "unknown"


def _identity(value: str) -> str:
    try:
        return sha256(value.strip().casefold().encode("utf-8")).hexdigest()
    except UnicodeError:
        return "invalid"


def _allow(runtime: AuthRuntime, request: Request, action: str, identity: str) -> bool | None:
    try:
        return bool(runtime.rate_limiter.allow(action, _client_ip(request), _identity(identity)))
    except Exception:
        return None


def _origin_and_csrf_valid(request: Request, settings: Settings) -> bool:
    origin = request.headers.get("origin")
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    header_token = request.headers.get(CSRF_HEADER, "")
    return (
        origin in settings.auth_allowed_origins
        and len(cookie_token) == 43
        and len(header_token) == 43
        and all(char in _CSRF_ALPHABET for char in cookie_token)
        and all(char in _CSRF_ALPHABET for char in header_token)
        and hmac.compare_digest(cookie_token, header_token)
    )


def _cookie_policy(settings: Settings) -> str:
    return settings.auth_cookie_samesite.capitalize()


def _set_cookie(response, name: str, value: str, settings: Settings, *, max_age: int) -> None:
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        path="/",
        secure=True,
        httponly=True,
        samesite=_cookie_policy(settings),
    )


def _clear_cookie(response, name: str, settings: Settings) -> None:
    response.delete_cookie(
        name,
        path="/",
        secure=True,
        httponly=True,
        samesite=_cookie_policy(settings),
    )


def _issue_mfa_challenge(
    session: Session,
    runtime: AuthRuntime,
    account_id: str,
    csrf_token: str,
    now: datetime,
) -> str | None:
    issued_at = int(now.timestamp())
    expires_at_seconds = issued_at + int(runtime.mfa_challenge_lifetime.total_seconds())
    if expires_at_seconds <= issued_at:
        return None
    expires_at = datetime.fromtimestamp(expires_at_seconds, UTC)
    challenge = jwt.encode(
        {
            "iss": runtime.issuer,
            "aud": runtime.audience,
            "iat": issued_at,
            "exp": expires_at_seconds,
            "sub": account_id,
            "jti": secrets.token_urlsafe(24),
            "purpose": "mfa_login",
        },
        runtime.signing_key,
        algorithm="HS256",
    )
    if not create_mfa_login_challenge(
        session,
        account_id,
        challenge,
        csrf_token,
        expires_at=expires_at,
    ):
        return None
    return challenge


def _decode_mfa_challenge(runtime: AuthRuntime, token: str | None, now: datetime) -> str | None:
    if not isinstance(token, str) or not 1 <= len(token) <= 8192:
        return None
    try:
        claims = jwt.decode(
            token,
            runtime.signing_key,
            algorithms=["HS256"],
            issuer=runtime.issuer,
            audience=runtime.audience,
            options={
                "require": ["iss", "aud", "iat", "exp", "sub", "jti", "purpose"],
                "verify_exp": False,
                "verify_iat": False,
            },
        )
    except (jwt.InvalidTokenError, TypeError, ValueError, OverflowError):
        return None
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    account_id = claims.get("sub")
    if (
        claims.get("purpose") != "mfa_login"
        or isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or not isinstance(account_id, str)
        or not 1 <= len(account_id) <= 36
        or not isinstance(claims.get("jti"), str)
        or not claims["jti"]
    ):
        return None
    now_seconds = int(now.timestamp())
    if issued_at > now_seconds or expires_at <= now_seconds:
        return None
    if expires_at - issued_at > int(runtime.mfa_challenge_lifetime.total_seconds()) + 1:
        return None
    return account_id


def _set_session_cookies(
    response, token: str, csrf_token: str, runtime: AuthRuntime, settings: Settings
):
    max_age = int(runtime.session_lifetime.total_seconds())
    _set_cookie(response, SESSION_COOKIE, token, settings, max_age=max_age)
    _set_cookie(response, CSRF_COOKIE, csrf_token, settings, max_age=max_age)
    _clear_cookie(response, MFA_COOKIE, settings)


def create_auth_router(settings: Settings, runtime: AuthRuntime | None) -> APIRouter:
    router = APIRouter(prefix="/v1/auth", tags=["auth"])

    @router.post("/register")
    def register(payload: RegistrationRequest, request: Request):
        if not _registration_runtime_ready(runtime):
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not _origin_and_csrf_valid(request, settings):
            return _error(403, "origin_or_csrf", "Origin or CSRF validation failed")
        allowed = _allow(runtime, request, "auth_register", payload.email)
        if allowed is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not allowed:
            return _error(429, "rate_limited", "Too many requests")
        now = _current_time(runtime)
        if now is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        email = payload.email.strip().lower()
        try:
            with runtime.session_factory.begin() as session:
                _, token = register_account_with_email_verification(
                    session,
                    email,
                    payload.password,
                    common_passwords=runtime.common_passwords,
                    lookup=runtime.password_lookup,
                    report_outage=runtime.report_password_outage,
                    now=now,
                    expires_at=now + runtime.email_verification_lifetime,
                )
                runtime.email_sender.send_verification(email, token)
            return JSONResponse(
                {"registered": True}, status_code=202, headers={"Cache-Control": "no-store"}
            )
        except RegistrationConflict:
            return _error(409, "registration_unavailable", "Registration could not be completed")
        except InvalidRegistrationInput:
            return _error(400, "invalid_registration", "Registration could not be completed")
        except Exception:
            return _error(503, "auth_unavailable", "Authentication is unavailable")

    @router.post("/verify-email")
    def verify_email(payload: EmailVerificationRequest, request: Request):
        if not _runtime_ready(runtime):
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not _origin_and_csrf_valid(request, settings):
            return _error(403, "origin_or_csrf", "Origin or CSRF validation failed")
        allowed = _allow(runtime, request, "auth_verify_email", "anonymous")
        if allowed is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not allowed:
            return _error(429, "rate_limited", "Too many requests")
        now = _current_time(runtime)
        if now is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        try:
            with runtime.session_factory.begin() as session:
                if not consume_email_verification(session, payload.token, now=now):
                    return _error(400, "invalid_verification", "Verification token is invalid")
            return JSONResponse({"verified": True}, headers={"Cache-Control": "no-store"})
        except Exception:
            return _error(503, "auth_unavailable", "Authentication is unavailable")

    @router.get("/status")
    def auth_status(request: Request):
        if not _runtime_ready(runtime):
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        origin = request.headers.get("origin")
        if origin is not None and origin not in settings.auth_allowed_origins:
            return _error(403, "origin_or_csrf", "Origin or CSRF validation failed")
        allowed = _allow(runtime, request, "auth_status", "anonymous")
        if allowed is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not allowed:
            return _error(429, "rate_limited", "Too many requests")
        now = _current_time(runtime)
        if now is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")

        session_token = request.cookies.get(SESSION_COOKIE)
        csrf_token = request.cookies.get(CSRF_COOKIE)
        if session_token:
            try:
                with runtime.session_factory.begin() as session:
                    active = get_active_session(
                        session,
                        session_token,
                        signing_key=runtime.signing_key,
                        issuer=runtime.issuer,
                        audience=runtime.audience,
                        now=now,
                    )
                    if active is not None:
                        if verify_csrf_token(active, csrf_token):
                            return JSONResponse(
                                {"authenticated": True, "csrf_token": csrf_token},
                                headers={"Cache-Control": "no-store"},
                            )
                        return JSONResponse(
                            {"authenticated": True, "csrf_token": None},
                            headers={"Cache-Control": "no-store"},
                        )
            except Exception:
                return _error(503, "auth_unavailable", "Authentication is unavailable")

        preauth_csrf = csrf_token or secrets.token_urlsafe(32)
        response = JSONResponse(
            {"authenticated": False, "csrf_token": preauth_csrf},
            headers={"Cache-Control": "no-store"},
        )
        if not csrf_token:
            _set_cookie(
                response,
                CSRF_COOKIE,
                preauth_csrf,
                settings,
                max_age=int(runtime.mfa_challenge_lifetime.total_seconds()),
            )
        if session_token:
            _clear_cookie(response, SESSION_COOKIE, settings)
            _clear_cookie(response, MFA_COOKIE, settings)
        return response

    @router.post("/login")
    def login(payload: LoginRequest, request: Request):
        if not _runtime_ready(runtime):
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not _origin_and_csrf_valid(request, settings):
            return _error(403, "origin_or_csrf", "Origin or CSRF validation failed")
        allowed = _allow(runtime, request, "auth_login", payload.email)
        if allowed is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not allowed:
            return _error(429, "rate_limited", "Too many requests")
        now = _current_time(runtime)
        if now is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")

        try:
            with runtime.session_factory.begin() as session:
                first = check_first_factor(
                    session,
                    payload.email,
                    payload.password,
                    dummy_password_hash=runtime.dummy_password_hash,
                )
                if first.status is FirstFactorStatus.MFA_REQUIRED and first.account_id:
                    csrf_token = request.cookies[CSRF_COOKIE]
                    challenge = _issue_mfa_challenge(
                        session, runtime, first.account_id, csrf_token, now
                    )
                    if challenge is None:
                        return _error(503, "auth_unavailable", "Authentication is unavailable")
                    response = JSONResponse(
                        {"authenticated": False, "mfa_required": True, "csrf_token": csrf_token},
                        headers={"Cache-Control": "no-store"},
                    )
                    _set_cookie(
                        response,
                        MFA_COOKIE,
                        challenge,
                        settings,
                        max_age=int(runtime.mfa_challenge_lifetime.total_seconds()),
                    )
                    return response
                if first.status is not FirstFactorStatus.PASSWORD_VERIFIED or not first.account_id:
                    return _error(401, "unauthorized", "Invalid credentials")
                issued = issue_session(
                    session,
                    first.account_id,
                    signing_key=runtime.signing_key,
                    issuer=runtime.issuer,
                    audience=runtime.audience,
                    now=now,
                    expires_at=now + runtime.session_lifetime,
                )
                if issued is None:
                    return _error(401, "unauthorized", "Invalid credentials")
            response = JSONResponse(
                {"authenticated": True, "csrf_token": issued.csrf_token},
                headers={"Cache-Control": "no-store"},
            )
            _set_session_cookies(
                response, issued.session_token, issued.csrf_token, runtime, settings
            )
            return response
        except InvalidDummyPasswordHash:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        except Exception:
            return _error(503, "auth_unavailable", "Authentication is unavailable")

    @router.post("/login/mfa")
    def login_mfa(payload: MfaLoginRequest, request: Request):
        if not _runtime_ready(runtime):
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not _origin_and_csrf_valid(request, settings):
            return _error(403, "origin_or_csrf", "Origin or CSRF validation failed")
        ip_allowed = _allow(runtime, request, "auth_login_mfa_ip", "anonymous")
        if ip_allowed is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not ip_allowed:
            return _error(429, "rate_limited", "Too many requests")
        now = _current_time(runtime)
        if now is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        challenge_token = request.cookies.get(MFA_COOKIE)
        account_id = _decode_mfa_challenge(runtime, challenge_token, now)
        if account_id is None:
            return _error(401, "unauthorized", "Invalid credentials")
        allowed = _allow(runtime, request, "auth_login_mfa_account", account_id)
        if allowed is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not allowed:
            return _error(429, "rate_limited", "Too many requests")
        try:
            with runtime.session_factory.begin() as session:
                consumed_account_id = consume_mfa_login_challenge(
                    session,
                    challenge_token,
                    request.cookies.get(CSRF_COOKIE, ""),
                    now=now,
                )
                if consumed_account_id != account_id:
                    raise _RejectAuthentication
                verified_account_id = check_second_factor(
                    session,
                    payload.email,
                    payload.password,
                    payload.code,
                    dummy_password_hash=runtime.dummy_password_hash,
                    key=runtime.totp_encryption_key,
                    key_version=runtime.totp_key_version,
                    now=int(now.timestamp()),
                )
                if verified_account_id != account_id:
                    raise _RejectAuthentication
                issued = issue_session(
                    session,
                    account_id,
                    signing_key=runtime.signing_key,
                    issuer=runtime.issuer,
                    audience=runtime.audience,
                    now=now,
                    expires_at=now + runtime.session_lifetime,
                )
                if issued is None:
                    raise _RejectAuthentication
            response = JSONResponse(
                {"authenticated": True, "csrf_token": issued.csrf_token},
                headers={"Cache-Control": "no-store"},
            )
            _set_session_cookies(
                response, issued.session_token, issued.csrf_token, runtime, settings
            )
            return response
        except _RejectAuthentication:
            return _error(401, "unauthorized", "Invalid credentials")
        except Exception:
            return _error(503, "auth_unavailable", "Authentication is unavailable")

    @router.post("/logout")
    def logout(request: Request):
        if not _runtime_ready(runtime):
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        allowed = _allow(runtime, request, "auth_logout", "anonymous")
        if allowed is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not allowed:
            return _error(429, "rate_limited", "Too many requests")
        if not _origin_and_csrf_valid(request, settings):
            return _error(403, "origin_or_csrf", "Origin or CSRF validation failed")
        now = _current_time(runtime)
        session_token = request.cookies.get(SESSION_COOKIE)
        if now is None or not session_token:
            return _error(401, "unauthorized", "Authentication is required")
        try:
            with runtime.session_factory.begin() as session:
                active = get_active_session(
                    session,
                    session_token,
                    signing_key=runtime.signing_key,
                    issuer=runtime.issuer,
                    audience=runtime.audience,
                    now=now,
                )
                csrf_token = request.cookies.get(CSRF_COOKIE, "")
                if active is None or not verify_csrf_token(active, csrf_token):
                    return _error(401, "unauthorized", "Authentication is required")
                account_allowed = _allow(runtime, request, "auth_logout_account", active.account_id)
                if account_allowed is None:
                    return _error(503, "auth_unavailable", "Authentication is unavailable")
                if not account_allowed:
                    return _error(429, "rate_limited", "Too many requests")
                revoked = revoke_session(
                    session,
                    session_token,
                    signing_key=runtime.signing_key,
                    issuer=runtime.issuer,
                    audience=runtime.audience,
                    now=now,
                )
                if not revoked:
                    return _error(401, "unauthorized", "Authentication is required")
            response = JSONResponse({"authenticated": False}, headers={"Cache-Control": "no-store"})
            _clear_cookie(response, SESSION_COOKIE, settings)
            _clear_cookie(response, CSRF_COOKIE, settings)
            _clear_cookie(response, MFA_COOKIE, settings)
            return response
        except Exception:
            return _error(503, "auth_unavailable", "Authentication is unavailable")

    return router
