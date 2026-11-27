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
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask, BackgroundTasks
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from metaguard_api.account_credentials import is_approved_password_hash, verify_password
from metaguard_api.account_security_events import (
    AccountSecurityEventKind,
    account_event_task,
    record_account_event,
    save_account_event,
)
from metaguard_api.accounts import Account
from metaguard_api.email_verification import (
    consume_email_verification,
    prepare_email_verification_resend,
)
from metaguard_api.first_factor import (
    FirstFactorStatus,
    InvalidDummyPasswordHash,
    _valid_email,
    check_first_factor,
)
from metaguard_api.login_email_challenge import (
    LoginEmailProof,
    consume_login_email_challenge,
    has_active_login_email_challenge,
    prepare_login_email_challenge,
)
from metaguard_api.login_risk import (
    LoginRisk,
    assess_login_risk,
    login_address_digest,
    record_login_failure,
    record_login_success,
)
from metaguard_api.registration import (
    InvalidRegistrationInput,
    RegistrationConflict,
)
from metaguard_api.registration_verification import register_account_with_email_verification
from metaguard_api.second_factor import check_second_factor
from metaguard_api.security_alerts import enqueue_security_alert
from metaguard_api.sessions import (
    IssuedSession,
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
_AUTH_BODY_LIMIT = 8192  # Fits bounded fields even when all characters use JSON escapes.


class RateLimiter(Protocol):
    """Injected limiter; identity is minimized and client IP is never proxy-derived here."""

    def allow(self, action: str, client_ip: str, identity: str) -> bool: ...


class SessionFactory(Protocol):
    def begin(self) -> AbstractContextManager[Session]: ...


class EmailSender(Protocol):
    """Injected delivery boundary for short-lived authentication email codes."""

    def send_verification(self, email: str, token: str) -> None: ...

    def send_password_reset(self, email: str, code: str) -> None: ...

    def send_login_challenge(self, email: str, code: str) -> None: ...


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
    login_risk_enabled: bool = False
    verification_delivery_after_commit: bool = False


@dataclass(frozen=True, slots=True)
class AuthenticatedOwner:
    """Authenticated account identity returned by shared route security checks."""

    account_id: str
    now: datetime


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class LoginEmailRequest(LoginRequest):
    code: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")


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


def _error(status: int, code: str, message: str, *, background: BackgroundTask | None = None):
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message}},
        headers={"Cache-Control": "no-store"},
        background=background,
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


def _email_verification_runtime_ready(runtime: AuthRuntime | None) -> bool:
    return (
        _runtime_ready(runtime)
        and callable(getattr(runtime.email_sender, "send_verification", None))
        and isinstance(runtime.email_verification_lifetime, timedelta)
        and runtime.email_verification_lifetime.total_seconds() >= 1
    )


def _registration_runtime_ready(runtime: AuthRuntime | None) -> bool:
    return (
        _email_verification_runtime_ready(runtime)
        and isinstance(runtime.common_passwords, frozenset)
        and bool(runtime.common_passwords)
        and all(isinstance(value, str) and value for value in runtime.common_passwords)
        and callable(runtime.password_lookup)
        and callable(runtime.report_password_outage)
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


def authenticate_owner(
    request: Request,
    settings: Settings,
    runtime: AuthRuntime | None,
    *,
    ip_rate_action: str,
    account_rate_action: str,
    audit_rate_limit: bool = True,
) -> tuple[AuthenticatedOwner | None, JSONResponse | None]:
    """Validate the established Origin/CSRF, session, and injected rate-limit boundary."""
    if not _runtime_ready(runtime):
        return None, _error(503, "auth_unavailable", "Authentication is unavailable")
    if not _origin_and_csrf_valid(request, settings):
        return None, _error(403, "origin_or_csrf", "Origin or CSRF validation failed")

    ip_allowed = _allow(runtime, request, ip_rate_action, "anonymous")
    if ip_allowed is None:
        return None, _error(503, "auth_unavailable", "Authentication is unavailable")
    if not ip_allowed:
        return None, _error(429, "rate_limited", "Too many requests")

    session_token = request.cookies.get(SESSION_COOKIE)
    now = _current_time(runtime)
    if now is None:
        return None, _error(503, "auth_unavailable", "Authentication is unavailable")
    if not session_token:
        return None, _error(401, "unauthorized", "Authentication is required")

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
            if (
                active is None
                or not isinstance(active.account_id, str)
                or not verify_csrf_token(active, csrf_token)
            ):
                return None, _error(401, "unauthorized", "Authentication is required")

            account_allowed = _allow(runtime, request, account_rate_action, active.account_id)
            if account_allowed is None:
                return None, _error(503, "auth_unavailable", "Authentication is unavailable")
            if not account_allowed:
                background = (
                    account_event_task(
                        runtime.session_factory.begin,
                        active.account_id,
                        AccountSecurityEventKind.RATE_LIMIT_EXCEEDED,
                        now,
                    )
                    if audit_rate_limit
                    else None
                )
                return None, _error(429, "rate_limited", "Too many requests", background=background)
            return AuthenticatedOwner(active.account_id, now), None
    except Exception:
        return None, _error(503, "auth_unavailable", "Authentication is unavailable")


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


def _session_response(issued: IssuedSession, runtime: AuthRuntime, settings: Settings):
    response = JSONResponse(
        {"authenticated": True, "csrf_token": issued.csrf_token},
        headers={"Cache-Control": "no-store"},
    )
    _set_session_cookies(response, issued.session_token, issued.csrf_token, runtime, settings)
    return response


def _lock_mfa_login_account(session: Session, account_id: str) -> str | None:
    if session.get_bind().dialect.name == "sqlite":
        # SQLite has no row-level FOR UPDATE; issue a no-op write to serialize mutations.
        return session.scalar(
            update(Account)
            .where(Account.id == account_id)
            .values(password_hash=Account.password_hash)
            .returning(Account.email)
        )
    return session.scalar(select(Account.email).where(Account.id == account_id).with_for_update())


def _lock_login_account(session: Session, email: str, *, serialize_sqlite: bool) -> Account | None:
    if not _valid_email(email):
        return None
    if serialize_sqlite and session.get_bind().dialect.name == "sqlite":
        return session.scalar(
            update(Account)
            .where(Account.email == email)
            .values(password_hash=Account.password_hash)
            .returning(Account)
        )
    return session.scalar(select(Account).where(Account.email == email).with_for_update())


def _login_address(runtime: AuthRuntime, request: Request, account_id: str) -> str | None:
    if not runtime.login_risk_enabled:
        return None
    return login_address_digest(account_id, _client_ip(request), runtime.signing_key)


def _login_risk(
    session: Session,
    runtime: AuthRuntime,
    account_id: str | None,
    address: str | None,
    now: datetime,
) -> LoginRisk:
    if not runtime.login_risk_enabled or account_id is None:
        return LoginRisk(None, False)
    return assess_login_risk(session, account_id, address, now=now)


def _record_auth_failure(
    session: Session, account_id: str, address: str | None, before: LoginRisk, now: datetime
) -> None:
    after = record_login_failure(session, account_id, address, now=now)
    if (before.locked_until is None and after.locked_until is not None) or (
        not before.step_up and after.step_up
    ):
        enqueue_security_alert(session, account_id, now=now)


def _record_auth_success(
    session: Session, account_id: str, address: str | None, now: datetime
) -> None:
    if record_login_success(session, account_id, address, now=now):
        save_account_event(session, account_id, AccountSecurityEventKind.NEW_IP_LOGIN, now=now)
        enqueue_security_alert(session, account_id, now=now)


def _send_login_email(send: Callable[[str, str], None], email: str, code: str) -> None:
    try:
        send(email, code)
    except Exception:
        # Transport diagnostics can include a recipient or a credential proof.
        pass


async def _read_auth_payload[T: BaseModel](request: Request, model: type[T]) -> T | None:
    content_type = request.headers.get("content-type", "").split(";", maxsplit=1)[0]
    if content_type.strip().lower() != "application/json":
        return None
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > _AUTH_BODY_LIMIT:
                return None
            body.extend(chunk)
        return model.model_validate_json(body)
    except (ClientDisconnect, ValidationError):
        return None


def _send_verification_best_effort(sender: EmailSender, email: str, token: str) -> None:
    try:
        sender.send_verification(email, token)
    except Exception:
        # Admission was already reported and the account can request a new code.
        # Do not attach the SMTP exception, recipient, or token to diagnostics.
        pass


def _resend_if_eligible(
    runtime: AuthRuntime, email: str, password: str, now: datetime
) -> str | None:
    try:
        with runtime.session_factory.begin() as session:
            token = prepare_email_verification_resend(
                session,
                email,
                password,
                dummy_password_hash=runtime.dummy_password_hash,
                now=now,
                expires_at=now + runtime.email_verification_lifetime,
            )
            if token is not None:
                session.flush()
                if not runtime.verification_delivery_after_commit:
                    runtime.email_sender.send_verification(email, token)
    except Exception:
        # A rollback retains the prior code. Never disclose account eligibility.
        return None
    return token if runtime.verification_delivery_after_commit else None


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
        committed_delivery = None
        try:
            with runtime.session_factory.begin() as session:
                try:
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
                except RegistrationConflict:
                    # The email already exists. Leave the account and its token untouched.
                    pass
                else:
                    if runtime.verification_delivery_after_commit:
                        committed_delivery = token
                    else:
                        runtime.email_sender.send_verification(email, token)
        except InvalidRegistrationInput:
            return _error(400, "invalid_registration", "Registration could not be completed")
        except Exception:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        return JSONResponse(
            {"registered": True},
            status_code=202,
            headers={"Cache-Control": "no-store"},
            background=(
                BackgroundTask(
                    _send_verification_best_effort, runtime.email_sender, email, committed_delivery
                )
                if committed_delivery is not None
                else None
            ),
        )

    @router.post(
        "/resend-verification",
        status_code=202,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {"schema": RegistrationRequest.model_json_schema()}
                },
            }
        },
    )
    async def resend_verification(request: Request):
        if not _email_verification_runtime_ready(runtime):
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not _origin_and_csrf_valid(request, settings):
            return _error(403, "origin_or_csrf", "Origin or CSRF validation failed")
        payload = await _read_auth_payload(request, RegistrationRequest)
        if payload is None:
            return _error(400, "invalid_request", "Invalid request")
        email = payload.email.strip().lower()
        allowed = _allow(runtime, request, "auth_resend_verification", email)
        if allowed is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not allowed:
            return _error(429, "rate_limited", "Too many requests")
        now = _current_time(runtime)
        if now is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        token = await run_in_threadpool(_resend_if_eligible, runtime, email, payload.password, now)
        return JSONResponse(
            {"requested": True},
            status_code=202,
            headers={"Cache-Control": "no-store"},
            background=(
                BackgroundTask(_send_verification_best_effort, runtime.email_sender, email, token)
                if token is not None
                else None
            ),
        )

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
                # Serialize risk, enrollment, and any session issuance on the owner row.
                owner = _lock_login_account(
                    session, payload.email, serialize_sqlite=runtime.login_risk_enabled
                )
                locked_id = owner.id if owner is not None else None
                address = None
                if runtime.login_risk_enabled and locked_id is not None:
                    now = _current_time(runtime)
                    if now is None:
                        raise RuntimeError("Authentication clock is unavailable")
                    address = _login_address(runtime, request, locked_id)
                risk = _login_risk(session, runtime, locked_id, address, now)
                if risk.locked_until is not None:
                    verify_password(payload.password, runtime.dummy_password_hash)
                    return _error(401, "unauthorized", "Invalid credentials")
                audit = BackgroundTasks()

                def on_bad_password(account_id: str) -> None:
                    if account_id == locked_id:
                        if runtime.login_risk_enabled:
                            _record_auth_failure(session, account_id, address, risk, now)
                        audit.add_task(
                            record_account_event,
                            runtime.session_factory.begin,
                            account_id,
                            AccountSecurityEventKind.LOGIN_FAILED,
                            now,
                        )

                first = check_first_factor(
                    session,
                    payload.email,
                    payload.password,
                    dummy_password_hash=runtime.dummy_password_hash,
                    on_bad_password=on_bad_password,
                )
                if first.account_id is None or first.account_id != locked_id:
                    return _error(401, "unauthorized", "Invalid credentials", background=audit)
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
                if risk.step_up:
                    send = getattr(runtime.email_sender, "send_login_challenge", None)
                    if address is None or owner is None or not callable(send):
                        return _error(503, "auth_unavailable", "Authentication is unavailable")
                    csrf_token = request.cookies[CSRF_COOKIE]
                    prepared = prepare_login_email_challenge(
                        session, owner, csrf_token, address, now=now
                    )
                    if prepared is None:
                        return _error(429, "rate_limited", "Too many requests")
                    background = (
                        BackgroundTask(_send_login_email, send, owner.email, prepared.code)
                        if prepared.code is not None
                        else None
                    )
                    return JSONResponse(
                        {
                            "authenticated": False,
                            "email_challenge_required": True,
                            "csrf_token": csrf_token,
                        },
                        headers={"Cache-Control": "no-store"},
                        background=background,
                    )
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
                if runtime.login_risk_enabled:
                    _record_auth_success(session, first.account_id, address, now)
            return _session_response(issued, runtime, settings)
        except InvalidDummyPasswordHash:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        except Exception:
            return _error(503, "auth_unavailable", "Authentication is unavailable")

    @router.post("/login/email")
    async def login_email(request: Request):
        if not _runtime_ready(runtime):
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not _origin_and_csrf_valid(request, settings):
            return _error(403, "origin_or_csrf", "Origin or CSRF validation failed")
        if not runtime.login_risk_enabled:
            return _error(401, "unauthorized", "Invalid credentials")
        allowed = _allow(runtime, request, "auth_login_email_ip", "anonymous")
        if allowed is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not allowed:
            return _error(429, "rate_limited", "Too many requests")
        payload = await _read_auth_payload(request, LoginEmailRequest)
        if payload is None:
            return _error(401, "unauthorized", "Invalid credentials")

        return await run_in_threadpool(_finish_email_login, payload, request)

    def _finish_email_login(payload: LoginEmailRequest, request: Request):
        allowed = _allow(runtime, request, "auth_login_email_pair", payload.email)
        if allowed is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not allowed:
            return _error(429, "rate_limited", "Too many requests")
        try:
            with runtime.session_factory.begin() as session:
                owner = _lock_login_account(session, payload.email, serialize_sqlite=True)
                now = _current_time(runtime)
                if now is None:
                    raise RuntimeError("Authentication clock is unavailable")
                address = _login_address(runtime, request, owner.id) if owner is not None else None
                if owner is None or address is None:
                    verify_password(payload.password, runtime.dummy_password_hash)
                    return _error(401, "unauthorized", "Invalid credentials")
                risk = _login_risk(session, runtime, owner.id, address, now)
                if risk.locked_until is not None:
                    verify_password(payload.password, runtime.dummy_password_hash)
                    return _error(401, "unauthorized", "Invalid credentials")
                password_rejected = False

                def on_bad_password(account_id: str) -> None:
                    nonlocal password_rejected
                    password_rejected = account_id == owner.id

                first = check_first_factor(
                    session,
                    payload.email,
                    payload.password,
                    dummy_password_hash=runtime.dummy_password_hash,
                    on_bad_password=on_bad_password,
                )
                password_verified = (
                    first.status is FirstFactorStatus.PASSWORD_VERIFIED
                    and first.account_id == owner.id
                )
                if not (password_verified or password_rejected):
                    return _error(401, "unauthorized", "Invalid credentials")
                # Password verification may cross the proof's expiry boundary.
                now = _current_time(runtime)
                if now is None:
                    raise RuntimeError("Authentication clock is unavailable")
                csrf_token = request.cookies[CSRF_COOKIE]
                failed_kind = None
                if password_rejected:
                    if not has_active_login_email_challenge(
                        session, owner, csrf_token, address, now=now
                    ):
                        return _error(401, "unauthorized", "Invalid credentials")
                    failed_kind = AccountSecurityEventKind.LOGIN_FAILED
                else:
                    proof = consume_login_email_challenge(
                        session, owner, csrf_token, address, payload.code, now=now
                    )
                    if proof is LoginEmailProof.REJECTED:
                        return _error(401, "unauthorized", "Invalid credentials")
                    if proof is LoginEmailProof.INVALID_CODE:
                        failed_kind = AccountSecurityEventKind.MFA_FAILED
                if failed_kind is not None:
                    risk = _login_risk(session, runtime, owner.id, address, now)
                    _record_auth_failure(session, owner.id, address, risk, now)
                    return _error(
                        401,
                        "unauthorized",
                        "Invalid credentials",
                        background=account_event_task(
                            runtime.session_factory.begin,
                            owner.id,
                            failed_kind,
                            now,
                        ),
                    )
                issued = issue_session(
                    session,
                    owner.id,
                    signing_key=runtime.signing_key,
                    issuer=runtime.issuer,
                    audience=runtime.audience,
                    now=now,
                    expires_at=now + runtime.session_lifetime,
                )
                if issued is None:
                    raise _RejectAuthentication
                _record_auth_success(session, owner.id, address, now)
            return _session_response(issued, runtime, settings)
        except _RejectAuthentication:
            return _error(401, "unauthorized", "Invalid credentials")
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
        action = "auth_login_mfa_pair" if runtime.login_risk_enabled else "auth_login_mfa_account"
        allowed = _allow(runtime, request, action, account_id)
        if allowed is None:
            return _error(503, "auth_unavailable", "Authentication is unavailable")
        if not allowed:
            return _error(429, "rate_limited", "Too many requests")
        audit = BackgroundTasks()
        try:
            with runtime.session_factory.begin() as session:
                # Match account lifecycle lock order before consuming the one-use challenge.
                locked_email = _lock_mfa_login_account(session, account_id)
                if locked_email is None or locked_email != payload.email:
                    verify_password(payload.password, runtime.dummy_password_hash)
                    raise _RejectAuthentication
                now = _current_time(runtime)
                if now is None:
                    raise RuntimeError("Authentication clock is unavailable")
                address = _login_address(runtime, request, account_id)
                risk = _login_risk(session, runtime, account_id, address, now)
                if risk.locked_until is not None:
                    verify_password(payload.password, runtime.dummy_password_hash)
                    raise _RejectAuthentication
                failed_kind = None

                def on_rejected(kind: AccountSecurityEventKind) -> None:
                    nonlocal failed_kind
                    failed_kind = kind
                    audit.add_task(
                        record_account_event,
                        runtime.session_factory.begin,
                        account_id,
                        kind,
                        now,
                    )

                # Roll back provisional challenge/TOTP updates on rejection, then
                # commit any genuine failure against the still-locked account.
                try:
                    with session.begin_nested():
                        consumed_account_id = consume_mfa_login_challenge(
                            session, challenge_token, request.cookies[CSRF_COOKIE], now=now
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
                            on_mfa_rejected=lambda: on_rejected(
                                AccountSecurityEventKind.MFA_FAILED
                            ),
                            on_bad_password=(
                                lambda _owner: on_rejected(AccountSecurityEventKind.LOGIN_FAILED)
                            )
                            if runtime.login_risk_enabled
                            else None,
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
                except _RejectAuthentication:
                    if runtime.login_risk_enabled and failed_kind is not None:
                        _record_auth_failure(session, account_id, address, risk, now)
                    return _error(401, "unauthorized", "Invalid credentials", background=audit)
                if runtime.login_risk_enabled:
                    _record_auth_success(session, account_id, address, now)
            return _session_response(issued, runtime, settings)
        except _RejectAuthentication:
            return _error(401, "unauthorized", "Invalid credentials", background=audit)
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
                    return _error(
                        429,
                        "rate_limited",
                        "Too many requests",
                        background=account_event_task(
                            runtime.session_factory.begin,
                            active.account_id,
                            AccountSecurityEventKind.RATE_LIMIT_EXCEEDED,
                            now,
                        ),
                    )
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
