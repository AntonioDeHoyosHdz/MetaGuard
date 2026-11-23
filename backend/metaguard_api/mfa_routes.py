"""Authenticated TOTP enrollment and two-factor lost-device replacement."""

from dataclasses import dataclass, field
from datetime import datetime

import pyotp
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from metaguard_api.account_credentials import verify_password
from metaguard_api.accounts import Account
from metaguard_api.auth_routes import (
    CSRF_COOKIE,
    MFA_COOKIE,
    SESSION_COOKIE,
    AuthRuntime,
    _allow,
    _clear_cookie,
    _current_time,
    _decode_mfa_challenge,
    _error,
    _origin_and_csrf_valid,
    _runtime_ready,
    authenticate_owner,
)
from metaguard_api.first_factor import FirstFactorStatus, check_first_factor
from metaguard_api.mfa_lifecycle import (
    RECOVERY_CODE_PATTERN,
    RECOVERY_SETUP_TOKEN_MAX_LENGTH,
    has_recovery_code,
    make_recovery_setup_token,
    open_recovery_setup_token,
    recovery_setup_binding,
    replace_totp,
    rotate_recovery_codes_and_revoke_sessions,
)
from metaguard_api.pending_totp import confirm_totp, remove_expired_pending, stage_totp
from metaguard_api.sessions import (
    consume_mfa_login_challenge,
    get_active_session,
    get_mfa_login_challenge_expiry,
    verify_csrf_token,
)
from metaguard_api.settings import Settings

_SETUP_SECONDS = 300
_OTP_PATTERN = r"^[0-9]{6}$"


class _SecureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class EnrollmentSetup(_SecureRequest):
    password: str = Field(min_length=1, max_length=1024, repr=False)


class EnrollmentConfirm(_SecureRequest):
    code: str = Field(min_length=6, max_length=6, pattern=_OTP_PATTERN, repr=False)


class RecoverySetup(EnrollmentSetup):
    email: str = Field(min_length=1, max_length=254, repr=False)
    recovery_code: str = Field(
        min_length=32, max_length=32, pattern=RECOVERY_CODE_PATTERN, repr=False
    )


class RecoveryConfirm(RecoverySetup):
    code: str = Field(min_length=6, max_length=6, pattern=_OTP_PATTERN, repr=False)
    setup_token: str = Field(min_length=1, max_length=RECOVERY_SETUP_TOKEN_MAX_LENGTH, repr=False)


class _Denied(Exception):
    """Abort a rejected auth operation without committing partial changes."""


@dataclass(frozen=True, slots=True)
class _RecoveryContext:
    account_id: str
    challenge: str = field(repr=False)
    csrf: str = field(repr=False)


def _invalid_credentials():
    return _error(401, "unauthorized", "Invalid credentials")


def _unavailable():
    return _error(503, "auth_unavailable", "Authentication is unavailable")


def _limit_error(allowed: bool | None):
    if allowed is None:
        return _unavailable()
    return _error(429, "rate_limited", "Too many requests")


def _setup_json(seed: str, email: str, expires_at: int, **additional: str) -> JSONResponse:
    return JSONResponse(
        {
            "secret": seed,
            "otpauth_uri": pyotp.TOTP(seed).provisioning_uri(name=email, issuer_name="MetaGuard"),
            "expires_at": expires_at,
            **additional,
        },
        headers={"Cache-Control": "no-store"},
    )


def _confirmed(codes: tuple[str, ...], settings: Settings) -> JSONResponse:
    response = JSONResponse({"recovery_codes": codes}, headers={"Cache-Control": "no-store"})
    for cookie in (SESSION_COOKIE, CSRF_COOKIE, MFA_COOKIE):
        _clear_cookie(response, cookie, settings)
    return response


def _locked_account(session: Session, account_id: str) -> Account:
    account = session.scalar(select(Account).where(Account.id == account_id).with_for_update())
    if account is None or account.email_verified_at is None:
        raise _Denied
    return account


def _lock_enrollment_session(
    session: Session, request: Request, runtime: AuthRuntime, account_id: str
) -> tuple[Account, datetime]:
    account = _locked_account(session, account_id)
    now = _current_time(runtime)
    if now is None:
        raise RuntimeError("Authentication clock is unavailable")
    active = get_active_session(
        session,
        request.cookies.get(SESSION_COOKIE, ""),
        signing_key=runtime.signing_key,
        issuer=runtime.issuer,
        audience=runtime.audience,
        now=now,
        lock_for_update=True,
    )
    # This query can wait on a parallel logout; do not continue with a stale time.
    now = _current_time(runtime)
    if now is None:
        raise RuntimeError("Authentication clock is unavailable")
    if (
        active is None
        or active.account_id != account_id
        or active.expires_at <= now
        or not verify_csrf_token(active, request.cookies.get(CSRF_COOKIE, ""))
    ):
        raise _Denied
    return account, now


def _recovery_context(
    request: Request, runtime: AuthRuntime | None, settings: Settings
) -> tuple[_RecoveryContext | None, JSONResponse | None]:
    if not _runtime_ready(runtime):
        return None, _unavailable()
    if not _origin_and_csrf_valid(request, settings):
        return None, _error(403, "origin_or_csrf", "Origin or CSRF validation failed")
    allowed = _allow(runtime, request, "mfa_recovery_ip", "anonymous")
    if allowed is not True:
        return None, _limit_error(allowed)
    now = _current_time(runtime)
    if now is None:
        return None, _unavailable()
    challenge = request.cookies.get(MFA_COOKIE, "")
    account_id = _decode_mfa_challenge(runtime, challenge, now)
    if account_id is None:
        return None, _invalid_credentials()
    allowed = _allow(runtime, request, "mfa_recovery_account", account_id)
    if allowed is not True:
        return None, _limit_error(allowed)
    return _RecoveryContext(account_id, challenge, request.cookies[CSRF_COOKIE]), None


def _verify_recovery_proofs(
    session: Session, context: _RecoveryContext, payload: RecoverySetup, runtime: AuthRuntime
) -> datetime:
    _locked_account(session, context.account_id)
    first = check_first_factor(
        session,
        payload.email,
        payload.password,
        dummy_password_hash=runtime.dummy_password_hash,
    )
    now = _current_time(runtime)
    if now is None:
        raise RuntimeError("Authentication clock is unavailable")
    if (
        first.status is not FirstFactorStatus.MFA_REQUIRED
        or first.account_id != context.account_id
        or _decode_mfa_challenge(runtime, context.challenge, now) != context.account_id
        or not has_recovery_code(session, context.account_id, payload.recovery_code)
    ):
        raise _Denied
    return now


def create_mfa_router(settings: Settings, runtime: AuthRuntime | None) -> APIRouter:
    router = APIRouter(tags=["mfa"])

    @router.post("/v1/users/me/totp/setup")
    def setup(payload: EnrollmentSetup, request: Request):
        owner, error = authenticate_owner(
            request,
            settings,
            runtime,
            ip_rate_action="requests_per_minute_per_ip",
            account_rate_action="mfa_enrollment_setup",
        )
        if error is not None:
            return error
        try:
            with runtime.session_factory.begin() as session:
                account, now = _lock_enrollment_session(session, request, runtime, owner.account_id)
                if not verify_password(payload.password, account.password_hash):
                    raise _Denied
                timestamp = int(now.timestamp())
                expires_at = timestamp + _SETUP_SECONDS
                seed = pyotp.random_base32()
                remove_expired_pending(session, owner.account_id, now=timestamp)
                staged = stage_totp(
                    session,
                    owner.account_id,
                    seed,
                    key=runtime.totp_encryption_key,
                    key_version=runtime.totp_key_version,
                    now=timestamp,
                    expires_at=expires_at,
                )
                email = account.email
            if not staged:
                return _error(409, "totp_unavailable", "Authenticator setup is unavailable")
            return _setup_json(seed, email, expires_at)
        except _Denied:
            return _invalid_credentials()
        except Exception:
            return _unavailable()

    @router.post("/v1/users/me/totp/confirm")
    def confirm(payload: EnrollmentConfirm, request: Request):
        owner, error = authenticate_owner(
            request,
            settings,
            runtime,
            ip_rate_action="requests_per_minute_per_ip",
            account_rate_action="mfa_enrollment_confirm",
        )
        if error is not None:
            return error
        try:
            with runtime.session_factory.begin() as session:
                _, now = _lock_enrollment_session(session, request, runtime, owner.account_id)
                if not confirm_totp(
                    session,
                    owner.account_id,
                    payload.code,
                    key=runtime.totp_encryption_key,
                    key_version=runtime.totp_key_version,
                    now=int(now.timestamp()),
                ):
                    raise _Denied
                codes = rotate_recovery_codes_and_revoke_sessions(
                    session, owner.account_id, now=now
                )
            return _confirmed(codes, settings)
        except _Denied:
            return _invalid_credentials()
        except Exception:
            return _unavailable()

    @router.post("/v1/auth/mfa/recovery/setup")
    def prepare_recovery(payload: RecoverySetup, request: Request):
        context, error = _recovery_context(request, runtime, settings)
        if error is not None:
            return error
        try:
            with runtime.session_factory.begin() as session:
                now = _verify_recovery_proofs(session, context, payload, runtime)
                deadline = get_mfa_login_challenge_expiry(
                    session, context.account_id, context.challenge, context.csrf, now=now
                )
                if deadline is None:
                    raise _Denied
                now_seconds = int(now.timestamp())
                expires_at = min(int(deadline.timestamp()), now_seconds + _SETUP_SECONDS)
                if expires_at <= now_seconds:
                    raise _Denied
                seed = pyotp.random_base32()
                binding = recovery_setup_binding(
                    context.account_id, context.challenge, context.csrf, payload.recovery_code
                )
                setup_token = make_recovery_setup_token(
                    runtime.totp_encryption_key, binding, seed, expires_at
                )
            return _setup_json(seed, payload.email, expires_at, setup_token=setup_token)
        except _Denied:
            return _invalid_credentials()
        except Exception:
            return _unavailable()

    @router.post("/v1/auth/mfa/recovery/confirm")
    def complete_recovery(payload: RecoveryConfirm, request: Request):
        context, error = _recovery_context(request, runtime, settings)
        if error is not None:
            return error
        try:
            with runtime.session_factory.begin() as session:
                # Match MFA login and password changes: account, then one-use challenge.
                now = _verify_recovery_proofs(session, context, payload, runtime)
                consumed = consume_mfa_login_challenge(
                    session, context.challenge, context.csrf, now=now
                )
                if consumed != context.account_id:
                    raise _Denied
                timestamp = int(now.timestamp())
                binding = recovery_setup_binding(
                    context.account_id, context.challenge, context.csrf, payload.recovery_code
                )
                seed = open_recovery_setup_token(
                    runtime.totp_encryption_key, binding, payload.setup_token, timestamp
                )
                if seed is None or not replace_totp(
                    session,
                    context.account_id,
                    seed,
                    payload.code,
                    key=runtime.totp_encryption_key,
                    key_version=runtime.totp_key_version,
                    now=timestamp,
                ):
                    raise _Denied
                codes = rotate_recovery_codes_and_revoke_sessions(
                    session, context.account_id, now=now
                )
            return _confirmed(codes, settings)
        except _Denied:
            return _invalid_credentials()
        except Exception:
            return _unavailable()

    return router
