"""Authenticated password changes without changing MFA enrollment."""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import delete, select, update
from starlette.background import BackgroundTask, BackgroundTasks
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from metaguard_api.account_credentials import hash_password, verify_password
from metaguard_api.account_security_events import AccountSecurityEventKind, record_account_event
from metaguard_api.accounts import Account, AccountSession
from metaguard_api.auth_routes import (
    CSRF_COOKIE,
    MFA_COOKIE,
    SESSION_COOKIE,
    AuthRuntime,
    _clear_cookie,
    _current_time,
    _error,
    authenticate_owner,
)
from metaguard_api.password_policy import PasswordScreeningResult, screen_password
from metaguard_api.password_reset import invalidate_password_resets
from metaguard_api.sessions import MfaLoginChallenge, get_active_session, verify_csrf_token
from metaguard_api.settings import Settings

_MAX_PASSWORD_CHANGE_BODY = 12_500  # Two 1024-character fields with JSON escapes.


class PasswordChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    current_password: str = Field(min_length=1, max_length=1024, repr=False)
    new_password: str = Field(min_length=1, max_length=1024, repr=False)


class _Denied(Exception):
    """Roll back the provisional password update if the request lost authorization."""


async def _read_payload(request: Request) -> PasswordChangeRequest | None:
    content_type = request.headers.get("content-type", "").split(";", maxsplit=1)[0]
    if content_type.strip().lower() != "application/json":
        return None
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > _MAX_PASSWORD_CHANGE_BODY:
                return None
            body.extend(chunk)
        return PasswordChangeRequest.model_validate_json(body)
    except (ClientDisconnect, ValidationError):
        return None


def _password_unavailable() -> JSONResponse:
    return _error(503, "auth_unavailable", "Authentication is unavailable")


def _password_rejected(background: BackgroundTask | None = None) -> JSONResponse:
    return _error(
        400,
        "password_rejected",
        "Choose a different password that meets the policy",
        background=background,
    )


def _change_password(
    runtime: AuthRuntime,
    settings: Settings,
    request: Request,
    account_id: str,
    payload: PasswordChangeRequest,
) -> JSONResponse:
    if (
        not runtime.common_passwords
        or not callable(runtime.password_lookup)
        or not callable(runtime.report_password_outage)
    ):
        return _password_unavailable()

    try:
        with runtime.session_factory.begin() as session:
            previous_hash = session.scalar(
                select(Account.password_hash).where(
                    Account.id == account_id, Account.email_verified_at.is_not(None)
                )
            )
            if previous_hash is None or not verify_password(
                payload.current_password, previous_hash
            ):
                raise _Denied

        # Network screening and its outage audit must not hold an account lock.
        if payload.current_password == payload.new_password:
            return _password_rejected()
        audit = BackgroundTasks()

        def on_compromised() -> None:
            now = _current_time(runtime)
            if now is not None:
                audit.add_task(
                    record_account_event,
                    runtime.session_factory.begin,
                    account_id,
                    AccountSecurityEventKind.LEAKED_PASSWORD_REJECTED,
                    now,
                )

        screening = screen_password(
            payload.new_password,
            common_passwords=runtime.common_passwords,
            lookup=runtime.password_lookup,
            report_outage=runtime.report_password_outage,
            on_compromised=on_compromised,
        )
        if screening is PasswordScreeningResult.REJECTED:
            return _password_rejected(audit)
        new_hash = hash_password(payload.new_password)

        with runtime.session_factory.begin() as session:
            # Lock the account first, as login does, and require the exact verified hash.
            updated_id = session.scalar(
                update(Account)
                .where(
                    Account.id == account_id,
                    Account.email_verified_at.is_not(None),
                    Account.password_hash == previous_hash,
                )
                .values(password_hash=new_hash)
                .returning(Account.id)
            )
            if updated_id is None:
                raise _Denied
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
            # The session check may wait on concurrent logout; refresh time after its lock.
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
            session.execute(
                update(AccountSession)
                .where(AccountSession.account_id == account_id, AccountSession.revoked_at.is_(None))
                .values(revoked_at=now)
            )
            session.execute(
                delete(MfaLoginChallenge).where(MfaLoginChallenge.account_id == account_id)
            )
            invalidate_password_resets(session, account_id)
    except _Denied:
        return _error(401, "unauthorized", "Invalid credentials or session")
    except Exception:
        return _password_unavailable()

    response = JSONResponse({"changed": True}, headers={"Cache-Control": "no-store"})
    for cookie in (SESSION_COOKIE, CSRF_COOKIE, MFA_COOKIE):
        _clear_cookie(response, cookie, settings)
    return response


def create_account_password_router(settings: Settings, runtime: AuthRuntime | None) -> APIRouter:
    router = APIRouter(tags=["auth"])

    @router.post(
        "/v1/users/me/password",
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {"schema": PasswordChangeRequest.model_json_schema()}
                },
            }
        },
    )
    async def change_password(request: Request) -> JSONResponse:
        owner, error = await run_in_threadpool(
            authenticate_owner,
            request,
            settings,
            runtime,
            ip_rate_action="account_password_change_ip",
            account_rate_action="account_password_change_account",
        )
        if error is not None:
            return error
        payload = await _read_payload(request)
        if payload is None:
            return _error(400, "invalid_request", "Invalid request")
        return await run_in_threadpool(
            _change_password, runtime, settings, request, owner.account_id, payload
        )

    return router
