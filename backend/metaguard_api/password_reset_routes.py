"""Anonymous proof-based password reset with generic admission and no session issuance."""

from asyncio import timeout
from email.errors import MessageError
from email.headerregistry import Address
from functools import partial
from threading import BoundedSemaphore

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.background import BackgroundTask, BackgroundTasks
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from metaguard_api.account_credentials import hash_password, verify_password
from metaguard_api.account_security_events import AccountSecurityEventKind, record_account_event
from metaguard_api.auth_routes import (
    AuthRuntime,
    _allow,
    _current_time,
    _error,
    _origin_and_csrf_valid,
    _runtime_ready,
)
from metaguard_api.first_factor import _valid_email
from metaguard_api.password_policy import PasswordScreeningResult, screen_password
from metaguard_api.password_reset import (
    bound_password_reset_transaction,
    confirm_password_reset,
    precheck_password_reset,
    prepare_password_reset,
)
from metaguard_api.settings import Settings


class _RequestPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    email: str = Field(min_length=3, max_length=254, repr=False)


class _ConfirmPayload(_RequestPayload):
    code: str = Field(min_length=1, max_length=128, repr=False)
    new_password: str = Field(min_length=1, max_length=1024, repr=False)
    mfa_code: str | None = Field(default=None, max_length=32, repr=False)


def _normalized_email(raw: str) -> str | None:
    email = raw.strip().lower()
    if not _valid_email(email) or not email.isprintable() or any(c.isspace() for c in email):
        return None
    try:
        return email if Address(addr_spec=email).addr_spec == email else None
    except (ValueError, MessageError):
        return None


async def _read_payload[Payload: BaseModel](
    request: Request, model: type[Payload], *, max_bytes: int
) -> Payload | None:
    media_type = request.headers.get("content-type", "").split(";", maxsplit=1)[0]
    if media_type.strip().lower() != "application/json":
        return None
    body = bytearray()
    try:
        async with timeout(10):
            async for chunk in request.stream():
                if len(body) + len(chunk) > max_bytes:
                    return None
                body.extend(chunk)
        return model.model_validate_json(body)
    except (ClientDisconnect, TimeoutError, ValidationError):
        return None


def _unavailable():
    return _error(503, "auth_unavailable", "Authentication is unavailable")


def _limited():
    return _error(429, "rate_limited", "Too many requests")


def _invalid_reset():
    return _error(401, "invalid_reset", "Invalid or expired reset proof")


def _password_rejected(background: BackgroundTask | None = None):
    return _error(
        400,
        "password_rejected",
        "Choose a different password that meets the policy",
        background=background,
    )


def _issue_and_send(runtime: AuthRuntime, email: str) -> None:
    try:
        with runtime.session_factory.begin() as session:
            bound_password_reset_transaction(session)
            code = prepare_password_reset(session, email, clock=partial(_current_time, runtime))
        if code is not None:
            runtime.email_sender.send_password_reset(email, code)
    except Exception:
        # Admission was already sent. Do not expose or log recipient or SMTP errors.
        # Delivery can be ambiguous; leave any committed proof valid until expiry.
        return


def _confirm(runtime: AuthRuntime, email: str, payload: _ConfirmPayload) -> JSONResponse:
    clock = partial(_current_time, runtime)
    factor = {"key": runtime.totp_encryption_key, "key_version": runtime.totp_key_version}
    try:
        with runtime.session_factory.begin() as session:
            bound_password_reset_transaction(session)
            candidate = precheck_password_reset(
                session, email, payload.code, payload.mfa_code, clock=clock, **factor
            )
        if candidate is None:
            return _invalid_reset()
        if verify_password(payload.new_password, candidate.password_hash):
            return _password_rejected()
        audit = BackgroundTasks()

        def on_compromised() -> None:
            now = clock()
            if now is not None:
                audit.add_task(
                    record_account_event,
                    runtime.session_factory.begin,
                    candidate.account_id,
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
            bound_password_reset_transaction(session)
            changed = confirm_password_reset(
                session,
                email,
                payload.code,
                payload.mfa_code,
                candidate=candidate,
                new_hash=new_hash,
                clock=clock,
                **factor,
            )
        if not changed:
            return _invalid_reset()
    except Exception:
        return _unavailable()
    return JSONResponse({"changed": True}, headers={"Cache-Control": "no-store"})


def create_password_reset_router(settings: Settings, runtime: AuthRuntime | None) -> APIRouter:
    router = APIRouter(prefix="/v1/auth/password-reset", tags=["auth"])
    admission_slots = BoundedSemaphore(32)
    mail_slots = BoundedSemaphore(4)
    confirm_slots = BoundedSemaphore(4)

    async def admit[Payload: _RequestPayload](
        request: Request, model: type[Payload], *, max_bytes: int, action: str
    ) -> tuple[Payload, str] | JSONResponse:
        if not _origin_and_csrf_valid(request, settings):
            return _error(403, "origin_or_csrf", "Origin or CSRF validation failed")
        if not _runtime_ready(runtime):
            return _unavailable()
        if not admission_slots.acquire(blocking=False):
            return _limited()
        try:
            payload = await _read_payload(request, model, max_bytes=max_bytes)
            email = _normalized_email(payload.email) if payload is not None else None
            if email is None:
                return _error(400, "invalid_request", "Invalid request")
            allowed = await run_in_threadpool(_allow, runtime, request, action, email)
            if allowed is None:
                return _unavailable()
            if not allowed:
                return _limited()
            return payload, email
        finally:
            admission_slots.release()

    async def deliver(email: str) -> None:
        # The response owns this work and sends its body before running it. Do not
        # queue mail work or let availability or SMTP timing alter admission.
        if mail_slots.acquire(blocking=False):
            try:
                await run_in_threadpool(_issue_and_send, runtime, email)
            finally:
                mail_slots.release()

    @router.post("/request", status_code=202)
    async def request_reset(request: Request) -> JSONResponse:
        admitted = await admit(
            request, _RequestPayload, max_bytes=2048, action="password_reset_request"
        )
        if isinstance(admitted, JSONResponse):
            return admitted
        if not callable(getattr(runtime.email_sender, "send_password_reset", None)):
            return _unavailable()
        return JSONResponse(
            {"requested": True},
            status_code=202,
            headers={"Cache-Control": "no-store"},
            background=BackgroundTask(deliver, admitted[1]),
        )

    @router.post("/confirm")
    async def confirm_reset(request: Request) -> JSONResponse:
        admitted = await admit(
            request, _ConfirmPayload, max_bytes=8192, action="password_reset_confirm"
        )
        if isinstance(admitted, JSONResponse):
            return admitted
        if (
            not runtime.common_passwords
            or not callable(runtime.password_lookup)
            or not callable(runtime.report_password_outage)
        ):
            return _unavailable()
        if not confirm_slots.acquire(blocking=False):
            return _limited()
        try:
            payload, email = admitted
            return await run_in_threadpool(_confirm, runtime, email, payload)
        finally:
            confirm_slots.release()

    return router
