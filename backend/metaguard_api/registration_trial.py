"""Opt-in registration for loopback or one trusted private HTTPS gateway."""

import os
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from secrets import token_urlsafe
from time import time
from typing import NoReturn
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic_settings import BaseSettings, SettingsConfigDict

from metaguard_api.account_credentials import hash_password
from metaguard_api.auth_routes import AuthRuntime
from metaguard_api.database import DatabaseSettings, create_database
from metaguard_api.gmail_sender import GmailSender
from metaguard_api.local_rate_limit import LocalRateLimiter
from metaguard_api.local_runtime import _offline_password_lookup, _read_blocklist
from metaguard_api.main import create_app
from metaguard_api.secrets import SecretName, SecretStore
from metaguard_api.settings import Settings
from metaguard_api.staging_runtime import (
    _FORWARDING_HEADERS,
    _LIBPQ_OVERRIDES,
    _is_private_ipv4,
    _linux_uid,
    _OfflineVirusTotal,
    _Transactions,
    _trusted_ca,
)
from metaguard_api.system_security_events import record_password_check_outage

_LOOPBACK = "127.0.0.1"
_ROUTES = frozenset(
    {
        ("GET", b"/v1/auth/status"),
        ("POST", b"/v1/auth/register"),
        ("POST", b"/v1/auth/verify-email"),
        ("POST", b"/v1/auth/resend-verification"),
        ("POST", b"/v1/auth/password-reset/request"),
        ("POST", b"/v1/auth/password-reset/confirm"),
        ("POST", b"/v1/auth/login"),
        ("POST", b"/v1/auth/logout"),
    }
)


class RegistrationTrialError(RuntimeError):
    """Report invalid trial configuration without leaking credential or setting values."""


class _TrialOptions(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="METAGUARD_REGISTRATION_", env_file=None)

    private_trial: bool = False
    db_tls_ca: Path
    password_blocklist: Path
    gmail_sender: str


class _IngressOptions(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="METAGUARD_REGISTRATION_INGRESS_", env_file=None)

    enabled: bool = False
    peer: str = ""


@dataclass(frozen=True, slots=True)
class _AccountMailSender:
    sender: GmailSender = field(repr=False)

    def send_verification(self, email: str, token: str) -> None:
        self.sender.send_verification(email, token)

    def send_password_reset(self, email: str, code: str) -> None:
        self.sender.send_password_reset(email, code)

    def send_login_challenge(self, email: str, code: str) -> NoReturn:
        raise RegistrationTrialError("Login challenge delivery is unavailable in this trial")


def _rejection(status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": "registration_trial_denied"}},
        headers={"Cache-Control": "no-store"},
    )


def create_registration_trial_app() -> FastAPI:
    """Keep the disposable trial restricted to loopback."""
    return _create_registration_app(_LOOPBACK)


def create_registration_ingress_app() -> FastAPI:
    """Allow the isolated account routes only from a designated HTTPS gateway."""
    try:
        options = _IngressOptions()
        if not options.enabled or not _is_private_ipv4(options.peer):
            raise ValueError("A single private registration gateway is required")
    except Exception:
        raise RegistrationTrialError("Registration ingress configuration is unavailable") from None
    return _create_registration_app(options.peer)


def _create_registration_app(allowed_peer: str) -> FastAPI:
    """Compose the guarded account routes with an explicitly mounted Gmail credential."""
    database = None
    try:
        settings = Settings()
        options = _TrialOptions()
        db_settings = DatabaseSettings()
        origins = settings.auth_allowed_origins
        uid = _linux_uid()
        credentials = Path(os.environ.get("CREDENTIALS_DIRECTORY", ""))
        if (
            not options.private_trial
            or uid is None
            or uid <= 0
            or settings.environment != "production"
            or len(origins) != 1
            or urlsplit(origins[0]).scheme != "https"
            or not _is_private_ipv4(db_settings.host)
            or db_settings.name != "metaguard_registration_trial"
            or db_settings.user != "metaguard_registration_app"
            or _LIBPQ_OVERRIDES.intersection(os.environ)
            or not options.password_blocklist.is_absolute()
            or not credentials.is_absolute()
        ):
            raise ValueError("Unsafe registration trial boundary")
        expected_host = urlsplit(origins[0]).netloc

        ca = _trusted_ca(options.db_tls_ca)
        blocklist = _read_blocklist(options.password_blocklist)
        secrets = SecretStore(settings.secret_dir)
        jwt = secrets.read_text(SecretName.JWT_SIGNING_KEY)
        totp = secrets.read(SecretName.TOTP_ENCRYPTION_KEY)
        jwt_bytes = jwt.encode("utf-8")
        if len(jwt_bytes) < 32 or len(totp) != 32 or jwt_bytes == totp:
            raise ValueError("Invalid registration trial keys")
        sender = _AccountMailSender(
            GmailSender(sender_email=options.gmail_sender, secret_store=SecretStore(credentials))
        )
        database = create_database(db_settings, connect_timeout_seconds=3, tls_root_cert=ca)
        app = create_app(
            settings,
            auth_runtime=AuthRuntime(
                session_factory=_Transactions(database),
                rate_limiter=LocalRateLimiter(settings, verification_mail_budget=True),
                signing_key=jwt,
                issuer="metaguard-registration-trial",
                audience="metaguard-registration-trial-api",
                dummy_password_hash=hash_password(token_urlsafe(32)),
                totp_encryption_key=totp,
                totp_key_version=1,
                session_lifetime=timedelta(minutes=15),
                mfa_challenge_lifetime=timedelta(minutes=5),
                common_passwords=blocklist,
                password_lookup=_offline_password_lookup,
                report_password_outage=lambda event: record_password_check_outage(
                    database, event, now=int(time())
                ),
                email_sender=sender,
                email_verification_lifetime=timedelta(hours=1),
                verification_delivery_after_commit=True,
            ),
            database=database,
            virus_total_client=_OfflineVirusTotal(),
        )
        lifespan_context = app.router.lifespan_context

        @asynccontextmanager
        async def lifespan(instance: FastAPI):
            try:
                async with lifespan_context(instance) as state:
                    yield state
            finally:
                try:
                    database.close()
                except Exception:
                    raise RegistrationTrialError("Registration trial cleanup failed") from None

        app.router.lifespan_context = lifespan

        @app.middleware("http")
        async def restrict_trial(request: Request, call_next):
            if (
                request.client is None
                or request.client.host != allowed_peer
                or _FORWARDING_HEADERS.intersection(request.headers)
                or "x-real-ip" in request.headers
            ):
                return _rejection(403)
            if allowed_peer != _LOOPBACK and (
                request.scope.get("scheme") != "https"
                or request.headers.getlist("host") != [expected_host]
                or len(request.headers.getlist("origin")) > 1
            ):
                return _rejection(403)
            if (request.method, request.scope.get("raw_path")) not in _ROUTES:
                return _rejection(404)
            return await call_next(request)

    except Exception:
        if database is not None:
            with suppress(Exception):
                database.close()
        raise RegistrationTrialError("Registration trial configuration is unavailable") from None
    return app
