"""Opt-in local composition for a disposable development database."""

import os
import re
import smtplib
import sys
from contextlib import AbstractContextManager, asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import timedelta
from email.message import EmailMessage
from pathlib import Path
from secrets import token_urlsafe
from time import time
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.orm import Session

from metaguard_api.account_credentials import hash_password
from metaguard_api.auth_routes import AuthRuntime
from metaguard_api.database import Database, DatabaseSettings, create_database
from metaguard_api.file_routes import FileRuntime
from metaguard_api.file_storage import InMemoryTemporaryFileStore
from metaguard_api.local_rate_limit import LocalRateLimiter
from metaguard_api.login_email_challenge import LOGIN_EMAIL_CODE_PATTERN
from metaguard_api.password_reset import RESET_CODE_PATTERN
from metaguard_api.processing_ipc_client import ProcessingClient, ProcessingClientConfig
from metaguard_api.processing_limits import MAX_FILE_SIZE
from metaguard_api.pwned_passwords import RangeServiceUnavailable
from metaguard_api.registration import InvalidRegistrationInput
from metaguard_api.secrets import SecretName, SecretStore
from metaguard_api.security_alerts import SECURITY_ALERT_SUBJECT, SECURITY_ALERT_TEXT
from metaguard_api.settings import Settings
from metaguard_api.system_security_events import record_password_check_outage
from metaguard_api.virustotal import VirusTotalResult, VirusTotalStatus

_LOOPBACK_IPS = frozenset({"127.0.0.1", "::1"})
_LOOPBACK_ORIGIN_HOSTS = _LOOPBACK_IPS | {"localhost"}
_MAX_BLOCKLIST_BYTES = 1024 * 1024
_LOCAL_MAILBOX = re.compile(r"[a-z0-9][a-z0-9._+-]{0,62}@example\.test")


class LocalConfigurationError(RuntimeError):
    """Report invalid local configuration without exposing any setting value."""


class _LocalOptions(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="METAGUARD_LOCAL_", env_file=None)

    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    password_blocklist: Path | None = None
    processor_socket: str | None = None
    processor_uid: int | None = None
    virus_total_enabled: bool = False


@dataclass(frozen=True, slots=True)
class _Transactions:
    database: Database = field(repr=False)

    def begin(self) -> AbstractContextManager[Session]:
        return self.database.transaction()


@dataclass(frozen=True, slots=True)
class _CaptureEmailSender:
    port: int

    def send_verification(self, email: str, token: str) -> None:
        self._send(
            email,
            "MetaGuard local verification code",
            f"Synthetic local verification only.\n\n{token}\n",
        )

    def send_password_reset(self, email: str, code: str) -> None:
        if not isinstance(code, str) or RESET_CODE_PATTERN.fullmatch(code) is None:
            raise ValueError("Invalid password reset code")
        self._send(
            email, "MetaGuard local password reset code", f"Synthetic local reset only.\n\n{code}\n"
        )

    def send_security_alert(self, email: str) -> None:
        self._send(email, SECURITY_ALERT_SUBJECT, SECURITY_ALERT_TEXT)

    def send_login_challenge(self, email: str, code: str) -> None:
        if not isinstance(code, str) or LOGIN_EMAIL_CODE_PATTERN.fullmatch(code) is None:
            raise ValueError("Invalid login challenge code")
        self._send(email, "MetaGuard local login code", f"Synthetic local login only.\n\n{code}\n")

    def _send(self, email: str, subject: str, body: str) -> None:
        if not _LOCAL_MAILBOX.fullmatch(email):
            raise InvalidRegistrationInput("Use a synthetic local email address")
        message = EmailMessage()
        message["From"] = "metaguard@example.test"
        message["To"] = email
        message["Subject"] = subject
        message.set_content(body)
        with smtplib.SMTP("127.0.0.1", self.port, local_hostname="[127.0.0.1]", timeout=3) as smtp:
            if smtp.send_message(message):
                raise RuntimeError("Local email capture did not accept the message")


class _OfflineVirusTotal:
    def lookup(self, digest: str, database: Database | None, *, now: int) -> VirusTotalResult:
        return VirusTotalResult(VirusTotalStatus.UNAVAILABLE)


def _offline_password_lookup(_prefix: str, _headers: dict[str, str]) -> str:
    raise RangeServiceUnavailable("Online screening is disabled in local development")


def _read_blocklist(path: Path) -> frozenset[str]:
    if not path.is_file():
        raise ValueError("A regular password blocklist file is required")
    with path.open("rb") as blocklist:
        data = blocklist.read(_MAX_BLOCKLIST_BYTES + 1)
    if len(data) > _MAX_BLOCKLIST_BYTES:
        raise ValueError("The local password blocklist is oversized")
    passwords = frozenset(password for password in data.decode("utf-8").splitlines() if password)
    if not passwords:
        raise ValueError("The local password blocklist is empty")
    return passwords


def _linux_uid() -> int | None:
    return os.geteuid() if sys.platform == "linux" else None


def _processor_config(options: _LocalOptions, settings: Settings) -> ProcessingClientConfig | None:
    if options.processor_socket is None and options.processor_uid is None:
        return None
    api_uid = _linux_uid()
    if (
        api_uid is None
        or api_uid <= 0
        or not options.processor_socket
        or options.processor_uid is None
        or options.processor_uid in {0, api_uid}
        or settings.upload_max_bytes > MAX_FILE_SIZE
    ):
        raise LocalConfigurationError("Isolated processing requires a separate Linux service user")
    return ProcessingClientConfig(
        socket_path=options.processor_socket,
        server_uid=options.processor_uid,
        timeout=120,
    )


def _validate_boundary(
    settings: Settings, database: DatabaseSettings, options: _LocalOptions
) -> None:
    origins = settings.auth_allowed_origins
    if (
        settings.environment != "development"
        or len(origins) != 1
        or (origin := urlsplit(origins[0])).scheme != "https"
        or origin.hostname not in _LOOPBACK_ORIGIN_HOSTS
    ):
        raise LocalConfigurationError(
            "Local development requires exactly one loopback HTTPS origin"
        )
    if (
        database.host not in _LOOPBACK_IPS
        or database.name != "metaguard_test"
        or any(option in os.environ for option in ("PGHOSTADDR", "PGSERVICE"))
    ):
        raise LocalConfigurationError(
            "Local development requires the dedicated disposable database"
        )
    if (options.smtp_port is None) != (options.password_blocklist is None):
        raise LocalConfigurationError("Local registration requires a capture port and blocklist")


def create_local_app() -> FastAPI:
    """Compose a local API without migrations or real provider access by default."""
    database = None
    try:
        settings = Settings()
        database_settings = DatabaseSettings()
        options = _LocalOptions()
        _validate_boundary(settings, database_settings, options)
        processor_config = _processor_config(options, settings)
        if options.virus_total_enabled and processor_config is None:
            raise LocalConfigurationError("Local reputation checks require isolated processing")
        rate_limiter = LocalRateLimiter(settings)
        secrets = SecretStore(settings.secret_dir)
        signing_key = secrets.read_text(SecretName.JWT_SIGNING_KEY)
        totp_key = secrets.read(SecretName.TOTP_ENCRYPTION_KEY)
        if len(signing_key.encode("utf-8")) < 32 or len(totp_key) != 32:
            raise ValueError("Invalid local authentication keys")
        storage_key = (
            secrets.read(SecretName.DATA_ENCRYPTION_KEY) if processor_config is not None else None
        )
        if storage_key is not None and (len(storage_key) != 32 or storage_key == totp_key):
            raise ValueError("A separate local storage key is required")
        blocklist = (
            _read_blocklist(options.password_blocklist) if options.password_blocklist else None
        )
        database = create_database(database_settings, connect_timeout_seconds=3)
        app = _compose_app(
            settings,
            options,
            database,
            AuthRuntime(
                session_factory=_Transactions(database),
                rate_limiter=rate_limiter,
                signing_key=signing_key,
                issuer="metaguard-local",
                audience="metaguard-local-api",
                dummy_password_hash=hash_password(token_urlsafe(32)),
                totp_encryption_key=totp_key,
                totp_key_version=1,
                session_lifetime=timedelta(minutes=15),
                mfa_challenge_lifetime=timedelta(minutes=5),
                common_passwords=blocklist,
                password_lookup=_offline_password_lookup if blocklist else None,
                report_password_outage=(
                    lambda event: record_password_check_outage(database, event, now=int(time()))
                )
                if blocklist
                else None,
                email_sender=(
                    _CaptureEmailSender(options.smtp_port)
                    if options.smtp_port is not None
                    else None
                ),
                email_verification_lifetime=timedelta(hours=1) if blocklist else None,
                login_risk_enabled=True,
            ),
            FileRuntime(
                store=InMemoryTemporaryFileStore(max_bytes=MAX_FILE_SIZE * 4),
                storage_key=storage_key,
                processing_client=ProcessingClient(processor_config),
                database=database,
            )
            if processor_config is not None and storage_key is not None
            else None,
        )
    except Exception:
        if database is not None:
            with suppress(Exception):
                database.close()
        raise LocalConfigurationError(
            "Local API configuration is unavailable; see docs/desarrollo-local.md"
        ) from None
    return app


def _compose_app(
    settings: Settings,
    options: _LocalOptions,
    database: Database,
    auth_runtime: AuthRuntime,
    file_runtime: FileRuntime | None,
) -> FastAPI:
    from metaguard_api.main import create_app

    app = create_app(
        settings,
        auth_runtime=auth_runtime,
        file_runtime=file_runtime,
        virus_total_client=None if options.virus_total_enabled else _OfflineVirusTotal(),
        database=database,
        security_alert_sender=(
            auth_runtime.email_sender
            if isinstance(auth_runtime.email_sender, _CaptureEmailSender)
            else None
        ),
    )
    api_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(instance: FastAPI):
        try:
            async with api_lifespan(instance) as state:
                yield state
        finally:
            try:
                database.close()
            except Exception:
                raise LocalConfigurationError("Local API database cleanup failed") from None

    app.router.lifespan_context = lifespan

    @app.middleware("http")
    async def require_loopback_peer(request: Request, call_next):
        if request.client is None or request.client.host not in _LOOPBACK_IPS:
            return JSONResponse(
                status_code=403,
                content={"error": {"code": "local_only", "message": "Local access required"}},
                headers={"Cache-Control": "no-store"},
            )
        return await call_next(request)

    return app
