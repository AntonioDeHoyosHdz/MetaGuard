"""Explicit composition for private staging with synthetic data only."""

import os
import stat
import sys
from contextlib import AbstractContextManager, asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import timedelta
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from secrets import token_urlsafe
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.orm import Session

from metaguard_api.account_credentials import hash_password
from metaguard_api.auth_routes import AuthRuntime
from metaguard_api.database import Database, DatabaseSettings, create_database
from metaguard_api.file_routes import FileRuntime
from metaguard_api.file_storage import InMemoryTemporaryFileStore
from metaguard_api.local_rate_limit import LocalRateLimiter
from metaguard_api.main import create_app
from metaguard_api.processing_ipc_client import ProcessingClient, ProcessingClientConfig
from metaguard_api.processing_limits import MAX_FILE_SIZE
from metaguard_api.secrets import SecretName, SecretStore
from metaguard_api.settings import Settings
from metaguard_api.virustotal import VirusTotalClient, VirusTotalResult, VirusTotalStatus

_PRIVATE_NETWORKS = tuple(
    IPv4Network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_LIBPQ_OVERRIDES = frozenset({"PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", "PGOPTIONS"})
_FORWARDING_HEADERS = frozenset(
    {"forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-port", "x-forwarded-proto"}
)


class StagingConfigurationError(RuntimeError):
    """Configuration details must not appear in startup errors."""


class _StagingOptions(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="METAGUARD_STAGING_", env_file=None)

    synthetic_only: bool = False
    allowed_peer: str
    db_tls_ca: Path
    processor_socket: str
    processor_uid: int


@dataclass(frozen=True, slots=True)
class _Transactions:
    database: Database = field(repr=False)

    def begin(self) -> AbstractContextManager[Session]:
        return self.database.transaction()


class _OfflineVirusTotal:
    def lookup(self, digest: str, database: Database | None, *, now: int) -> VirusTotalResult:
        return VirusTotalResult(VirusTotalStatus.UNAVAILABLE)


def _linux_uid() -> int | None:
    return os.geteuid() if sys.platform == "linux" else None


def _is_private_ipv4(host: str) -> bool:
    try:
        address = IPv4Address(host)
    except ValueError:
        return False
    return any(address in network for network in _PRIVATE_NETWORKS)


def _trusted_ca(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("Configure an absolute path to the staging CA")
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_size == 0
        or not os.access(resolved, os.R_OK)
        or (sys.platform == "linux" and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    ):
        raise ValueError("The staging CA must be a readable, protected regular file")
    return resolved


def _validate_boundary(
    settings: Settings, db: DatabaseSettings, options: _StagingOptions
) -> tuple[Path, ProcessingClientConfig]:
    origins = settings.auth_allowed_origins
    if (
        not options.synthetic_only
        or settings.environment != "production"
        or len(origins) != 1
        or urlsplit(origins[0]).scheme != "https"
    ):
        raise ValueError("Staging requires explicit synthetic-only mode and one HTTPS origin")
    if options.allowed_peer != "127.0.0.1" and not _is_private_ipv4(options.allowed_peer):
        raise ValueError("Staging requires a private ingress peer")
    if (
        not _is_private_ipv4(db.host)
        or db.name not in {"metaguard_staging", "metaguard_registration_trial"}
        or db.user != "metaguard_app"
        or _LIBPQ_OVERRIDES.intersection(os.environ)
    ):
        raise ValueError("Staging requires the dedicated private PostgreSQL database")
    api_uid = _linux_uid()
    if (
        api_uid is None
        or api_uid <= 0
        or options.processor_uid in {0, api_uid}
        or settings.upload_max_bytes > MAX_FILE_SIZE
    ):
        raise ValueError("Staging requires separate unprivileged Linux service users")
    return _trusted_ca(options.db_tls_ca), ProcessingClientConfig(
        socket_path=options.processor_socket, server_uid=options.processor_uid, timeout=120
    )


def _bind_lifespan_and_ingress(app: FastAPI, database: Database, allowed_peer: str) -> None:
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
                raise StagingConfigurationError("Staging API database cleanup failed") from None

    app.router.lifespan_context = lifespan

    @app.middleware("http")
    async def require_direct_peer(request: Request, call_next):
        if (
            request.client is None
            or request.client.host != allowed_peer
            or _FORWARDING_HEADERS.intersection(request.headers)
        ):
            return JSONResponse(
                status_code=403,
                content={
                    "error": {"code": "staging_peer_denied", "message": "Private access required"}
                },
                headers={"Cache-Control": "no-store"},
            )
        return await call_next(request)


def create_staging_app() -> FastAPI:
    """Enable private auth and isolated processing without migrations or external providers."""
    database = None
    try:
        settings = Settings()
        db_settings = DatabaseSettings()
        options = _StagingOptions()
        ca_path, processor = _validate_boundary(settings, db_settings, options)
        secrets = SecretStore(settings.secret_dir)
        signing_key = secrets.read_text(SecretName.JWT_SIGNING_KEY)
        totp_key = secrets.read(SecretName.TOTP_ENCRYPTION_KEY)
        storage_key = secrets.read(SecretName.DATA_ENCRYPTION_KEY)
        if len(signing_key.encode("utf-8")) < 32 or len(totp_key) != 32 or len(storage_key) != 32:
            raise ValueError("Invalid staging keys")
        if storage_key == totp_key or signing_key.encode("utf-8") in {totp_key, storage_key}:
            raise ValueError("Staging keys must be distinct")
        database = create_database(db_settings, connect_timeout_seconds=3, tls_root_cert=ca_path)
        app = create_app(
            settings,
            auth_runtime=AuthRuntime(
                session_factory=_Transactions(database),
                rate_limiter=LocalRateLimiter(settings),
                signing_key=signing_key,
                issuer="metaguard-registration-trial"
                if db_settings.name == "metaguard_registration_trial"
                else "metaguard-staging",
                audience="metaguard-registration-trial-api"
                if db_settings.name == "metaguard_registration_trial"
                else "metaguard-staging-api",
                dummy_password_hash=hash_password(token_urlsafe(32)),
                totp_encryption_key=totp_key,
                totp_key_version=1,
                session_lifetime=timedelta(minutes=15),
                mfa_challenge_lifetime=timedelta(minutes=5),
            ),
            file_runtime=FileRuntime(
                store=InMemoryTemporaryFileStore(max_bytes=MAX_FILE_SIZE * 4),
                storage_key=storage_key,
                processing_client=ProcessingClient(processor),
                database=database,
            ),
            virus_total_client=(
                VirusTotalClient(secrets)
                if (settings.secret_dir / SecretName.VIRUSTOTAL_API_KEY.value).is_file()
                else _OfflineVirusTotal()
            ),
            database=database,
            security_alert_sender=None,
        )
        _bind_lifespan_and_ingress(app, database, options.allowed_peer)
    except Exception:
        if database is not None:
            with suppress(Exception):
                database.close()
        raise StagingConfigurationError(
            "Staging API configuration is unavailable; see docs/validacion-staging.md"
        ) from None
    return app
