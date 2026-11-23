"""FastAPI application entry point."""

import asyncio
from contextlib import asynccontextmanager, suppress
from functools import partial
from typing import Literal

from fastapi import FastAPI, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text

from metaguard_api.account_password_routes import create_account_password_router
from metaguard_api.auth_routes import AuthRuntime, create_auth_router
from metaguard_api.database import Database, DatabaseSettings, create_database
from metaguard_api.file_maintenance import run_maintenance_loop
from metaguard_api.file_routes import FileRuntime, create_file_router
from metaguard_api.file_storage import InMemoryTemporaryFileStore
from metaguard_api.maintenance import purge_maintenance_for_api
from metaguard_api.mfa_routes import create_mfa_router
from metaguard_api.password_reset_routes import create_password_reset_router
from metaguard_api.report_routes import create_report_router
from metaguard_api.secrets import SecretStore
from metaguard_api.security_alert_dispatch import run_security_alert_dispatch_loop
from metaguard_api.security_alerts import SecurityAlertSender, dispatch_security_alerts
from metaguard_api.security_event_routes import create_security_event_router
from metaguard_api.settings import Settings
from metaguard_api.virustotal import VirusTotalClient, VirusTotalLookup


class LiveStatus(BaseModel):
    status: Literal["ok"]


class ReadyStatus(BaseModel):
    status: Literal["ok", "unavailable"]


def _maintenance_dependencies_ready(file_runtime: FileRuntime | None) -> bool:
    return (
        isinstance(file_runtime, FileRuntime)
        and isinstance(file_runtime.store, InMemoryTemporaryFileStore)
        and isinstance(file_runtime.database, Database)
    )


def create_app(
    settings: Settings | None = None,
    *,
    auth_runtime: AuthRuntime | None = None,
    file_runtime: FileRuntime | None = None,
    virus_total_client: VirusTotalLookup | None = None,
    database: Database | None = None,
    security_alert_sender: SecurityAlertSender | None = None,
) -> FastAPI:
    """Create the API without connecting to external services at import time."""
    app_settings = settings or Settings()
    configured_virus_total_client = virus_total_client or VirusTotalClient(
        SecretStore(app_settings.secret_dir)
    )
    docs_enabled = app_settings.environment != "production"

    @asynccontextmanager
    async def lifespan(instance: FastAPI):
        task = None
        if _maintenance_dependencies_ready(file_runtime):
            purge = (
                purge_maintenance_for_api
                if database is None
                else partial(purge_maintenance_for_api, database=database)
            )
            task = asyncio.create_task(
                run_maintenance_loop(
                    purge,
                    file_runtime,
                )
            )
        instance.state.maintenance_task = task
        security_alert_task = None
        if auth_runtime is not None and security_alert_sender is not None:
            dispatch = partial(
                dispatch_security_alerts,
                auth_runtime.session_factory,
                security_alert_sender,
                now=auth_runtime.now,
            )
            security_alert_task = asyncio.create_task(run_security_alert_dispatch_loop(dispatch))
        instance.state.security_alert_task = security_alert_task
        try:
            yield
        finally:
            tasks = tuple(pending for pending in (task, security_alert_task) if pending is not None)
            for pending in tasks:
                pending.cancel()
            for pending in tasks:
                with suppress(asyncio.CancelledError):
                    await pending

    app = FastAPI(
        title="MetaGuard API",
        version="0.1.0",
        openapi_url="/openapi.json" if docs_enabled else None,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = app_settings
    app.state.auth_runtime = auth_runtime
    app.state.file_runtime = file_runtime
    app.include_router(create_auth_router(app_settings, auth_runtime))
    app.include_router(create_password_reset_router(app_settings, auth_runtime))
    app.include_router(create_account_password_router(app_settings, auth_runtime))
    app.include_router(create_mfa_router(app_settings, auth_runtime))
    app.include_router(
        create_file_router(app_settings, auth_runtime, file_runtime, configured_virus_total_client)
    )
    app.include_router(create_report_router(app_settings, auth_runtime, file_runtime))
    app.include_router(create_security_event_router(app_settings, auth_runtime))
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(app_settings.auth_allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
        max_age=600,
    )

    @app.middleware("http")
    async def disable_auth_caching(request, call_next):
        response = await call_next(request)
        if request.url.path.startswith(("/v1/auth/", "/v1/users/me/totp/")):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def redact_auth_validation_errors(request, error):
        if request.url.path.startswith(("/v1/auth/", "/v1/users/me/totp/")):
            return JSONResponse(
                status_code=400,
                content={"error": {"code": "invalid_request", "message": "Invalid request"}},
                headers={"Cache-Control": "no-store"},
            )
        return await request_validation_exception_handler(request, error)

    @app.get(
        "/health/live",
        response_model=LiveStatus,
        tags=["health"],
        summary="Check whether the API process is alive",
    )
    def live() -> LiveStatus:
        return LiveStatus(status="ok")

    @app.get(
        "/health/ready",
        response_model=ReadyStatus,
        responses={503: {"model": ReadyStatus}},
        tags=["health"],
        summary="Check database availability",
    )
    def ready(response: Response) -> ReadyStatus:
        response.headers["Cache-Control"] = "no-store"
        try:
            ready_database = (
                database
                if database is not None
                else create_database(DatabaseSettings(), connect_timeout_seconds=3)
            )
            try:
                with ready_database.transaction() as session:
                    available = session.execute(text("SELECT 1")).scalar_one() == 1
            finally:
                if database is None:
                    ready_database.close()
        except Exception:
            # Dependency errors may contain connection details; never expose them here.
            available = False
        if not available:
            response.status_code = 503
        return ReadyStatus(status="ok" if available else "unavailable")

    return app


app = create_app()
