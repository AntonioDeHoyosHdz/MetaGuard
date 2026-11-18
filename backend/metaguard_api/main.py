"""FastAPI application entry point."""

from typing import Literal

from fastapi import FastAPI, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text

from metaguard_api.auth_routes import AuthRuntime, create_auth_router
from metaguard_api.database import DatabaseSettings, create_database
from metaguard_api.file_routes import FileRuntime, create_file_router
from metaguard_api.settings import Settings


class LiveStatus(BaseModel):
    status: Literal["ok"]


class ReadyStatus(BaseModel):
    status: Literal["ok", "unavailable"]


def create_app(
    settings: Settings | None = None,
    *,
    auth_runtime: AuthRuntime | None = None,
    file_runtime: FileRuntime | None = None,
) -> FastAPI:
    """Create the API without connecting to external services at import time."""
    app_settings = settings or Settings()
    docs_enabled = app_settings.environment != "production"

    app = FastAPI(
        title="MetaGuard API",
        version="0.1.0",
        openapi_url="/openapi.json" if docs_enabled else None,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
    )
    app.state.settings = app_settings
    app.state.auth_runtime = auth_runtime
    app.state.file_runtime = file_runtime
    app.include_router(create_auth_router(app_settings, auth_runtime))
    app.include_router(create_file_router(app_settings, auth_runtime, file_runtime))
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(app_settings.auth_allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
        max_age=600,
    )

    @app.middleware("http")
    async def disable_auth_caching(request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/v1/auth/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def redact_auth_validation_errors(request, error):
        if request.url.path.startswith("/v1/auth/"):
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
            database = create_database(DatabaseSettings(), connect_timeout_seconds=3)
            try:
                with database.transaction() as session:
                    available = session.execute(text("SELECT 1")).scalar_one() == 1
            finally:
                database.close()
        except Exception:
            # Dependency errors may contain connection details; never expose them here.
            available = False
        if not available:
            response.status_code = 503
        return ReadyStatus(status="ok" if available else "unavailable")

    return app


app = create_app()
