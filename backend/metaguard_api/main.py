"""FastAPI application entry point."""

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

from metaguard_api.settings import Settings


class LiveStatus(BaseModel):
    status: Literal["ok"]


def create_app(settings: Settings | None = None) -> FastAPI:
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

    @app.get(
        "/health/live",
        response_model=LiveStatus,
        tags=["health"],
        summary="Check whether the API process is alive",
    )
    def live() -> LiveStatus:
        return LiveStatus(status="ok")

    return app


app = create_app()
