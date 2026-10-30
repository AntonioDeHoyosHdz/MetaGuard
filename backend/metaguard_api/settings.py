"""Validated, non-secret runtime settings for the API."""

from pathlib import Path
from typing import Literal

from pydantic import Field, PositiveInt
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings; credentials are read from Docker Secret files separately."""

    model_config = SettingsConfigDict(
        env_prefix="METAGUARD_",
        env_file=None,
        extra="forbid",
    )

    environment: Literal["development", "test", "demo", "production"] = "production"
    secret_dir: Path = Path("/run/secrets")

    # User-approved initial demo limits from docs/limites.md (not production defaults).
    upload_max_bytes: int = Field(default=25 * 1024 * 1024, gt=0)
    image_max_side_px: int = Field(default=8_000, gt=0)
    image_max_pixels: int = Field(default=40_000_000, gt=0)
    pdf_max_pages: int = Field(default=100, gt=0)
    processing_timeout_seconds: int = Field(default=60, gt=0)
    worker_cpu_limit: float = Field(default=1.0, gt=0)
    worker_memory_bytes: int = Field(default=1024**3, gt=0)
    worker_concurrency: int = Field(default=1, gt=0)

    requests_per_minute_per_ip: int = Field(default=60, gt=0)
    requests_per_minute_per_account: int = Field(default=120, gt=0)
    registrations_per_hour_per_ip: int = Field(default=5, gt=0)
    uploads_per_minute_per_ip: int = Field(default=3, gt=0)
    uploads_per_hour_per_account: int = Field(default=10, gt=0)
    login_failures_before_lock: int = Field(default=5, gt=0)
    login_lockout_seconds: tuple[PositiveInt, PositiveInt, PositiveInt] = (60, 300, 900)
