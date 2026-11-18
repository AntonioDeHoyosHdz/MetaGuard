"""Validated, non-secret runtime settings for the API."""

from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, PositiveInt, field_validator, model_validator
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
    auth_allowed_origins: tuple[str, ...] = ()
    auth_cookie_samesite: Literal["lax", "strict", "none"] = "lax"

    @field_validator("auth_allowed_origins")
    @classmethod
    def validate_auth_allowed_origins(cls, origins: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(origins)) != len(origins):
            raise ValueError("Authentication origins must be unique")
        for origin in origins:
            parsed = urlsplit(origin)
            if (
                origin == "*"
                or parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.hostname is None
                or parsed.netloc.endswith(":")
                or parsed.path
                or parsed.query
                or parsed.fragment
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("Authentication origins must be exact HTTP(S) origins")
            try:
                port = parsed.port
            except ValueError as error:
                raise ValueError("Authentication origins must use a valid port") from error
            if port == 0:
                raise ValueError("Authentication origins must use a valid port")
        return origins

    @model_validator(mode="after")
    def validate_auth_cookie_policy(self) -> "Settings":
        if self.auth_cookie_samesite == "none" and not self.auth_allowed_origins:
            raise ValueError("SameSite=None requires an exact allowed-origin list")
        return self

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
