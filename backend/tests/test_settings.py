import pytest
from pydantic import ValidationError

from metaguard_api.settings import Settings


def test_settings_use_approved_demo_limits() -> None:
    settings = Settings(_env_file=None)

    assert settings.environment == "production"
    assert settings.upload_max_bytes == 25 * 1024 * 1024
    assert settings.image_max_side_px == 8_000
    assert settings.image_max_pixels == 40_000_000
    assert settings.pdf_max_pages == 100
    assert settings.processing_timeout_seconds == 60
    assert settings.worker_cpu_limit == 1.0
    assert settings.worker_memory_bytes == 1024**3
    assert settings.worker_concurrency == 1
    assert settings.requests_per_minute_per_ip == 60
    assert settings.requests_per_minute_per_account == 120
    assert settings.registrations_per_hour_per_ip == 5
    assert settings.uploads_per_minute_per_ip == 3
    assert settings.uploads_per_hour_per_account == 10
    assert settings.login_failures_before_lock == 5
    assert settings.login_lockout_seconds == (60, 300, 900)


def test_settings_only_read_prefixed_environment_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UPLOAD_MAX_BYTES", "1")
    monkeypatch.setenv("METAGUARD_UPLOAD_MAX_BYTES", "4096")

    settings = Settings(_env_file=None)

    assert settings.upload_max_bytes == 4096


def test_settings_reject_invalid_resource_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("METAGUARD_UPLOAD_MAX_BYTES", "0")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_reject_non_positive_lockout_durations(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("METAGUARD_LOGIN_LOCKOUT_SECONDS", "[-1, 0, -900]")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)
