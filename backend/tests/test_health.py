from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from metaguard_api.database import Database
from metaguard_api.main import create_app
from metaguard_api.settings import Settings


def test_liveness_is_minimal_and_does_not_need_runtime_secrets() -> None:
    app = create_app(Settings(_env_file=None, environment="test"))

    with TestClient(app) as client:
        response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_openapi_documents_liveness_endpoint() -> None:
    app = create_app(Settings(_env_file=None, environment="test"))

    schema = app.openapi()

    assert "/health/live" in schema["paths"]


def test_production_hides_interactive_api_docs() -> None:
    app = create_app(Settings(_env_file=None, environment="production"))

    with TestClient(app) as client:
        response = client.get("/docs")

    assert response.status_code == 404


def test_production_hides_openapi_schema() -> None:
    app = create_app(Settings(_env_file=None, environment="production"))

    with TestClient(app) as client:
        response = client.get("/openapi.json")

    assert response.status_code == 404


def test_readiness_checks_database_and_closes_it(monkeypatch: pytest.MonkeyPatch) -> None:
    database = MagicMock()
    session = database.transaction.return_value.__enter__.return_value
    session.execute.return_value.scalar_one.return_value = 1
    factory = MagicMock(return_value=database)
    monkeypatch.setattr("metaguard_api.main.create_database", factory)
    app = create_app(Settings(_env_file=None, environment="test"))

    with TestClient(app) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
        factory.assert_not_called()
        response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["cache-control"] == "no-store"
    assert factory.call_args.kwargs == {"connect_timeout_seconds": 3}
    assert str(session.execute.call_args.args[0]) == "SELECT 1"
    database.close.assert_called_once()


def test_readiness_failure_is_minimal_and_releases_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = MagicMock()
    session = database.transaction.return_value.__enter__.return_value
    session.execute.side_effect = RuntimeError("sensitive database error")
    monkeypatch.setattr("metaguard_api.main.create_database", lambda *_args, **_kwargs: database)
    app = create_app(Settings(_env_file=None, environment="test"))

    with TestClient(app) as client:
        response = client.get("/health/ready")
        live_response = client.get("/health/live")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    assert response.headers["cache-control"] == "no-store"
    assert "sensitive" not in response.text
    assert live_response.json() == {"status": "ok"}
    database.close.assert_called_once()


def test_readiness_handles_missing_database_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise RuntimeError("sensitive secret path")

    monkeypatch.setattr("metaguard_api.main.create_database", fail)
    app = create_app(Settings(_env_file=None, environment="test"))
    with TestClient(app) as client:
        response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    assert "secret" not in response.text


def test_readiness_executes_sql_with_real_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "metaguard_api.main.create_database",
        lambda *_args, **_kwargs: Database(create_engine("sqlite://")),
    )
    app = create_app(Settings(_env_file=None, environment="test"))
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_rejects_unexpected_database_result(monkeypatch: pytest.MonkeyPatch) -> None:
    database = MagicMock()
    session = database.transaction.return_value.__enter__.return_value
    session.execute.return_value.scalar_one.return_value = 0
    monkeypatch.setattr("metaguard_api.main.create_database", lambda *_args, **_kwargs: database)
    app = create_app(Settings(_env_file=None, environment="test"))
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    database.close.assert_called_once()
