from fastapi.testclient import TestClient

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
