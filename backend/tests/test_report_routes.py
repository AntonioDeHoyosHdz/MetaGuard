import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from metaguard_api.account_credentials import hash_password
from metaguard_api.accounts import Account
from metaguard_api.auth_routes import AuthRuntime
from metaguard_api.database import Base, Database
from metaguard_api.file_routes import FileRuntime
from metaguard_api.file_storage import InMemoryTemporaryFileStore
from metaguard_api.main import create_app
from metaguard_api.processing_ipc_client import ProcessingClient
from metaguard_api.processing_types import ProcessedFile, ProcessingReport
from metaguard_api.reports import FileReport
from metaguard_api.reports import create_report as persist_report
from metaguard_api.settings import Settings

ORIGIN = "https://frontend.example"
SIGNING_KEY = "synthetic-jwt-signing-key-for-tests-only-32-bytes"
TOTP_KEY = b"t" * 32
STORAGE_KEY = b"s" * 32
NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
PASSWORD = "correct horse battery staple"
REPORT_FIELDS = {
    "media_type",
    "metadata_categories",
    "output_verified",
    "width",
    "height",
    "page_count",
    "active_content_removed",
    "uri_links_removed",
}


class FakeRateLimiter:
    def __init__(self):
        self.calls = []

    def allow(self, action, client_ip, identity):
        self.calls.append((action, client_ip, identity))
        return True


class FakeProcessingClient(ProcessingClient):
    def __init__(self):
        self.calls = []

    def process(self, data, content_type):
        self.calls.append((data, content_type))
        return ProcessedFile(
            cleaned_bytes=b"synthetic-cleaned-copy",
            media_type=content_type,
            report=ProcessingReport(
                media_type=content_type,
                metadata_categories=("gps", "software"),
                output_verified=True,
                width=12,
                height=8,
                active_content_removed=False,
                uri_links_removed=0,
            ),
        )


@pytest.fixture
def api_factory():
    environments = []

    def build():
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        factory = sessionmaker(engine, expire_on_commit=False)
        owner_id = str(uuid4())
        other_id = str(uuid4())
        with factory.begin() as session:
            session.add_all(
                [
                    Account(
                        id=owner_id,
                        email="owner@example.test",
                        password_hash=hash_password(PASSWORD),
                        email_verified_at=NOW,
                    ),
                    Account(
                        id=other_id,
                        email="other@example.test",
                        password_hash=hash_password(PASSWORD),
                        email_verified_at=NOW,
                    ),
                ]
            )

        limiter = FakeRateLimiter()
        auth_runtime = AuthRuntime(
            session_factory=factory,
            rate_limiter=limiter,
            signing_key=SIGNING_KEY,
            issuer="https://api.example",
            audience="metaguard-api",
            dummy_password_hash=hash_password("constant dummy password"),
            totp_encryption_key=TOTP_KEY,
            totp_key_version=1,
            session_lifetime=timedelta(days=2),
            mfa_challenge_lifetime=timedelta(minutes=5),
            now=lambda: NOW,
        )
        store = InMemoryTemporaryFileStore(max_bytes=4096)
        file_runtime = FileRuntime(
            store=store,
            storage_key=STORAGE_KEY,
            processing_client=FakeProcessingClient(),
            database=Database(engine),
        )
        settings = Settings(environment="test", auth_allowed_origins=(ORIGIN,))
        app = create_app(settings, auth_runtime=auth_runtime, file_runtime=file_runtime)
        environments.append((engine, factory, app, store, limiter, owner_id, other_id))
        return environments[-1]

    yield build
    for engine, *_ in environments:
        engine.dispose()


def login_client(app, email):
    client = TestClient(app, base_url="https://api.example")
    preauth = client.get("/v1/auth/status")
    response = client.post(
        "/v1/auth/login",
        json={"email": email, "password": PASSWORD},
        headers={"Origin": ORIGIN, "X-CSRF-Token": preauth.json()["csrf_token"]},
    )
    assert response.status_code == 200
    return client, {"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]}


def create_report(client, headers):
    uploaded = client.post(
        "/v1/uploads",
        content=b"synthetic source bytes",
        headers={**headers, "Content-Type": "image/png"},
    )
    assert uploaded.status_code == 201
    response = client.post(f"/v1/analyses/{uploaded.json()['upload_id']}", json={}, headers=headers)
    assert response.status_code == 200
    return response.json()


def test_analysis_persists_only_minimized_report_and_returns_owner_resource(api_factory):
    _, factory, app, store, _, owner_id, _ = api_factory()
    client, headers = login_client(app, "owner@example.test")

    result = create_report(client, headers)

    assert set(result) == {"report_id", "report", "created_at", "expires_at", "virus_total"}
    assert result["virus_total"]["original"]["status"] == "not_requested"
    assert result["virus_total"]["cleaned"]["status"] == "not_requested"
    assert set(result["report"]) == REPORT_FIELDS
    assert result["report"]["metadata_categories"] == ["gps", "software"]
    assert result["expires_at"] == "2026-11-19T12:00:00+00:00"
    assert (
        store.get(result["report_id"], owner_id, key=STORAGE_KEY, now=NOW)
        == b"synthetic-cleaned-copy"
    )
    with factory() as session:
        row = session.get(FileReport, result["report_id"])
        assert row is not None
        assert row.owner_id == owner_id
        assert row.download_token_digest is None
        assert set(json.loads(row.report_json)) == REPORT_FIELDS
        assert "synthetic source bytes" not in row.report_json
        assert "synthetic-cleaned-copy" not in row.report_json


def test_report_persistence_rejects_extracted_values_and_extra_fields(api_factory):
    _, factory, app, _, _, owner_id, _ = api_factory()
    valid_shape = {
        "media_type": "image/png",
        "metadata_categories": ["gps"],
        "output_verified": True,
        "width": 12,
        "height": 8,
        "page_count": None,
        "active_content_removed": False,
        "uri_links_removed": 0,
    }
    extracted_value = {**valid_shape, "metadata_categories": ["latitude=12.34"]}
    extra_field = {**valid_shape, "gps": {"latitude": 12.34}}
    database = app.state.file_runtime.database

    assert (
        persist_report(
            database,
            report_id=str(uuid4()),
            owner_id=owner_id,
            report=extracted_value,
            now=NOW,
        )
        is None
    )
    assert (
        persist_report(
            database,
            report_id=str(uuid4()),
            owner_id=owner_id,
            report=extra_field,
            now=NOW,
        )
        is None
    )
    with factory() as session:
        assert session.query(FileReport).count() == 0


def test_report_list_and_object_routes_hide_foreign_reports(api_factory):
    _, _, app, _, _, _, _ = api_factory()
    owner, owner_headers = login_client(app, "owner@example.test")
    other, other_headers = login_client(app, "other@example.test")
    result = create_report(owner, owner_headers)
    report_id = result["report_id"]

    owner_list = owner.get("/v1/reports", headers=owner_headers)
    other_list = other.get("/v1/reports", headers=other_headers)
    owner_get = owner.get(f"/v1/reports/{report_id}", headers=owner_headers)
    foreign_get = other.get(f"/v1/reports/{report_id}", headers=other_headers)
    foreign_delete = other.delete(f"/v1/reports/{report_id}", headers=other_headers)
    foreign_token = other.post(f"/v1/reports/{report_id}/download-token", headers=other_headers)

    assert owner_list.status_code == 200
    assert [item["report_id"] for item in owner_list.json()["reports"]] == [report_id]
    assert other_list.status_code == 200 and other_list.json() == {"reports": []}
    assert owner_get.status_code == 200 and owner_get.json()["report_id"] == report_id
    for response in (foreign_get, foreign_delete, foreign_token):
        assert response.status_code == 404
        assert response.json() == {"error": {"code": "not_found", "message": "Report not found"}}


def test_download_token_is_digest_only_one_use_and_deletes_clean_copy(api_factory):
    engine, factory, app, store, _, owner_id, _ = api_factory()
    client, headers = login_client(app, "owner@example.test")
    result = create_report(client, headers)
    report_id = result["report_id"]
    statements = []
    event.listen(
        engine,
        "before_cursor_execute",
        lambda _conn, _cursor, statement, _parameters, _context, _many: statements.append(
            statement
        ),
    )

    issued = client.post(f"/v1/reports/{report_id}/download-token", headers=headers)

    assert issued.status_code == 200
    assert set(issued.json()) == {"token", "expires_at"}
    token = issued.json()["token"]
    digest = sha256(token.encode("ascii")).hexdigest()
    assert issued.json()["expires_at"] == "2026-11-18T12:10:00+00:00"
    with factory() as session:
        row = session.get(FileReport, report_id)
        assert row.download_token_digest == digest
        assert token not in repr(row)

    for missing in ("Origin", "X-CSRF-Token"):
        incomplete = {name: value for name, value in headers.items() if name != missing}
        denied = client.post("/v1/downloads", headers=incomplete, json={"token": token})
        assert denied.status_code == 403
    downloaded = client.post("/v1/downloads", headers=headers, json={"token": token})
    replay = client.post("/v1/downloads", headers=headers, json={"token": token})

    assert downloaded.status_code == 200
    assert downloaded.content == b"synthetic-cleaned-copy"
    assert downloaded.headers["content-type"] == "image/png"
    assert downloaded.headers["cache-control"] == "no-store"
    assert replay.status_code == 404
    assert store.get(report_id, owner_id, key=STORAGE_KEY, now=NOW) is None
    with factory() as session:
        row = session.get(FileReport, report_id)
        assert row.download_token_digest is None
    consume_statements = [
        statement
        for statement in statements
        if statement.lstrip().upper().startswith("UPDATE FILE_REPORTS")
    ]
    assert any("RETURNING" in statement.upper() for statement in consume_statements)
    assert any("OWNER_ID" in statement.upper() for statement in consume_statements)
    assert all(token not in statement for statement in statements)


def test_download_body_errors_never_reflect_or_log_inputs(api_factory, caplog):
    _, _, app, _, _, _, _ = api_factory()
    client, headers = login_client(app, "owner@example.test")
    marker = "synthetic-private-marker"
    caplog.set_level("INFO")
    for payload in ({"unexpected": marker}, {"token": [marker]}, [marker]):
        response = client.post("/v1/downloads", headers=headers, json=payload)
        assert response.status_code == 400
        assert response.headers["cache-control"] == "no-store"
        assert marker not in response.text
    invalid_json = client.post(
        "/v1/downloads",
        headers={**headers, "Content-Type": "application/json"},
        content=marker,
    )
    assert invalid_json.status_code == 400
    assert marker not in invalid_json.text
    assert marker not in caplog.text
    assert "/v1/downloads/{token}" not in app.openapi()["paths"]


def test_foreign_download_does_not_consume_the_owners_token(api_factory):
    _, _, app, _, _, _, _ = api_factory()
    owner, owner_headers = login_client(app, "owner@example.test")
    other, other_headers = login_client(app, "other@example.test")
    result = create_report(owner, owner_headers)
    issued = owner.post(f"/v1/reports/{result['report_id']}/download-token", headers=owner_headers)

    body = {"token": issued.json()["token"]}
    foreign = other.post("/v1/downloads", json=body, headers=other_headers)
    owner_download = owner.post("/v1/downloads", json=body, headers=owner_headers)

    assert foreign.status_code == 404
    assert owner_download.status_code == 200
    assert owner_download.content == b"synthetic-cleaned-copy"


def test_manual_delete_removes_report_and_clean_copy(api_factory):
    _, factory, app, store, _, owner_id, _ = api_factory()
    client, headers = login_client(app, "owner@example.test")
    result = create_report(client, headers)
    report_id = result["report_id"]

    deleted = client.delete(f"/v1/reports/{report_id}", headers=headers)
    fetched = client.get(f"/v1/reports/{report_id}", headers=headers)

    assert deleted.status_code == 204
    assert fetched.status_code == 404
    with factory() as session:
        assert session.get(FileReport, report_id) is None
    assert store.get(report_id, owner_id, key=STORAGE_KEY, now=NOW) is None


def test_report_expiry_is_24_hours_and_expired_rows_are_not_visible(api_factory):
    _, factory, app, _, _, _, _ = api_factory()
    client, headers = login_client(app, "owner@example.test")
    result = create_report(client, headers)
    assert result["expires_at"] == "2026-11-19T12:00:00+00:00"

    object.__setattr__(
        app.state.auth_runtime,
        "now",
        lambda: NOW + timedelta(hours=24),
    )
    listed = client.get("/v1/reports", headers=headers)
    fetched = client.get(f"/v1/reports/{result['report_id']}", headers=headers)

    assert listed.status_code == 200 and listed.json() == {"reports": []}
    assert fetched.status_code == 404
    with factory() as session:
        row = session.get(FileReport, result["report_id"])
        assert row is not None


def test_download_token_expires_at_ten_minutes(api_factory):
    _, _, app, _, _, _, _ = api_factory()
    client, headers = login_client(app, "owner@example.test")
    result = create_report(client, headers)
    issued = client.post(f"/v1/reports/{result['report_id']}/download-token", headers=headers)
    token = issued.json()["token"]

    object.__setattr__(
        app.state.auth_runtime,
        "now",
        lambda: NOW + timedelta(minutes=10),
    )
    expired = client.post("/v1/downloads", json={"token": token}, headers=headers)

    assert expired.status_code == 404


def test_cleaned_copy_expires_after_ten_minutes_while_report_remains(api_factory):
    _, factory, app, store, _, owner_id, _ = api_factory()
    client, headers = login_client(app, "owner@example.test")
    result = create_report(client, headers)
    report_id = result["report_id"]

    after_ten_minutes = NOW + timedelta(minutes=10)
    assert store.get(report_id, owner_id, key=STORAGE_KEY, now=after_ten_minutes) is None
    object.__setattr__(app.state.auth_runtime, "now", lambda: after_ten_minutes)
    reports = client.get("/v1/reports", headers=headers)

    assert reports.status_code == 200
    assert [item["report_id"] for item in reports.json()["reports"]] == [report_id]
    with factory() as session:
        assert session.get(FileReport, report_id) is not None


def test_report_delete_store_failure_follows_database_commit(api_factory, monkeypatch):
    _, factory, app, store, _, owner_id, _ = api_factory()
    client, headers = login_client(app, "owner@example.test")
    result = create_report(client, headers)

    def fail_delete(*_args, **_kwargs):
        raise RuntimeError("synthetic store failure")

    monkeypatch.setattr(app.state.file_runtime.store, "delete", fail_delete)
    response = client.delete(f"/v1/reports/{result['report_id']}", headers=headers)

    assert response.status_code == 503
    with factory() as session:
        assert session.get(FileReport, result["report_id"]) is None
    assert (
        store.get(result["report_id"], owner_id, key=STORAGE_KEY, now=NOW)
        == b"synthetic-cleaned-copy"
    )


def test_report_delete_commit_failure_preserves_record_and_clean_copy(api_factory, monkeypatch):
    _, factory, app, store, _, owner_id, _ = api_factory()
    client, headers = login_client(app, "owner@example.test")
    result = create_report(client, headers)
    report_id = result["report_id"]
    database = app.state.file_runtime.database
    transaction = database.transaction

    @contextmanager
    def fail_commit():
        with transaction() as session:
            yield session
            raise RuntimeError("synthetic commit failure")

    monkeypatch.setattr(database, "transaction", fail_commit)

    response = client.delete(f"/v1/reports/{report_id}", headers=headers)

    assert response.status_code == 503
    with factory() as session:
        assert session.get(FileReport, report_id) is not None
    assert store.get(report_id, owner_id, key=STORAGE_KEY, now=NOW) == b"synthetic-cleaned-copy"
