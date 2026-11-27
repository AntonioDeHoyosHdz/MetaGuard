import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Event
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx2 import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from metaguard_api.account_credentials import hash_password
from metaguard_api.accounts import Account
from metaguard_api.auth_routes import AuthRuntime
from metaguard_api.database import Base, Database
from metaguard_api.file_routes import FileRuntime, _AnalysisPermit
from metaguard_api.file_storage import InMemoryTemporaryFileStore
from metaguard_api.main import create_app
from metaguard_api.processing_ipc_client import ProcessingClient
from metaguard_api.processing_types import ProcessedFile, ProcessingReport
from metaguard_api.reports import FileReport
from metaguard_api.settings import Settings
from metaguard_api.virustotal import VirusTotalResult, VirusTotalStatus

ORIGIN = "https://frontend.example"
SIGNING_KEY = "synthetic-jwt-signing-key-for-tests-only-32-bytes"
TOTP_KEY = b"t" * 32
STORAGE_KEY = b"s" * 32
NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
PASSWORD = "correct horse battery staple"


class FakeRateLimiter:
    def __init__(self, allowed=True):
        self.allowed = allowed
        self.calls = []

    def allow(self, action, client_ip, identity):
        self.calls.append((action, client_ip, identity))
        return self.allowed


class FakeProcessingClient(ProcessingClient):
    def __init__(self):
        self.calls = []
        self.fail = False

    def process(self, data, content_type):
        self.calls.append((data, content_type))
        if self.fail:
            raise RuntimeError("synthetic private processing details")
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


class FakeVirusTotalClient:
    def __init__(self, *, fail=False):
        self.calls = []
        self.fail = fail

    def lookup(self, digest, database, *, now):
        self.calls.append((digest, database, now))
        if self.fail:
            raise RuntimeError("private provider details")
        return VirusTotalResult(
            status=VirusTotalStatus.FOUND,
            last_analysis_stats={"malicious": 0, "undetected": 8},
            last_analysis_date=int(NOW.timestamp()),
            report_url=f"https://www.virustotal.com/gui/file/{digest}",
        )


@pytest.fixture
def api_factory(tmp_path):
    environments = []

    def build(
        *,
        max_upload_bytes=1024,
        max_store_bytes=4096,
        with_file_runtime=True,
        virus_total_client=None,
    ):
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        factory = sessionmaker(engine, expire_on_commit=False)
        account_id = str(uuid4())
        with factory.begin() as session:
            session.add(
                Account(
                    id=account_id,
                    email="user@example.test",
                    password_hash=hash_password(PASSWORD),
                    email_verified_at=NOW,
                )
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
            session_lifetime=timedelta(minutes=15),
            mfa_challenge_lifetime=timedelta(minutes=5),
            now=lambda: NOW,
        )
        store = InMemoryTemporaryFileStore(max_bytes=max_store_bytes)
        processor = FakeProcessingClient()
        file_runtime = (
            FileRuntime(
                store=store,
                storage_key=STORAGE_KEY,
                processing_client=processor,
                database=Database(engine),
            )
            if with_file_runtime
            else None
        )
        settings = Settings(
            environment="test",
            secret_dir=tmp_path / "secrets",
            auth_allowed_origins=(ORIGIN,),
            upload_max_bytes=max_upload_bytes,
        )
        app = create_app(
            settings,
            auth_runtime=auth_runtime,
            file_runtime=file_runtime,
            virus_total_client=virus_total_client,
        )
        environments.append((engine, factory, app, store, processor, limiter, account_id))
        return environments[-1]

    yield build
    for engine, *_ in environments:
        engine.dispose()


def login_client(app, *, email="user@example.test"):
    client = TestClient(app, base_url="https://api.example")
    preauth = client.get("/v1/auth/status")
    assert preauth.status_code == 200
    response = client.post(
        "/v1/auth/login",
        json={"email": email, "password": PASSWORD},
        headers={"Origin": ORIGIN, "X-CSRF-Token": preauth.json()["csrf_token"]},
    )
    assert response.status_code == 200
    return client, {"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]}


def advance_auth_clock(app, *, minutes):
    object.__setattr__(
        app.state.auth_runtime,
        "now",
        lambda: NOW + timedelta(minutes=minutes),
    )


def test_upload_route_fails_closed_when_runtime_is_not_configured(api_factory):
    _, _, app, _, _, _, _ = api_factory(with_file_runtime=False)
    client, headers = login_client(app)

    response = client.post(
        "/v1/uploads",
        content=b"synthetic upload",
        headers={**headers, "Content-Type": "image/png"},
    )

    assert response.status_code == 503


def test_upload_fails_closed_when_processor_is_not_the_api_ipc_client(api_factory):
    _, _, app, _, _, _, _ = api_factory()
    client, headers = login_client(app)
    app.state.file_runtime.processing_client = object()

    response = client.post(
        "/v1/uploads",
        content=b"synthetic upload",
        headers={**headers, "Content-Type": "image/png"},
    )

    assert response.status_code == 503


def test_upload_stores_raw_bytes_and_analysis_returns_only_minimized_report(api_factory):
    _, _, app, store, processor, limiter, account_id = api_factory()
    client, headers = login_client(app)
    original = b"synthetic bytes; API must not parse file content"

    uploaded = client.post(
        "/v1/uploads",
        content=original,
        headers={**headers, "Content-Type": "image/png"},
    )

    assert uploaded.status_code == 201
    assert set(uploaded.json()) == {"upload_id", "media_type"}
    upload_id = uploaded.json()["upload_id"]
    assert uploaded.json()["media_type"] == "image/png"
    assert store.get(upload_id, account_id, key=STORAGE_KEY, now=NOW) == original

    analysis = client.post(
        f"/v1/analyses/{upload_id}",
        json={"virus_total_consent": True},
        headers=headers,
    )

    assert analysis.status_code == 200
    assert set(analysis.json()) == {
        "report_id",
        "report",
        "created_at",
        "expires_at",
        "virus_total",
    }
    assert analysis.json()["virus_total"] == {
        "original": {
            "status": "key_unavailable",
            "sha256": sha256(original).hexdigest(),
            "last_analysis_stats": None,
            "last_analysis_date": None,
            "report_url": None,
        },
        "cleaned": {
            "status": "key_unavailable",
            "sha256": sha256(b"synthetic-cleaned-copy").hexdigest(),
            "last_analysis_stats": None,
            "last_analysis_date": None,
            "report_url": None,
        },
    }
    assert analysis.json()["report"] == {
        "media_type": "image/png",
        "metadata_categories": ["gps", "software"],
        "output_verified": True,
        "width": 12,
        "height": 8,
        "page_count": None,
        "active_content_removed": False,
        "uri_links_removed": 0,
    }
    assert analysis.json()["expires_at"] == "2026-11-19T12:00:00+00:00"
    assert b"synthetic-cleaned-copy" not in analysis.content
    assert processor.calls == [(original, "image/png")]
    assert [call[0] for call in limiter.calls if call[0].startswith("uploads_")] == [
        "uploads_per_minute_per_ip",
        "uploads_per_hour_per_account",
    ]


def test_analysis_only_queries_hashes_after_explicit_consent(api_factory):
    import json

    from metaguard_api.file_processing import ProcessedFile

    vt = FakeVirusTotalClient()
    _, _, app, _, processor, _, _ = api_factory(virus_total_client=vt)
    client, headers = login_client(app)
    original = b"synthetic original bytes"
    cleaned = b"synthetic-cleaned-copy"
    processor.process = lambda _data, content_type: ProcessedFile(
        cleaned_bytes=cleaned,
        media_type=content_type,
        report=ProcessingReport(
            media_type=content_type,
            metadata_categories=(),
            output_verified=True,
            width=12,
            height=8,
            active_content_removed=False,
            uri_links_removed=0,
        ),
    )
    upload = client.post(
        "/v1/uploads", content=original, headers={**headers, "Content-Type": "image/png"}
    )
    upload_id = upload.json()["upload_id"]

    denied = client.post(f"/v1/analyses/{upload_id}", json={}, headers=headers)
    assert denied.status_code == 200
    assert vt.calls == []
    assert denied.json()["virus_total"]["original"]["status"] == "not_requested"
    assert denied.json()["virus_total"]["cleaned"]["status"] == "not_requested"
    assert all("sha256" not in result for result in denied.json()["virus_total"].values())

    consented = client.post(
        f"/v1/analyses/{upload_id}",
        content=json.dumps({"virus_total_consent": True}),
        headers={**headers, "Content-Type": "application/json"},
    )
    assert consented.status_code == 200
    assert [call[0] for call in vt.calls] == [
        sha256(original).hexdigest(),
        sha256(cleaned).hexdigest(),
    ]
    assert all(call[1] is not None for call in vt.calls)
    assert consented.headers["Cache-Control"] == "no-store"
    result = consented.json()
    for label, content in (("original", original), ("cleaned", cleaned)):
        verdict = result["virus_total"][label]
        digest = sha256(content).hexdigest()
        assert verdict["status"] == "found"
        assert verdict["sha256"] == digest
        assert verdict["report_url"].endswith(digest)
    saved = client.get(f"/v1/reports/{result['report_id']}", headers=headers)
    assert saved.status_code == 200
    assert saved.json() == {key: value for key, value in result.items() if key != "virus_total"}


@pytest.mark.parametrize("provider_enabled", [True, False])
def test_unavailable_virustotal_returns_both_hashes(
    api_factory, monkeypatch, caplog, provider_enabled
):
    vt = FakeVirusTotalClient(fail=True) if provider_enabled else None
    if vt is None:
        monkeypatch.setattr("metaguard_api.main.VirusTotalClient", lambda *args, **kwargs: None)
    _, _, app, _, _, _, _ = api_factory(virus_total_client=vt)
    client, headers = login_client(app)
    upload = client.post(
        "/v1/uploads", content=b"synthetic", headers={**headers, "Content-Type": "image/png"}
    )

    response = client.post(
        f"/v1/analyses/{upload.json()['upload_id']}",
        json={"virus_total_consent": True},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    for label, content in (("original", b"synthetic"), ("cleaned", b"synthetic-cleaned-copy")):
        verdict = response.json()["virus_total"][label]
        assert verdict["status"] == "unavailable"
        assert verdict["sha256"] == sha256(content).hexdigest()
        assert verdict["report_url"] is None
    assert "private provider details" not in response.text
    assert "private provider details" not in caplog.text


def test_analysis_defaults_consent_to_false_and_rejects_unknown_fields(api_factory):
    _, _, app, _, processor, _, _ = api_factory()
    client, headers = login_client(app)
    uploaded = client.post(
        "/v1/uploads", content=b"synthetic", headers={**headers, "Content-Type": "image/png"}
    )

    default_consent = client.post(
        f"/v1/analyses/{uploaded.json()['upload_id']}", json={}, headers=headers
    )
    invalid_consent = client.post(
        f"/v1/analyses/{uploaded.json()['upload_id']}",
        json={"virus_total_consent": "yes", "unexpected": True},
        headers=headers,
    )

    assert default_consent.status_code == 200
    assert invalid_consent.status_code == 400
    assert len(processor.calls) == 1


def test_pdf_inventory_is_immediate_owner_only_and_not_persisted(api_factory):
    _, factory, app, _, processor, _, _ = api_factory()
    client, headers = login_client(app)
    preview = "https://example.invalid/document"
    processor.process = lambda _, media_type: ProcessedFile(
        b"synthetic-clean",
        media_type,
        ProcessingReport(media_type, (), True, page_count=1, uri_links_removed=2),
        removed_pdf_links=(preview,),
    )
    upload = client.post(
        "/v1/uploads",
        content=b"%PDF-synthetic",
        headers={**headers, "Content-Type": "application/pdf"},
    )
    path = f"/v1/analyses/{upload.json()['upload_id']}"
    analysis = client.post(path, json={}, headers=headers)

    assert analysis.status_code == 200
    assert analysis.headers["Cache-Control"] == "no-store"
    assert analysis.json()["removed_pdf_links"] == [preview]
    assert analysis.json()["report"]["uri_links_removed"] == 2
    report_id = analysis.json()["report_id"]
    history_entry = client.get(f"/v1/reports/{report_id}", headers=headers)
    history = client.get("/v1/reports", headers=headers)
    assert history_entry.status_code == history.status_code == 200
    assert preview not in history_entry.text
    assert preview not in history.text
    assert "removed_pdf_links" not in history_entry.json()
    with factory.begin() as session:
        assert preview not in session.get(FileReport, report_id).report_json
    unauthorized = TestClient(app, base_url="https://api.example")
    preauth = unauthorized.get("/v1/auth/status")
    denied = unauthorized.post(
        path,
        json={},
        headers={"Origin": ORIGIN, "X-CSRF-Token": preauth.json()["csrf_token"]},
    )
    assert denied.status_code == 401
    assert preview not in denied.text


def test_pdf_inventory_from_direct_processor_is_validated_before_persisting(api_factory, caplog):
    _, factory, app, _, processor, _, _ = api_factory()
    client, headers = login_client(app)
    raw = "https://example.invalid/document?value=synthetic"
    processor.process = lambda _, media_type: ProcessedFile(
        b"synthetic-clean",
        media_type,
        ProcessingReport(media_type, (), True, page_count=1, uri_links_removed=1),
        removed_pdf_links=(raw,),
    )
    upload = client.post(
        "/v1/uploads",
        content=b"%PDF-synthetic",
        headers={**headers, "Content-Type": "application/pdf"},
    )
    analysis = client.post(f"/v1/analyses/{upload.json()['upload_id']}", json={}, headers=headers)

    assert analysis.status_code == 503
    assert raw not in analysis.text
    assert raw not in caplog.text
    with factory.begin() as session:
        assert session.query(FileReport).all() == []


def test_upload_requires_exact_origin_csrf_and_an_authenticated_session(api_factory):
    _, _, app, _, _, _, _ = api_factory()
    anonymous = TestClient(app, base_url="https://api.example")
    preauth = anonymous.get("/v1/auth/status")
    no_session = anonymous.post(
        "/v1/uploads",
        content=b"synthetic",
        headers={
            "Origin": ORIGIN,
            "X-CSRF-Token": preauth.json()["csrf_token"],
            "Content-Type": "image/png",
        },
    )
    client, headers = login_client(app)
    bad_origin = client.post(
        "/v1/uploads",
        content=b"synthetic",
        headers={**headers, "Origin": "https://attacker.example", "Content-Type": "image/png"},
    )
    bad_csrf = client.post(
        "/v1/uploads",
        content=b"synthetic",
        headers={**headers, "X-CSRF-Token": "x" * 43, "Content-Type": "image/png"},
    )

    assert no_session.status_code == 401
    assert bad_origin.status_code == 403
    assert bad_csrf.status_code == 403


def test_upload_rejects_unsupported_media_and_empty_body(api_factory):
    _, _, app, store, _, _, _ = api_factory()
    client, headers = login_client(app)

    unsupported = client.post(
        "/v1/uploads",
        content=b"synthetic",
        headers={**headers, "Content-Type": "text/plain"},
    )
    empty = client.post(
        "/v1/uploads", content=b"", headers={**headers, "Content-Type": "image/jpeg"}
    )

    assert unsupported.status_code == 415
    assert empty.status_code == 400
    assert store.size_bytes == 0


def test_upload_enforces_configured_byte_limit_during_streaming(api_factory):
    _, _, app, store, _, _, _ = api_factory(max_upload_bytes=8)
    client, headers = login_client(app)

    response = client.post(
        "/v1/uploads",
        content=b"123456789",
        headers={**headers, "Content-Type": "application/pdf"},
    )

    assert response.status_code == 413
    assert store.size_bytes == 0


def test_upload_enforces_byte_limit_when_content_length_is_absent(api_factory):
    _, _, app, store, _, _, _ = api_factory(max_upload_bytes=8)
    client, headers = login_client(app)

    response = client.post(
        "/v1/uploads",
        content=iter((b"123456", b"789")),
        headers={**headers, "Content-Type": "application/pdf"},
    )

    assert response.status_code == 413
    assert store.size_bytes == 0


def test_analysis_is_owner_scoped_and_foreign_owner_cannot_trigger_processing(api_factory):
    reputation = FakeVirusTotalClient()
    _, factory, app, _, processor, _, owner_id = api_factory(virus_total_client=reputation)
    owner, owner_headers = login_client(app)
    uploaded = owner.post(
        "/v1/uploads", content=b"synthetic", headers={**owner_headers, "Content-Type": "image/png"}
    )
    other_id = str(uuid4())
    with factory.begin() as session:
        session.add(
            Account(
                id=other_id,
                email="other@example.test",
                password_hash=hash_password(PASSWORD),
                email_verified_at=NOW,
            )
        )
    other, other_headers = login_client(app, email="other@example.test")

    response = other.post(
        f"/v1/analyses/{uploaded.json()['upload_id']}",
        json={"virus_total_consent": True},
        headers=other_headers,
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"
    assert "virus_total" not in response.json()
    assert "removed_pdf_links" not in response.json()
    assert processor.calls == []
    assert reputation.calls == []
    assert owner_id != other_id


def test_expired_owner_analysis_returns_generic_404_and_deletes_owner_storage(api_factory):
    _, _, app, store, _, _, _ = api_factory(max_store_bytes=8)
    client, headers = login_client(app)
    original = b"expired!"
    uploaded = client.post(
        "/v1/uploads", content=original, headers={**headers, "Content-Type": "image/png"}
    )
    upload_id = uploaded.json()["upload_id"]
    assert store.size_bytes == len(original)
    advance_auth_clock(app, minutes=11)

    expired = client.post(f"/v1/analyses/{upload_id}", json={}, headers=headers)
    missing = client.post(f"/v1/analyses/{uuid4()}", json={}, headers=headers)

    assert expired.status_code == 404
    assert expired.json() == missing.json()
    assert store.size_bytes == 0
    assert upload_id not in app.state.file_runtime._uploads


def test_new_upload_purges_expired_storage_before_capacity_check(api_factory):
    _, _, app, store, _, _, owner_id = api_factory(max_store_bytes=8)
    client, headers = login_client(app)
    original = b"expired!"
    uploaded = client.post(
        "/v1/uploads", content=original, headers={**headers, "Content-Type": "image/png"}
    )
    expired_upload_id = uploaded.json()["upload_id"]
    advance_auth_clock(app, minutes=11)

    replacement = b"new-data"
    response = client.post(
        "/v1/uploads", content=replacement, headers={**headers, "Content-Type": "image/png"}
    )

    assert response.status_code == 201
    replacement_id = response.json()["upload_id"]
    now = NOW + timedelta(minutes=11)
    assert store.size_bytes == len(replacement)
    assert store.get(expired_upload_id, owner_id, key=STORAGE_KEY, now=now) is None
    assert expired_upload_id not in app.state.file_runtime._uploads
    assert store.get(replacement_id, owner_id, key=STORAGE_KEY, now=now) == replacement


def test_foreign_expired_probe_does_not_evict_owner_upload(api_factory):
    _, factory, app, store, _, _, owner_id = api_factory(max_store_bytes=8)
    owner, owner_headers = login_client(app)
    original = b"expired!"
    uploaded = owner.post(
        "/v1/uploads", content=original, headers={**owner_headers, "Content-Type": "image/png"}
    )
    upload_id = uploaded.json()["upload_id"]
    other_id = str(uuid4())
    with factory.begin() as session:
        session.add(
            Account(
                id=other_id,
                email="other@example.test",
                password_hash=hash_password(PASSWORD),
                email_verified_at=NOW,
            )
        )
    other, other_headers = login_client(app, email="other@example.test")
    advance_auth_clock(app, minutes=11)

    response = other.post(f"/v1/analyses/{upload_id}", json={}, headers=other_headers)

    assert response.status_code == 404
    assert response.json() == {"error": {"code": "not_found", "message": "Upload not found"}}
    assert store.size_bytes == len(original)
    assert app.state.file_runtime._uploads[upload_id].owner_id == owner_id


def test_upload_fails_closed_for_rate_limit_and_storage_capacity(api_factory):
    _, _, app, store, _, limiter, account_id = api_factory(max_store_bytes=4)
    client, headers = login_client(app)
    assert store.put("occupied", account_id, b"full", key=STORAGE_KEY, now=NOW)
    limiter.allowed = False

    limited = client.post(
        "/v1/uploads", content=b"x", headers={**headers, "Content-Type": "image/png"}
    )
    limiter.allowed = True
    unavailable = client.post(
        "/v1/uploads", content=b"x", headers={**headers, "Content-Type": "image/png"}
    )

    assert limited.status_code == 429
    assert unavailable.status_code == 503
    assert b"synthetic private" not in unavailable.content


def test_processing_failure_is_generic_and_does_not_expose_processor_details(api_factory):
    _, _, app, _, processor, _, _ = api_factory()
    client, headers = login_client(app)
    uploaded = client.post(
        "/v1/uploads", content=b"synthetic", headers={**headers, "Content-Type": "image/png"}
    )
    processor.fail = True

    response = client.post(f"/v1/analyses/{uploaded.json()['upload_id']}", json={}, headers=headers)

    assert response.status_code == 503
    assert "Retry-After" not in response.headers
    assert b"synthetic private processing details" not in response.content
    assert len(processor.calls) == 1

    processor.fail = False
    retry = client.post(f"/v1/analyses/{uploaded.json()['upload_id']}", json={}, headers=headers)
    assert retry.status_code == 200


def test_busy_analysis_rejects_without_reading_or_consuming_upload(api_factory, monkeypatch):
    reputation = FakeVirusTotalClient()
    _, factory, app, store, processor, _, _ = api_factory(virus_total_client=reputation)
    client, headers = login_client(app)
    upload_headers = {**headers, "Content-Type": "image/png"}
    first = client.post("/v1/uploads", content=b"first", headers=upload_headers)
    retryable = client.post("/v1/uploads", content=b"retryable", headers=upload_headers)
    first_id = first.json()["upload_id"]
    retryable_id = retryable.json()["upload_id"]
    first_path = f"/v1/analyses/{first_id}"
    retryable_path = f"/v1/analyses/{retryable_id}"
    reads = []
    started = Event()
    finish = Event()
    get = store.get
    process = processor.process

    def observe_read(file_id, *args, **kwargs):
        reads.append(file_id)
        return get(file_id, *args, **kwargs)

    def hold_first(data, content_type):
        if data == b"first":
            started.set()
            if not finish.wait(5):
                raise TimeoutError("Synthetic analysis did not resume")
        return process(data, content_type)

    monkeypatch.setattr(store, "get", observe_read)
    monkeypatch.setattr(processor, "process", hold_first)
    with ThreadPoolExecutor(max_workers=1) as pool:
        in_flight = pool.submit(client.post, first_path, json={}, headers=headers)
        try:
            assert started.wait(5)
            busy = client.post(retryable_path, json={"virus_total_consent": True}, headers=headers)
            assert busy.status_code == 503
            assert busy.headers["Retry-After"] == "1"
            assert busy.headers["Cache-Control"] == "no-store"
            assert busy.json()["error"]["code"] == "processing_busy"
            assert reads == [first_id]
            assert processor.calls == []
            assert reputation.calls == []
            assert store.size_bytes == len(b"firstretryable")
            with factory() as session:
                assert session.query(FileReport).count() == 0
        finally:
            finish.set()
        assert in_flight.result(timeout=5).status_code == 200

    retry = client.post(retryable_path, json={}, headers=headers)
    assert retry.status_code == 200
    assert reads == [first_id, retryable_id]
    assert processor.calls == [(b"first", "image/png"), (b"retryable", "image/png")]


def test_cancelled_analysis_keeps_slot_until_active_worker_really_exits(api_factory, monkeypatch):
    _, factory, app, _, processor, _, _ = api_factory()
    client, headers = login_client(app)
    upload_headers = {**headers, "Content-Type": "image/png"}
    first = client.post("/v1/uploads", content=b"first", headers=upload_headers)
    next_upload = client.post("/v1/uploads", content=b"next", headers=upload_headers)
    first_path = f"/v1/analyses/{first.json()['upload_id']}"
    next_path = f"/v1/analyses/{next_upload.json()['upload_id']}"

    async def exercise():
        loop = asyncio.get_running_loop()
        started = asyncio.Event()
        released = asyncio.Event()
        finish = Event()
        process = processor.process
        run_stage = _AnalysisPermit.run

        def hold_first(data, content_type):
            if data == b"first":
                loop.call_soon_threadsafe(started.set)
                if not finish.wait(5):
                    raise TimeoutError("Synthetic analysis did not resume")
            return process(data, content_type)

        def observe_exit(self, stage, *args, **kwargs):
            try:
                return run_stage(self, stage, *args, **kwargs)
            finally:
                if stage is hold_first and args[0] == b"first":
                    loop.call_soon_threadsafe(released.set)

        monkeypatch.setattr(processor, "process", hold_first)
        monkeypatch.setattr(_AnalysisPermit, "run", observe_exit)
        # Exercise direct asyncio cancellation at the routed request, not an AnyIO scope.
        routed_app = FastAPI()
        routed_app.router = app.router
        async with AsyncClient(
            transport=ASGITransport(app=routed_app),
            base_url="https://api.example",
            cookies=client.cookies,
        ) as async_client:
            task = asyncio.create_task(async_client.post(first_path, json={}, headers=headers))
            try:
                await asyncio.wait_for(started.wait(), timeout=5)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=5)
                busy = await async_client.post(next_path, json={}, headers=headers)
                assert busy.status_code == 503
                assert busy.json()["error"]["code"] == "processing_busy"
            finally:
                finish.set()
                if started.is_set():
                    await asyncio.wait_for(released.wait(), timeout=5)
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            retry = await async_client.post(next_path, json={}, headers=headers)
            assert retry.status_code == 200

    asyncio.run(exercise())
    with factory() as session:
        assert session.query(FileReport).count() == 1


def test_report_persistence_failure_removes_the_new_cleaned_copy(api_factory, monkeypatch):
    _, factory, app, store, _, _, _ = api_factory()
    client, headers = login_client(app)
    original = b"synthetic upload bytes"
    uploaded = client.post(
        "/v1/uploads", content=original, headers={**headers, "Content-Type": "image/png"}
    )

    def fail_transaction():
        raise RuntimeError("synthetic database failure")

    monkeypatch.setattr(app.state.file_runtime.database, "transaction", fail_transaction)
    analysis = client.post(f"/v1/analyses/{uploaded.json()['upload_id']}", json={}, headers=headers)

    assert analysis.status_code == 503
    assert store.size_bytes == len(original)
    with factory() as session:
        assert session.query(FileReport).count() == 0
