from datetime import UTC, datetime
from hashlib import sha256
from threading import Event
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from metaguard_api import local_runtime, main, maintenance
from metaguard_api.account_credentials import hash_password
from metaguard_api.accounts import Account, EmailVerificationToken
from metaguard_api.database import Base, Database
from metaguard_api.system_security_events import SystemSecurityEvent

ORIGIN = "https://127.0.0.1:5173"
EMAIL = "login@example.test"
PASSWORD = "a synthetic local password"


@pytest.fixture
def environment(monkeypatch, tmp_path):
    monkeypatch.setenv("METAGUARD_ENVIRONMENT", "development")
    monkeypatch.setenv("METAGUARD_AUTH_ALLOWED_ORIGINS", f'["{ORIGIN}"]')
    monkeypatch.setenv("METAGUARD_DB_HOST", "127.0.0.1")
    monkeypatch.setenv("METAGUARD_DB_NAME", "metaguard_test")
    monkeypatch.setenv("METAGUARD_SECRET_DIR", str(tmp_path))
    monkeypatch.setenv("METAGUARD_DB_SECRET_DIR", str(tmp_path))
    for variable in (
        "PGHOSTADDR",
        "PGSERVICE",
        "METAGUARD_LOCAL_SMTP_PORT",
        "METAGUARD_LOCAL_PASSWORD_BLOCKLIST",
        "METAGUARD_LOCAL_PROCESSOR_SOCKET",
        "METAGUARD_LOCAL_PROCESSOR_UID",
        "METAGUARD_LOCAL_VIRUS_TOTAL_ENABLED",
    ):
        monkeypatch.delenv(variable, raising=False)
    (tmp_path / "jwt_signing_key").write_text("synthetic-jwt-key-only-for-tests-32-bytes")
    (tmp_path / "totp_encryption_key").write_bytes(b"k" * 32)
    return tmp_path


@pytest.fixture
def database(monkeypatch, environment):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    database = Database(engine)
    passed = []

    def create_local_db(settings, *, connect_timeout_seconds):
        assert settings.host == "127.0.0.1"
        assert settings.name == "metaguard_test"
        assert connect_timeout_seconds == 3
        passed.append(settings)
        return database

    monkeypatch.setattr(local_runtime, "create_database", create_local_db)
    monkeypatch.setattr(main, "create_database", reject_unvalidated_database)
    monkeypatch.setattr(maintenance, "create_database", reject_unvalidated_database)

    with database.transaction() as session:
        session.add(
            Account(
                id=str(uuid4()),
                email=EMAIL,
                password_hash=hash_password(PASSWORD),
                email_verified_at=datetime.now(UTC),
            )
        )
    yield database, passed
    engine.dispose()


def reject_unvalidated_database(*_args, **_kwargs):
    pytest.fail("Local runtime must not construct a different database")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("METAGUARD_ENVIRONMENT", "production"),
        ("METAGUARD_DB_HOST", "remote.example.test"),
        ("METAGUARD_DB_HOST", "localhost"),
        ("METAGUARD_DB_NAME", "metaguard"),
        ("METAGUARD_AUTH_ALLOWED_ORIGINS", '["http://127.0.0.1:5173"]'),
        ("METAGUARD_AUTH_ALLOWED_ORIGINS", '["https://frontend.example.test"]'),
        ("METAGUARD_AUTH_ALLOWED_ORIGINS", "invalid-json-value"),
        ("PGHOSTADDR", "203.0.113.2"),
        ("PGSERVICE", "other-destination"),
        ("METAGUARD_LOCAL_SMTP_PORT", "1025"),
        ("METAGUARD_LOCAL_PROCESSOR_UID", "1001"),
        ("METAGUARD_LOCAL_VIRUS_TOTAL_ENABLED", "true"),
    ],
)
def test_unsafe_configuration_refuses_before_secrets_or_db(monkeypatch, environment, name, value):
    monkeypatch.setenv(name, value)
    monkeypatch.setattr(local_runtime, "create_database", reject_unvalidated_database)
    monkeypatch.setattr(local_runtime.SecretStore, "read", reject_unvalidated_database)
    with pytest.raises(local_runtime.LocalConfigurationError) as error:
        local_runtime.create_local_app()
    assert value not in str(error.value)


def test_default_app_does_not_enable_authentication():
    assert TestClient(main.app).get("/v1/auth/status").status_code == 503


def _csrf(client):
    response = client.get("/v1/auth/status")
    assert response.status_code == 200
    if not response.json()["authenticated"]:
        assert "secure" in response.headers["set-cookie"].lower()
        assert "httponly" in response.headers["set-cookie"].lower()
    return {"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]}


def _local_client(app):
    return TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 12345))


def test_local_login_logout_and_readiness_use_one_injected_database(database, monkeypatch):
    db, passed = database
    close = db.close
    closes = []

    def count_close():
        closes.append(True)
        close()

    monkeypatch.setattr(db, "close", count_close)
    with _local_client(local_runtime.create_local_app()) as client:
        assert client.get("/health/ready").json() == {"status": "ok"}
        assert len(passed) == 1
        assert closes == []
        headers = _csrf(client)
        path = "/v1/auth/login"
        credentials = {"email": EMAIL, "password": PASSWORD}
        assert client.post(path, json=credentials).status_code == 403
        login = client.post(path, json=credentials, headers=headers)
        assert login.status_code == 200
        session_header = next(
            header
            for header in login.headers.get_list("set-cookie")
            if header.startswith("__Host-metaguard_session=")
        ).lower()
        assert "secure" in session_header and "httponly" in session_header
        assert "domain=" not in session_header
        cookie = client.cookies.get("__Host-metaguard_session")
        assert cookie and cookie not in login.text
        assert client.get("/v1/auth/status").json()["authenticated"] is True
        active_csrf = _csrf(client)
        assert client.post("/v1/auth/logout", headers=active_csrf).status_code == 200
        client.cookies.set("__Host-metaguard_session", cookie)
        assert client.get("/v1/auth/status").json()["authenticated"] is False
    assert closes == [True]


def test_registration_requires_explicit_capture_and_blocklist(database):
    with _local_client(local_runtime.create_local_app()) as client:
        response = client.post(
            "/v1/auth/register",
            json={"email": "new@example.test", "password": PASSWORD},
            headers=_csrf(client),
        )
    assert response.status_code == 503


def test_loopback_capture_verifies_registration_without_exposing_token(
    database, environment, monkeypatch
):
    db, _ = database
    blocklist = environment / "blocklist.txt"
    blocked = "a blocked local password"
    blocklist.write_text(blocked)
    monkeypatch.setenv("METAGUARD_LOCAL_PASSWORD_BLOCKLIST", str(blocklist))
    monkeypatch.setenv("METAGUARD_LOCAL_SMTP_PORT", "1025")
    mailbox = []

    class FakeSMTP:
        def __init__(self, host, port, *, local_hostname, timeout):
            assert (host, port, local_hostname, timeout) == (
                "127.0.0.1",
                1025,
                "[127.0.0.1]",
                3,
            )

        def __enter__(self):
            return self

        def __exit__(self, *error):
            return None

        def send_message(self, message):
            mailbox.append(message)
            return {}

    monkeypatch.setattr(local_runtime.smtplib, "SMTP", FakeSMTP)
    with _local_client(local_runtime.create_local_app()) as client:
        headers = _csrf(client)
        email = "new@example.test"
        response = client.post(
            "/v1/auth/register",
            json={"email": email, "password": blocked},
            headers=headers,
        )
        assert response.status_code == 400
        assert mailbox == []
        invalid_recipient = client.post(
            "/v1/auth/register",
            json={"email": "other@example.com", "password": PASSWORD},
            headers=headers,
        )
        assert invalid_recipient.status_code == 400
        assert mailbox == []
        response = client.post(
            "/v1/auth/register",
            json={"email": email, "password": PASSWORD},
            headers=headers,
        )
        assert response.status_code == 202
        assert len(mailbox) == 1 and mailbox[0]["To"] == email
        token = mailbox[0].get_content().splitlines()[-1]
        assert token not in response.text
        with db.transaction() as session:
            account = session.scalar(select(Account).where(Account.email == email))
            verification = session.scalar(
                select(EmailVerificationToken).where(
                    EmailVerificationToken.account_id == account.id
                )
            )
            assert verification.token_digest == sha256(token.encode("ascii")).hexdigest()
            assert session.scalar(select(SystemSecurityEvent)) is not None
        assert (
            client.post("/v1/auth/verify-email", json={"token": token}, headers=headers).status_code
            == 200
        )


def test_local_app_rejects_non_loopback_asgi_peers_even_with_spoofed_headers(database):
    app = local_runtime.create_local_app()
    with TestClient(app, base_url=ORIGIN, client=("203.0.113.2", 12345)) as client:
        response = client.get("/health/live", headers={"X-Forwarded-For": "127.0.0.1"})
    assert response.status_code == 403


def test_optional_processing_maintenance_uses_the_validated_db(database, environment, monkeypatch):
    db, _ = database
    ran = Event()
    answers = []
    monkeypatch.setenv("METAGUARD_LOCAL_PROCESSOR_SOCKET", "/run/metaguard-ipc/processor.sock")
    monkeypatch.setenv("METAGUARD_LOCAL_PROCESSOR_UID", "2001")
    monkeypatch.setattr(local_runtime, "_linux_uid", lambda: 2002)
    (environment / "data_encryption_key").write_bytes(b"d" * 32)

    async def one_cycle(purge, file_runtime):
        answers.append((file_runtime.database, purge()))
        ran.set()

    monkeypatch.setattr(main, "run_maintenance_loop", one_cycle)
    app = local_runtime.create_local_app()
    with _local_client(app):
        assert ran.wait(2)
    assert answers == [(db, 0)]
