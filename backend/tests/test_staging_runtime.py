from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from metaguard_api import database, main, staging_runtime
from metaguard_api.account_credentials import hash_password
from metaguard_api.accounts import Account
from metaguard_api.virustotal import VirusTotalStatus

ORIGIN = "https://staging.example.test"
FRONTEND = "10.2.0.10"
DB_HOST = "10.2.0.30"
EMAIL = "staging@example.test"
PASSWORD = "synthetic staging account password"


@pytest.fixture
def settings(monkeypatch, tmp_path):
    ca = tmp_path / "staging-ca.pem"
    ca.write_text("synthetic CA fixture", encoding="utf-8")
    env = {
        "METAGUARD_STAGING_SYNTHETIC_ONLY": "true",
        "METAGUARD_ENVIRONMENT": "production",
        "METAGUARD_AUTH_ALLOWED_ORIGINS": f'["{ORIGIN}"]',
        "METAGUARD_STAGING_ALLOWED_PEER": FRONTEND,
        "METAGUARD_STAGING_DB_TLS_CA": str(ca),
        "METAGUARD_STAGING_PROCESSOR_SOCKET": "/run/metaguard-ipc/processor.sock",
        "METAGUARD_STAGING_PROCESSOR_UID": "42001",
        "METAGUARD_SECRET_DIR": str(tmp_path),
        "METAGUARD_DB_SECRET_DIR": str(tmp_path),
        "METAGUARD_DB_HOST": DB_HOST,
        "METAGUARD_DB_NAME": "metaguard_staging",
        "METAGUARD_DB_USER": "metaguard_app",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    for key in ("PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", "PGOPTIONS"):
        monkeypatch.delenv(key, raising=False)
    for name, value in {
        "jwt_signing_key": b"staging-jwt-secret-test-fixture-32-bytes",
        "totp_encryption_key": b"a" * 32,
        "data_encryption_key": b"b" * 32,
        "postgres_password": b"synthetic password fixture",
    }.items():
        (tmp_path / name).write_bytes(value)
    monkeypatch.setattr(staging_runtime, "_linux_uid", lambda: 42000)
    return ca


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("METAGUARD_STAGING_SYNTHETIC_ONLY", None),
        ("METAGUARD_ENVIRONMENT", "development"),
        ("METAGUARD_AUTH_ALLOWED_ORIGINS", '["http://staging.example.test"]'),
        ("METAGUARD_AUTH_ALLOWED_ORIGINS", '["https://one.test","https://two.test"]'),
        ("METAGUARD_STAGING_ALLOWED_PEER", "10.2.0.0/24"),
        ("METAGUARD_STAGING_ALLOWED_PEER", "198.51.100.7"),
        ("METAGUARD_DB_HOST", "127.0.0.1"),
        ("METAGUARD_DB_HOST", "169.254.169.254"),
        ("METAGUARD_DB_HOST", "192.0.2.20"),
        ("METAGUARD_DB_HOST", "db.staging.test"),
        ("METAGUARD_DB_HOST", "10.2.0.31,10.2.0.32"),
        ("METAGUARD_DB_NAME", "metaguard"),
        ("METAGUARD_DB_USER", "postgres"),
        ("METAGUARD_STAGING_DB_TLS_CA", "relative.pem"),
        ("METAGUARD_STAGING_DB_TLS_CA", None),
        ("METAGUARD_STAGING_PROCESSOR_SOCKET", "processor.sock"),
        ("METAGUARD_STAGING_PROCESSOR_UID", "42000"),
        ("METAGUARD_STAGING_PROCESSOR_UID", "0"),
        ("PGHOSTADDR", "10.2.0.31"),
        ("PGSERVICE", "other-destination"),
        ("PGSERVICEFILE", "other-settings.conf"),
        ("PGOPTIONS", "-c search_path=unexpected"),
    ],
)
def test_refuses_configuration_before_reading_secrets(monkeypatch, settings, key, value):
    if value is None:
        monkeypatch.delenv(key)
    else:
        monkeypatch.setenv(key, value)
    read = Mock(side_effect=AssertionError("must not read secrets"))
    connect = Mock(side_effect=AssertionError("must not connect"))
    monkeypatch.setattr(staging_runtime.SecretStore, "read", read)
    monkeypatch.setattr(staging_runtime, "create_database", connect)

    with pytest.raises(staging_runtime.StagingConfigurationError) as error:
        staging_runtime.create_staging_app()

    assert error.value.__cause__ is None
    read.assert_not_called()
    connect.assert_not_called()


def test_refuses_missing_ca_and_non_linux_or_root(monkeypatch, settings):
    rejected = Mock(side_effect=AssertionError("must not read secrets"))
    monkeypatch.setattr(staging_runtime.SecretStore, "read", rejected)
    for uid in (None, 0):
        with monkeypatch.context() as patch:
            patch.setattr(staging_runtime, "_linux_uid", lambda uid=uid: uid)
            with pytest.raises(staging_runtime.StagingConfigurationError):
                staging_runtime.create_staging_app()
    settings.unlink()
    with pytest.raises(staging_runtime.StagingConfigurationError):
        staging_runtime.create_staging_app()
    rejected.assert_not_called()


def test_rejects_reused_encryption_key_before_connecting(monkeypatch, settings):
    (settings.parent / "data_encryption_key").write_bytes(b"a" * 32)
    connect = Mock(side_effect=AssertionError("must not connect"))
    monkeypatch.setattr(staging_runtime, "create_database", connect)
    with pytest.raises(staging_runtime.StagingConfigurationError):
        staging_runtime.create_staging_app()
    connect.assert_not_called()


def test_compose_auth_files_database_and_offline_providers(monkeypatch, settings):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    database.Base.metadata.create_all(engine)
    db = database.Database(engine)
    with db.transaction() as session:
        session.add(
            Account(
                id=str(uuid4()),
                email=EMAIL,
                password_hash=hash_password(PASSWORD),
                email_verified_at=datetime.now(UTC),
            )
        )
    compose = Mock(wraps=main.create_app)
    connect = Mock(return_value=db)
    close = Mock(wraps=db.close)
    monkeypatch.setattr(db, "close", close)
    monkeypatch.setattr(staging_runtime, "create_database", connect)
    monkeypatch.setattr(staging_runtime, "create_app", compose)
    monkeypatch.setattr(main, "VirusTotalClient", Mock(side_effect=AssertionError("external VT")))
    app = staging_runtime.create_staging_app()

    args, kwargs = connect.call_args
    assert (args[0].host, args[0].name, args[0].user) == (
        DB_HOST,
        "metaguard_staging",
        "metaguard_app",
    )
    assert kwargs == {"connect_timeout_seconds": 3, "tls_root_cert": settings.resolve()}
    assert app.state.file_runtime.database is db
    assert app.state.auth_runtime.email_sender is None
    assert app.state.auth_runtime.password_lookup is None
    assert compose.call_args.kwargs["security_alert_sender"] is None
    offline_vt = compose.call_args.kwargs["virus_total_client"]
    assert offline_vt.lookup("0" * 64, db, now=1).status is VirusTotalStatus.UNAVAILABLE

    with TestClient(app, base_url=ORIGIN, client=(FRONTEND, 4321)) as client:
        assert client.get("/health/ready").json() == {"status": "ok"}
        assert client.get("/openapi.json").status_code == 404
        status = client.get("/v1/auth/status")
        assert status.status_code == 200
        headers = {"Origin": ORIGIN, "X-CSRF-Token": status.json()["csrf_token"]}
        data = {"email": EMAIL, "password": PASSWORD}
        denied = client.post("/v1/auth/register", headers=headers, json=data)
        assert denied.status_code == 503
        login = client.post("/v1/auth/login", headers=headers, json=data)
        assert login.status_code == 200
        assert login.json()["authenticated"] is True
        close.assert_not_called()
    close.assert_called_once_with()


def test_forwarding_headers_do_not_override_peer(monkeypatch, settings):
    db = Mock(spec=database.Database)
    monkeypatch.setattr(staging_runtime, "create_database", lambda *args, **kwargs: db)
    app = staging_runtime.create_staging_app()
    spoof = {"X-Forwarded-For": FRONTEND}
    untrusted = TestClient(app, client=("10.2.0.99", 4321))
    assert untrusted.get("/health/live", headers=spoof).status_code == 403
    trusted = TestClient(app, client=(FRONTEND, 4321))
    assert trusted.get("/health/live", headers=spoof).status_code == 403
    assert trusted.get("/health/live", headers={"Forwarded": f"for={FRONTEND}"}).status_code == 403
    assert trusted.get("/health/live").status_code == 200


def test_disposes_database_after_composition_failure(monkeypatch, settings):
    db = Mock(spec=database.Database)
    monkeypatch.setattr(staging_runtime, "create_database", lambda *args, **kwargs: db)
    monkeypatch.setattr(staging_runtime, "create_app", Mock(side_effect=RuntimeError("private")))
    with pytest.raises(staging_runtime.StagingConfigurationError, match="^Staging API"):
        staging_runtime.create_staging_app()
    db.close.assert_called_once_with()


def test_tls_is_opt_in_at_database_connection_boundary(monkeypatch, settings):
    engine_factory = Mock()
    monkeypatch.setattr(database, "create_engine", engine_factory)
    db_settings = database.DatabaseSettings()

    database.create_database(db_settings, connect_timeout_seconds=3)
    assert engine_factory.call_args.kwargs["connect_args"] == {"connect_timeout": 3}

    database.create_database(db_settings, connect_timeout_seconds=3, tls_root_cert=settings)
    assert engine_factory.call_args.args[0].host == DB_HOST
    assert engine_factory.call_args.kwargs["connect_args"] == {
        "connect_timeout": 3,
        "sslmode": "verify-full",
        "sslrootcert": str(settings),
        "gssencmode": "disable",
    }
