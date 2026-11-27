import re
from contextlib import contextmanager
from hashlib import sha256
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from metaguard_api import database, registration_trial
from metaguard_api.accounts import Account, EmailVerificationToken

ORIGIN = "https://registration.example.test"
EMAIL = "candidate@school.example.test"
PASSWORD = "a completely synthetic passphrase"


@pytest.fixture
def trial(monkeypatch, tmp_path):
    ca = tmp_path / "db-ca.pem"
    ca.write_text("synthetic CA fixture", encoding="utf-8")
    blocklist = tmp_path / "blocklist.txt"
    blocklist.write_text("common synthetic password\n", encoding="utf-8")
    mail = tmp_path / "credentials"
    mail.mkdir()
    (mail / "gmail_app_password").write_bytes(b"abcdefghijklmnop")
    (tmp_path / "jwt_signing_key").write_bytes(b"a" * 36)
    (tmp_path / "totp_encryption_key").write_bytes(b"b" * 32)
    env = {
        "METAGUARD_REGISTRATION_PRIVATE_TRIAL": "true",
        "METAGUARD_REGISTRATION_DB_TLS_CA": str(ca),
        "METAGUARD_REGISTRATION_PASSWORD_BLOCKLIST": str(blocklist),
        "METAGUARD_REGISTRATION_GMAIL_SENDER": "synthetic@gmail.com",
        "METAGUARD_ENVIRONMENT": "production",
        "METAGUARD_AUTH_ALLOWED_ORIGINS": f'["{ORIGIN}"]',
        "METAGUARD_SECRET_DIR": str(tmp_path),
        "METAGUARD_DB_SECRET_DIR": str(tmp_path),
        "METAGUARD_DB_HOST": "10.2.0.30",
        "METAGUARD_DB_NAME": "metaguard_registration_trial",
        "METAGUARD_DB_USER": "metaguard_registration_app",
        "CREDENTIALS_DIRECTORY": str(mail),
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    for key in ("PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", "PGOPTIONS"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(registration_trial, "_linux_uid", lambda: 42000)
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    database.Base.metadata.create_all(engine)
    db = database.Database(engine)
    connect = Mock(return_value=db)
    smtp = Mock()
    session = Mock()
    session.send_message.return_value = {}
    smtp.return_value.__enter__ = Mock(return_value=session)
    smtp.return_value.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(registration_trial, "create_database", connect)
    monkeypatch.setattr("metaguard_api.gmail_sender.smtplib.SMTP_SSL", smtp)
    try:
        yield db, connect, session
    finally:
        db.close()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("METAGUARD_REGISTRATION_PRIVATE_TRIAL", "false"),
        ("METAGUARD_DB_NAME", "metaguard_staging"),
        ("METAGUARD_DB_HOST", "203.0.113.4"),
        ("METAGUARD_DB_USER", "postgres"),
        ("METAGUARD_AUTH_ALLOWED_ORIGINS", '["http://registration.example.test"]'),
        ("CREDENTIALS_DIRECTORY", "relative"),
        ("PGHOSTADDR", "203.0.113.4"),
    ],
)
def test_rejects_unsafe_config_before_opening_secrets_or_db(trial, monkeypatch, key, value):
    _, connect, smtp = trial
    monkeypatch.setenv(key, value)
    read = Mock(side_effect=AssertionError("unexpected secret read"))
    monkeypatch.setattr(registration_trial.SecretStore, "read", read)

    with pytest.raises(registration_trial.RegistrationTrialError) as error:
        registration_trial.create_registration_trial_app()

    assert error.value.__cause__ is None and value not in str(error.value)
    read.assert_not_called()
    connect.assert_not_called()
    smtp.send_message.assert_not_called()


def test_trial_guards_peer_and_mail_scope(trial):
    _, connect, smtp = trial
    app = registration_trial.create_registration_trial_app()
    assert connect.call_args.kwargs["tls_root_cert"].name == "db-ca.pem"

    with TestClient(app, base_url=ORIGIN, client=("10.2.0.10", 5555)) as other:
        assert other.get("/v1/auth/status").status_code == 403

    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 5555)) as client:
        assert (
            client.get("/v1/auth/status", headers={"X-Forwarded-For": "127.0.0.1"}).status_code
            == 403
        )
        for method, path in (
            ("GET", "/docs"),
            ("GET", "/v1/auth/password-reset/request"),
            ("GET", "/v1/auth/password-reset/confirm"),
            ("POST", "/v1/auth/login/email"),
            ("POST", "/v1/auth/login/mfa"),
            ("GET", "/v1/auth/register"),
            ("POST", "/v1/files"),
        ):
            response = client.request(method, path)
            assert response.status_code == 404
            assert response.headers["cache-control"] == "no-store"
        data = {"email": EMAIL, "password": PASSWORD}
        assert client.post("/v1/auth/register", json=data).status_code == 403
    smtp.send_message.assert_not_called()


def test_register_resend_verify_login_without_outside_smtp(trial):
    db, _, smtp = trial
    app = registration_trial.create_registration_trial_app()
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 5555)) as client:
        token = client.get("/v1/auth/status").json()["csrf_token"]
        headers = {"Origin": ORIGIN, "X-CSRF-Token": token}
        data = {"email": EMAIL, "password": PASSWORD}
        registered = client.post("/v1/auth/register", headers=headers, json=data)
        assert registered.status_code == 202
        assert client.post("/v1/auth/login", headers=headers, json=data).status_code == 401
        resent = client.post("/v1/auth/resend-verification", headers=headers, json=data)
        assert resent.status_code == 202
        assert smtp.send_message.call_count == 2
        tokens = []
        for call in smtp.send_message.call_args_list:
            message = call.args[0]
            assert str(message["To"]) == EMAIL
            code = re.search(r"(?m)^[A-Za-z0-9_-]{43}$", message.get_body(("plain",)).get_content())
            assert code and code.group() not in registered.text + resent.text
            tokens.append(code.group())
        verify = "/v1/auth/verify-email"
        assert client.post(verify, headers=headers, json={"token": tokens[0]}).status_code == 400
        assert client.post(verify, headers=headers, json={"token": tokens[1]}).status_code == 200
        assert client.post(verify, headers=headers, json={"token": tokens[1]}).status_code == 400
        login = client.post("/v1/auth/login", headers=headers, json=data)
        assert login.status_code == 200 and login.json()["authenticated"]
        logout = client.post(
            "/v1/auth/logout",
            headers={"Origin": ORIGIN, "X-CSRF-Token": login.json()["csrf_token"]},
        )
        assert logout.status_code == 200
        assert client.get("/v1/auth/status").json()["authenticated"] is False
        with db.transaction() as connection:
            assert connection.scalar(select(Account)).email_verified_at is not None
    assert smtp.send_message.call_count == 2


def test_private_trial_recovers_password_for_verified_non_gmail_recipient(trial, monkeypatch):
    _, _, smtp = trial
    peer = "10.2.0.10"
    monkeypatch.setenv("METAGUARD_REGISTRATION_INGRESS_ENABLED", "true")
    monkeypatch.setenv("METAGUARD_REGISTRATION_INGRESS_PEER", peer)
    app = registration_trial.create_registration_ingress_app()
    reset_request = "/v1/auth/password-reset/request"
    reset_confirm = "/v1/auth/password-reset/confirm"
    new_password = "a different synthetic passphrase"

    with (
        TestClient(app, base_url=ORIGIN, client=(peer, 5555)) as client,
        TestClient(app, base_url=ORIGIN, client=("10.2.0.11", 5555)) as other,
    ):
        assert other.post(reset_request).status_code == 403
        assert other.post(reset_confirm).status_code == 403

        def csrf_headers():
            return {
                "Origin": ORIGIN,
                "X-CSRF-Token": client.get("/v1/auth/status").json()["csrf_token"],
            }

        login_path = "/v1/auth/login"
        data = {"email": EMAIL, "password": PASSWORD}
        assert (
            client.post("/v1/auth/register", headers=csrf_headers(), json=data).status_code == 202
        )
        verify_message = smtp.send_message.call_args.args[0]
        verify_code = re.search(
            r"(?m)^[A-Za-z0-9_-]{43}$", verify_message.get_body(("plain",)).get_content()
        )
        assert verify_code is not None
        verified = client.post(
            "/v1/auth/verify-email", headers=csrf_headers(), json={"token": verify_code.group()}
        )
        assert verified.status_code == 200
        login = client.post(login_path, headers=csrf_headers(), json=data)
        assert login.status_code == 200 and login.json()["authenticated"]

        assert client.post(reset_request, json={"email": EMAIL}).status_code == 403
        assert client.post(reset_confirm, json={}).status_code == 403
        assert smtp.send_message.call_count == 1
        requested = client.post(reset_request, headers=csrf_headers(), json={"email": EMAIL})
        assert (requested.status_code, requested.json()) == (202, {"requested": True})
        assert requested.headers["cache-control"] == "no-store"
        assert smtp.send_message.call_count == 2
        sent = smtp.send_message.call_args
        reset_message = sent.args[0]
        assert str(reset_message["To"]) == EMAIL
        assert str(reset_message["From"]) == str(verify_message["From"])
        assert sent.kwargs == {"from_addr": str(verify_message["From"]), "to_addrs": [EMAIL]}
        reset_code = re.search(r"(?m)^[a-f0-9]{32}$", reset_message.get_content())
        assert reset_code is not None and reset_code.group() not in requested.text

        payload = {"email": EMAIL, "code": reset_code.group(), "new_password": new_password}
        changed = client.post(reset_confirm, headers=csrf_headers(), json=payload)
        assert (changed.status_code, changed.json()) == (200, {"changed": True})
        assert client.get("/v1/auth/status").json()["authenticated"] is False
        reused = client.post(reset_confirm, headers=csrf_headers(), json=payload)
        assert reused.status_code == 401
        assert reused.json()["error"]["code"] == "invalid_reset"
        assert client.post(login_path, headers=csrf_headers(), json=data).status_code == 401
        data["password"] = new_password
        recovered = client.post(login_path, headers=csrf_headers(), json=data)
        assert recovered.status_code == 200 and recovered.json()["authenticated"]


def test_mail_runs_after_commit_and_never_runs_after_rollback(trial, monkeypatch):
    db, _, smtp = trial
    events = []
    fail_commit = True

    @contextmanager
    def tracked_begin():
        with db.transaction() as session:
            yield session
            if fail_commit:
                events.append("rolled back")
                raise RuntimeError("synthetic commit failure")
        events.append("committed")

    class TrackedTransactions:
        def __init__(self, _database):
            pass

        def begin(self):
            return tracked_begin()

    monkeypatch.setattr(registration_trial, "_Transactions", TrackedTransactions)
    smtp.send_message.side_effect = lambda *_args, **_kwargs: events.append("smtp") or {}
    app = registration_trial.create_registration_trial_app()
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 5555)) as client:
        headers = {
            "Origin": ORIGIN,
            "X-CSRF-Token": client.get("/v1/auth/status").json()["csrf_token"],
        }
        data = {"email": EMAIL, "password": PASSWORD}
        register = "/v1/auth/register"
        resend = "/v1/auth/resend-verification"

        assert client.post(register, headers=headers, json=data).status_code == 503
        assert events == ["rolled back"]
        smtp.send_message.assert_not_called()
        with db.transaction() as session:
            assert session.scalar(select(Account)) is None
            assert session.scalar(select(EmailVerificationToken)) is None

        fail_commit = False
        assert client.post(register, headers=headers, json=data).status_code == 202
        assert events[-2:] == ["committed", "smtp"]
        message = smtp.send_message.call_args.args[0]
        old_code = re.search(r"(?m)^[A-Za-z0-9_-]{43}$", message.get_body(("plain",)).get_content())
        assert old_code is not None
        old_digest = sha256(old_code.group().encode("ascii")).hexdigest()

        fail_commit = True
        assert client.post(resend, headers=headers, json=data).status_code == 202
        assert events[-1] == "rolled back"
        assert smtp.send_message.call_count == 1
        with db.transaction() as session:
            assert session.scalar(select(EmailVerificationToken)).token_digest == old_digest


def test_mail_outage_keeps_committed_registration_eligible_for_resend(trial):
    db, _, smtp = trial
    app = registration_trial.create_registration_trial_app()
    smtp.send_message.side_effect = RuntimeError("synthetic delivery error")
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 5555)) as client:
        headers = {
            "Origin": ORIGIN,
            "X-CSRF-Token": client.get("/v1/auth/status").json()["csrf_token"],
        }
        data = {"email": EMAIL, "password": PASSWORD}
        registered = client.post("/v1/auth/register", headers=headers, json=data)
        assert (registered.status_code, registered.json()) == (202, {"registered": True})
        with db.transaction() as session:
            assert session.scalar(select(Account)).email_verified_at is None
            assert session.scalar(select(EmailVerificationToken)) is not None
        smtp.send_message.side_effect = None
        resent = client.post("/v1/auth/resend-verification", headers=headers, json=data)
        assert (resent.status_code, resent.json()) == (202, {"requested": True})
        assert smtp.send_message.call_count == 2


@pytest.mark.parametrize("enabled,peer", [("false", "10.2.0.10"), ("true", "203.0.113.9")])
def test_private_ingress_requires_opt_in_and_private_peer(trial, monkeypatch, enabled, peer):
    _, connect, smtp = trial
    monkeypatch.setenv("METAGUARD_REGISTRATION_INGRESS_ENABLED", enabled)
    monkeypatch.setenv("METAGUARD_REGISTRATION_INGRESS_PEER", peer)
    read = Mock(side_effect=AssertionError("must not read secrets"))
    monkeypatch.setattr(registration_trial.SecretStore, "read", read)
    with pytest.raises(registration_trial.RegistrationTrialError):
        registration_trial.create_registration_ingress_app()
    read.assert_not_called()
    connect.assert_not_called()
    smtp.send_message.assert_not_called()


def test_private_ingress_requires_pinned_peer_and_https_origin(trial, monkeypatch):
    _, _, smtp = trial
    frontend = "10.2.0.10"
    monkeypatch.setenv("METAGUARD_REGISTRATION_INGRESS_ENABLED", "true")
    monkeypatch.setenv("METAGUARD_REGISTRATION_INGRESS_PEER", frontend)
    app = registration_trial.create_registration_ingress_app()
    status = "/v1/auth/status"
    with TestClient(app, base_url=ORIGIN, client=(frontend, 5555)) as client:
        assert client.get(status).status_code == 200
        assert client.get(status, headers={"Host": "different.example.test"}).status_code == 403
        assert client.get(status, headers={"X-Forwarded-For": frontend}).status_code == 403
        assert client.get(ORIGIN.replace("https:", "http:") + status).status_code == 403
        assert client.get("/health/ready").status_code == 404
        assert (
            client.post(
                "/v1/auth/register", json={"email": EMAIL, "password": PASSWORD}
            ).status_code
            == 403
        )
    outsider = TestClient(app, base_url=ORIGIN, client=("10.2.0.99", 5555))
    assert outsider.get(status).status_code == 403
    smtp.send_message.assert_not_called()
