from datetime import UTC, datetime, timedelta
from hashlib import sha256
from json import dumps
from uuid import uuid4

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from metaguard_api.account_credentials import hash_password, verify_password
from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account, AccountSession, EmailVerificationToken
from metaguard_api.database import Base
from metaguard_api.main import create_app
from metaguard_api.settings import Settings
from metaguard_api.totp_secrets import encrypt_totp_secret

ORIGIN = "https://frontend.example"
SIGNING_KEY = "synthetic-jwt-signing-key-for-tests-only-32-bytes"
TOTP_KEY = b"t" * 32
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


class FakeRateLimiter:
    def __init__(self, allowed=True):
        self.allowed = allowed
        self.calls = []

    def allow(self, action, client_ip, identity):
        self.calls.append((action, client_ip, identity))
        return self.allowed


@pytest.fixture
def auth_env():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    account_id = str(uuid4())
    email = "user@example.test"
    password = "correct horse battery staple"
    totp_secret = pyotp.random_base32()
    with factory.begin() as session:
        session.add(
            Account(
                id=account_id,
                email=email,
                password_hash=hash_password(password),
                email_verified_at=NOW,
            )
        )
    return {
        "engine": engine,
        "factory": factory,
        "account_id": account_id,
        "email": email,
        "password": password,
        "totp_secret": totp_secret,
        "clock": [NOW],
    }


def make_runtime(auth_env, *, rate_limiter=None, with_mfa=False):
    if rate_limiter is None:
        rate_limiter = FakeRateLimiter()
    if with_mfa:
        with auth_env["factory"].begin() as session:
            session.add(
                AccountTotp(
                    account_id=auth_env["account_id"],
                    encrypted_secret=encrypt_totp_secret(
                        TOTP_KEY, auth_env["account_id"], auth_env["totp_secret"]
                    ),
                    key_version=1,
                )
            )
    return {
        "session_factory": auth_env["factory"],
        "rate_limiter": rate_limiter,
        "signing_key": SIGNING_KEY,
        "issuer": "https://api.example",
        "audience": "metaguard-api",
        "dummy_password_hash": hash_password("constant dummy password"),
        "totp_encryption_key": TOTP_KEY,
        "totp_key_version": 1,
        "session_lifetime": timedelta(minutes=15),
        "mfa_challenge_lifetime": timedelta(minutes=5),
        "now": lambda: auth_env["clock"][0],
    }


def make_client(auth_env, *, rate_limiter=None, with_mfa=False, settings=None):
    from metaguard_api.auth_routes import AuthRuntime

    runtime = AuthRuntime(**make_runtime(auth_env, rate_limiter=rate_limiter, with_mfa=with_mfa))
    app = create_app(
        settings or Settings(environment="test", auth_allowed_origins=(ORIGIN,)),
        auth_runtime=runtime,
    )
    return TestClient(app, base_url="https://api.example"), runtime


def preauth(client):
    response = client.get("/v1/auth/status")
    assert response.status_code == 200
    assert response.json()["authenticated"] is False
    return response.json()["csrf_token"]


def test_auth_status_fails_closed_when_runtime_dependencies_are_missing():
    client = TestClient(create_app(Settings(environment="test")))

    response = client.get("/v1/auth/status")

    assert response.status_code == 503


def test_auth_status_issues_host_only_secure_csrf_cookie(auth_env):
    client, runtime = make_client(auth_env)

    response = client.get("/v1/auth/status")

    assert response.status_code == 200
    assert response.json() == {
        "authenticated": False,
        "csrf_token": client.cookies.get("__Host-metaguard_csrf"),
    }
    assert response.headers["cache-control"] == "no-store"
    cookie = next(
        value
        for value in response.headers.get_list("set-cookie")
        if "__Host-metaguard_csrf=" in value
    )
    assert "httponly" in cookie.lower()
    assert "secure" in cookie.lower()
    assert "path=/" in cookie.lower()
    assert "samesite=lax" in cookie.lower()
    assert "domain=" not in cookie.lower()
    assert SIGNING_KEY not in repr(runtime)
    assert TOTP_KEY.decode("ascii") not in repr(runtime)


def test_password_login_status_and_logout_revoke_session_immediately(auth_env):
    client, _ = make_client(auth_env)
    csrf = preauth(client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}

    response = client.post(
        "/v1/auth/login",
        json={"email": auth_env["email"], "password": auth_env["password"]},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["authenticated"] is True
    assert response.json()["csrf_token"] == client.cookies.get("__Host-metaguard_csrf")
    assert "session_token" not in response.json()
    session_cookie = next(
        value
        for value in response.headers.get_list("set-cookie")
        if "__Host-metaguard_session=" in value
    )
    assert "httponly" in session_cookie.lower()
    assert "secure" in session_cookie.lower()
    assert "domain=" not in session_cookie.lower()

    status = client.get("/v1/auth/status")
    assert status.json() == {"authenticated": True, "csrf_token": response.json()["csrf_token"]}
    assert status.headers["cache-control"] == "no-store"

    logout = client.post(
        "/v1/auth/logout", headers={"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]}
    )
    assert logout.status_code == 200
    with auth_env["factory"]() as session:
        stored = session.scalar(select(AccountSession))
        assert stored.revoked_at is not None
    assert client.get("/v1/auth/status").json()["authenticated"] is False


def test_login_requires_exact_origin_and_matching_csrf(auth_env):
    client, runtime = make_client(auth_env)
    limiter = runtime.rate_limiter
    csrf = preauth(client)
    payload = {"email": auth_env["email"], "password": auth_env["password"]}

    wrong_origin = client.post(
        "/v1/auth/login",
        json=payload,
        headers={"Origin": f"{ORIGIN}/", "X-CSRF-Token": csrf},
    )
    assert wrong_origin.status_code == 403
    assert len(limiter.calls) == 1
    assert limiter.calls[0][0] == "auth_status"

    wrong_csrf = client.post(
        "/v1/auth/login",
        json=payload,
        headers={"Origin": ORIGIN, "X-CSRF-Token": "x" * 43},
    )
    assert wrong_csrf.status_code == 403


def test_login_fails_closed_without_limiter_and_rate_limits_denials(auth_env):
    from metaguard_api.auth_routes import AuthRuntime

    # A missing limiter is represented explicitly because an absent runtime is also fail-closed.
    runtime = AuthRuntime(**{**make_runtime(auth_env), "rate_limiter": None})
    client = TestClient(
        create_app(
            Settings(environment="test", auth_allowed_origins=(ORIGIN,)), auth_runtime=runtime
        ),
        base_url="https://api.example",
    )
    assert client.get("/v1/auth/status").status_code == 503
    client.cookies.set("__Host-metaguard_csrf", "c" * 43)
    csrf_headers = {"Origin": ORIGIN, "X-CSRF-Token": "c" * 43}
    assert (
        client.post(
            "/v1/auth/login",
            json={"email": auth_env["email"], "password": auth_env["password"]},
            headers=csrf_headers,
        ).status_code
        == 503
    )
    assert (
        client.post(
            "/v1/auth/login/mfa",
            json={"email": auth_env["email"], "password": auth_env["password"], "code": "000000"},
            headers=csrf_headers,
        ).status_code
        == 503
    )
    assert client.post("/v1/auth/logout", headers=csrf_headers).status_code == 503

    blocked_client, _ = make_client(auth_env, rate_limiter=FakeRateLimiter(allowed=False))
    assert blocked_client.get("/v1/auth/status").status_code == 429


def test_login_rejects_invalid_credentials_generically(auth_env):
    client, runtime = make_client(auth_env)
    csrf = preauth(client)

    response = client.post(
        "/v1/auth/login",
        json={"email": auth_env["email"], "password": "wrong password"},
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )

    assert response.status_code == 401
    assert response.json() == {"error": {"code": "unauthorized", "message": "Invalid credentials"}}
    assert "__Host-metaguard_session" not in client.cookies

    for email in (auth_env["email"].upper(), auth_env["email"]):
        client.post(
            "/v1/auth/login",
            json={"email": email, "password": "wrong password"},
            headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        )
    assert runtime.rate_limiter.calls[-2][2] == runtime.rate_limiter.calls[-1][2]


def test_login_rejects_unverified_account_with_generic_denial(auth_env):
    unverified_email = "unverified@example.test"
    with auth_env["factory"].begin() as session:
        session.add(
            Account(
                id=str(uuid4()),
                email=unverified_email,
                password_hash=hash_password(auth_env["password"]),
                email_verified_at=None,
            )
        )

    client, _ = make_client(auth_env)
    csrf = preauth(client)

    # Correct password on unverified account must be rejected generically
    response = client.post(
        "/v1/auth/login",
        json={"email": unverified_email, "password": auth_env["password"]},
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )
    assert response.status_code == 401
    assert response.json() == {"error": {"code": "unauthorized", "message": "Invalid credentials"}}
    assert "__Host-metaguard_session" not in client.cookies

    # Wrong password on unverified account must also be rejected generically
    bad_pw_response = client.post(
        "/v1/auth/login",
        json={"email": unverified_email, "password": "wrong password"},
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )
    assert bad_pw_response.status_code == 401
    assert bad_pw_response.json() == {
        "error": {"code": "unauthorized", "message": "Invalid credentials"}
    }
    assert "__Host-metaguard_session" not in client.cookies


def test_auth_validation_errors_do_not_echo_credentials_or_codes(auth_env):
    client, _ = make_client(auth_env)
    csrf = preauth(client)
    oversized_password = "p" * 1025

    response = client.post(
        "/v1/auth/login",
        json={"email": auth_env["email"], "password": oversized_password},
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )

    assert response.status_code == 400
    assert response.json() == {"error": {"code": "invalid_request", "message": "Invalid request"}}
    assert oversized_password not in response.text


def test_mfa_login_requires_password_challenge_and_current_totp(auth_env):
    client, _ = make_client(auth_env, with_mfa=True)
    csrf = preauth(client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    response = client.post(
        "/v1/auth/login",
        json={"email": auth_env["email"], "password": auth_env["password"]},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["mfa_required"] is True
    assert "__Host-metaguard_mfa=" in "".join(response.headers.get_list("set-cookie"))
    assert "__Host-metaguard_session" not in client.cookies
    now_step_code = pyotp.TOTP(auth_env["totp_secret"]).at(NOW.timestamp())
    mfa_response = client.post(
        "/v1/auth/login/mfa",
        json={
            "email": auth_env["email"],
            "password": auth_env["password"],
            "code": now_step_code,
        },
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )

    assert mfa_response.status_code == 200
    assert mfa_response.json()["authenticated"] is True
    assert "__Host-metaguard_session" in client.cookies
    challenge = response.cookies.get("__Host-metaguard_mfa")
    csrf_after_login = mfa_response.json()["csrf_token"]
    client.cookies.set("__Host-metaguard_mfa", challenge)
    replay = client.post(
        "/v1/auth/login/mfa",
        json={
            "email": auth_env["email"],
            "password": auth_env["password"],
            "code": now_step_code,
        },
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf_after_login},
    )
    assert replay.status_code == 401


def test_credentials_are_not_accepted_from_disallowed_cors_origin(auth_env):
    client, _ = make_client(auth_env)

    preflight = client.options(
        "/v1/auth/login",
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-csrf-token",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == ORIGIN
    assert preflight.headers["access-control-allow-credentials"] == "true"

    rejected = client.options(
        "/v1/auth/login",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-csrf-token",
        },
    )
    assert rejected.status_code == 400
    assert "access-control-allow-origin" not in rejected.headers


def test_refresh_route_is_not_exposed(auth_env):
    client, _ = make_client(auth_env)

    assert client.post("/v1/auth/refresh").status_code == 404


def test_same_site_none_cookies_remain_secure(auth_env):
    settings = Settings(
        environment="test",
        auth_allowed_origins=(ORIGIN,),
        auth_cookie_samesite="none",
    )
    client, _ = make_client(auth_env, settings=settings)
    csrf = preauth(client)

    response = client.post(
        "/v1/auth/login",
        json={"email": auth_env["email"], "password": auth_env["password"]},
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )

    assert response.status_code == 200
    assert all(
        "secure" in cookie.lower() and "samesite=none" in cookie.lower()
        for cookie in response.headers.get_list("set-cookie")
    )


def test_same_site_none_requires_exact_allowed_origins():
    with pytest.raises(ValueError):
        Settings(environment="test", auth_cookie_samesite="none")
    with pytest.raises(ValueError):
        Settings(environment="test", auth_allowed_origins=("*",))
    with pytest.raises(ValueError):
        Settings(environment="test", auth_allowed_origins=("https://frontend.example/path",))

    settings = Settings(
        environment="test",
        auth_cookie_samesite="none",
        auth_allowed_origins=(ORIGIN,),
    )
    assert settings.auth_cookie_samesite == "none"


def test_login_mfa_does_not_issue_session_for_invalid_challenge_or_replayed_code(auth_env):
    client, _ = make_client(auth_env, with_mfa=True)
    csrf = preauth(client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    login = client.post(
        "/v1/auth/login",
        json={"email": auth_env["email"], "password": auth_env["password"]},
        headers=headers,
    )
    client.cookies.set("__Host-metaguard_mfa", "invalid")
    invalid = client.post(
        "/v1/auth/login/mfa",
        json={"email": auth_env["email"], "password": auth_env["password"], "code": "000000"},
        headers=headers,
    )
    assert invalid.status_code == 401
    assert "__Host-metaguard_session" not in client.cookies

    client.cookies.set("__Host-metaguard_mfa", login.cookies.get("__Host-metaguard_mfa"))
    code = pyotp.TOTP(auth_env["totp_secret"]).at(NOW.timestamp())
    first = client.post(
        "/v1/auth/login/mfa",
        json={"email": auth_env["email"], "password": auth_env["password"], "code": code},
        headers=headers,
    )
    assert first.status_code == 200


def test_mfa_challenge_cannot_be_replayed_with_a_later_valid_totp(auth_env):
    client, _ = make_client(auth_env, with_mfa=True)
    csrf = preauth(client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    login = client.post(
        "/v1/auth/login",
        json={"email": auth_env["email"], "password": auth_env["password"]},
        headers=headers,
    )
    challenge = login.cookies.get("__Host-metaguard_mfa")
    first_code = pyotp.TOTP(auth_env["totp_secret"]).at(NOW.timestamp())
    first = client.post(
        "/v1/auth/login/mfa",
        json={"email": auth_env["email"], "password": auth_env["password"], "code": first_code},
        headers=headers,
    )
    assert first.status_code == 200

    auth_env["clock"][0] = NOW + timedelta(seconds=30)
    later_code = pyotp.TOTP(auth_env["totp_secret"]).at(auth_env["clock"][0].timestamp())
    client.cookies.clear()
    client.cookies.set("__Host-metaguard_mfa", challenge, domain="api.example", path="/")
    client.cookies.set("__Host-metaguard_csrf", csrf, domain="api.example", path="/")
    replay = client.post(
        "/v1/auth/login/mfa",
        json={"email": auth_env["email"], "password": auth_env["password"], "code": later_code},
        headers=headers,
    )

    assert replay.status_code == 401
    with auth_env["factory"]() as session:
        assert session.scalar(select(AccountSession.id)) is not None
        assert len(session.scalars(select(AccountSession.id)).all()) == 1


def test_mfa_challenge_is_bound_to_its_issuing_csrf_context(auth_env):
    first_client, _ = make_client(auth_env, with_mfa=True)
    first_csrf = preauth(first_client)
    first_login = first_client.post(
        "/v1/auth/login",
        json={"email": auth_env["email"], "password": auth_env["password"]},
        headers={"Origin": ORIGIN, "X-CSRF-Token": first_csrf},
    )
    challenge = first_login.cookies.get("__Host-metaguard_mfa")

    second_client, _ = make_client(auth_env)
    second_csrf = preauth(second_client)
    assert second_csrf != first_csrf
    second_client.cookies.set("__Host-metaguard_mfa", challenge, domain="api.example", path="/")
    response = second_client.post(
        "/v1/auth/login/mfa",
        json={
            "email": auth_env["email"],
            "password": auth_env["password"],
            "code": pyotp.TOTP(auth_env["totp_secret"]).at(NOW.timestamp()),
        },
        headers={"Origin": ORIGIN, "X-CSRF-Token": second_csrf},
    )

    assert response.status_code == 401
    assert "__Host-metaguard_session" not in second_client.cookies
    with auth_env["factory"]() as session:
        assert session.scalar(select(AccountSession.id)) is None


def test_session_issue_failure_rolls_back_challenge_and_totp_consumption(auth_env, monkeypatch):
    client, _ = make_client(auth_env, with_mfa=True)
    csrf = preauth(client)
    login = client.post(
        "/v1/auth/login",
        json={"email": auth_env["email"], "password": auth_env["password"]},
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )
    challenge = login.cookies.get("__Host-metaguard_mfa")
    challenge_digest = sha256(challenge.encode("ascii")).hexdigest()
    code = pyotp.TOTP(auth_env["totp_secret"]).at(NOW.timestamp())

    from metaguard_api import auth_routes

    monkeypatch.setattr(auth_routes, "issue_session", lambda *args, **kwargs: None)
    response = client.post(
        "/v1/auth/login/mfa",
        json={"email": auth_env["email"], "password": auth_env["password"], "code": code},
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )

    assert response.status_code == 401
    with auth_env["factory"]() as session:
        assert session.scalar(select(AccountSession.id)) is None
        assert session.scalar(select(AccountTotp.last_accepted_step)) is None
        stored_challenge_count = session.execute(
            text(
                "SELECT count(*) FROM mfa_login_challenges "
                "WHERE challenge_digest = :challenge_digest"
            ),
            {"challenge_digest": challenge_digest},
        ).scalar_one()
        assert stored_challenge_count == 1
        stored_digests = session.execute(
            text(
                "SELECT challenge_digest, csrf_digest FROM mfa_login_challenges "
                "WHERE challenge_digest = :challenge_digest"
            ),
            {"challenge_digest": challenge_digest},
        ).one()
        assert stored_digests.challenge_digest == challenge_digest
        assert stored_digests.csrf_digest == sha256(csrf.encode("ascii")).hexdigest()
        assert challenge not in repr(stored_digests)
        assert csrf not in repr(stored_digests)


class FakeEmailSender:
    def __init__(self):
        self.deliveries = []

    def send_verification(self, email, token):
        self.deliveries.append((email, token))


def make_registration_client(auth_env, *, email_sender=None, rate_limiter=None):
    from metaguard_api.auth_routes import AuthRuntime

    runtime_values = make_runtime(auth_env, rate_limiter=rate_limiter)
    runtime_values.update(
        common_passwords=frozenset({"password"}),
        password_lookup=lambda _prefix, _headers: "00000000000000000000000000000000000:0",
        report_password_outage=lambda _event: None,
        email_sender=email_sender or FakeEmailSender(),
        email_verification_lifetime=timedelta(hours=1),
    )
    runtime = AuthRuntime(**runtime_values)
    app = create_app(
        Settings(environment="test", auth_allowed_origins=(ORIGIN,)),
        auth_runtime=runtime,
    )
    return TestClient(app, base_url="https://api.example"), runtime


def test_registration_and_email_verification_keep_token_out_of_responses(auth_env):
    sender = FakeEmailSender()
    client, runtime = make_registration_client(auth_env, email_sender=sender)
    csrf = preauth(client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    email = "new-user@example.test"
    password = "a sufficiently long synthetic password"

    registered = client.post(
        "/v1/auth/register",
        json={"email": email, "password": password},
        headers=headers,
    )
    assert registered.status_code == 202
    assert registered.json() == {"registered": True}
    duplicate = client.post(
        "/v1/auth/register",
        json={"email": email.upper(), "password": "another long synthetic password"},
        headers=headers,
    )
    assert duplicate.status_code == registered.status_code
    assert duplicate.content == registered.content
    assert duplicate.headers == registered.headers
    assert registered.headers["cache-control"] == "no-store"
    assert "set-cookie" not in registered.headers
    assert len(sender.deliveries) == 1
    assert sender.deliveries[0][0] == email
    token = sender.deliveries[0][1]
    assert token not in registered.text

    with auth_env["factory"]() as session:
        account = session.scalar(select(Account).where(Account.email == email))
        assert account is not None
        assert account.email_verified_at is None
        stored = session.execute(
            text("SELECT token_digest FROM email_verification_tokens WHERE account_id=:id"),
            {"id": account.id},
        ).scalar_one()
        assert stored == sha256(token.encode("ascii")).hexdigest()
        assert token not in stored

    verified = client.post("/v1/auth/verify-email", json={"token": token}, headers=headers)
    assert verified.status_code == 200
    assert verified.json() == {"verified": True}
    assert token not in verified.text
    assert runtime.rate_limiter.calls[-1][0] == "auth_verify_email"
    login = client.post(
        "/v1/auth/login", json={"email": email, "password": password}, headers=headers
    )
    assert login.status_code == 200
    with auth_env["factory"]() as session:
        account = session.scalar(select(Account).where(Account.email == email))
        assert account is not None and account.email_verified_at is not None
        assert (
            session.execute(text("SELECT count(*) FROM email_verification_tokens")).scalar_one()
            == 0
        )


def test_gmail_transport_integrates_with_existing_registration(auth_env, tmp_path, monkeypatch):
    import re
    from unittest.mock import MagicMock

    from metaguard_api.gmail_sender import GmailSender
    from metaguard_api.secrets import SecretStore

    # The SMTP double captures a synthetic message; no provider receives it.
    (tmp_path / "gmail_app_password").write_text("abcdefghijklmnop", encoding="ascii")
    smtp = MagicMock()
    smtp.return_value.__enter__.return_value.send_message.return_value = {}
    monkeypatch.setattr("metaguard_api.gmail_sender.smtplib.SMTP_SSL", smtp)
    sender = GmailSender(sender_email="stagingtest@gmail.com", secret_store=SecretStore(tmp_path))
    client, _ = make_registration_client(auth_env, email_sender=sender)
    csrf = preauth(client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    email = "staging-recipient@example.test"
    password = "a sufficiently long synthetic password"

    registered = client.post(
        "/v1/auth/register", json={"email": email, "password": password}, headers=headers
    )
    assert registered.status_code == 202
    outbound = smtp.return_value.__enter__.return_value.send_message
    outbound.assert_called_once()
    message = outbound.call_args.args[0]
    assert str(message["To"]) == email
    plain = message.get_body(preferencelist=("plain",)).get_content()
    html = message.get_body(preferencelist=("html",)).get_content()
    for private_value in (email, password):
        assert private_value not in plain
        assert private_value not in html
    code = re.search(r"(?m)^[A-Za-z0-9_-]{43}$", plain)
    assert code is not None
    token = code.group()
    assert f">{token}</code>" in html
    assert token not in registered.text

    verified = client.post("/v1/auth/verify-email", json={"token": token}, headers=headers)
    assert verified.status_code == 200
    replay = client.post("/v1/auth/verify-email", json={"token": token}, headers=headers)
    assert replay.status_code == 400


def test_registration_fails_closed_when_screening_or_sender_is_missing(auth_env):
    client, _ = make_client(auth_env)
    csrf = preauth(client)
    response = client.post(
        "/v1/auth/register",
        json={"email": "no-provider@example.test", "password": "a sufficiently long password"},
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )
    assert response.status_code == 503
    assert "no-provider@example.test" not in response.text


class FailingEmailSender:
    def send_verification(self, email, token):
        raise RuntimeError(f"synthetic mail failure for {email}: {token}")


RESEND_PATH = "/v1/auth/resend-verification"
PENDING_EMAIL = "pending@example.test"
PENDING_PASSWORD = "a sufficiently long synthetic password"


def register_pending(client, sender, headers):
    response = client.post(
        "/v1/auth/register",
        json={"email": PENDING_EMAIL, "password": PENDING_PASSWORD},
        headers=headers,
    )
    assert response.status_code == 202
    return sender.deliveries[-1][1]


def test_resend_protects_origin_csrf_and_bounds_input(auth_env):
    sender = FakeEmailSender()
    client, runtime = make_registration_client(auth_env, email_sender=sender)
    csrf = preauth(client)
    payload = {"email": PENDING_EMAIL, "password": PENDING_PASSWORD}
    for headers in (
        {"Origin": f"{ORIGIN}.other.test", "X-CSRF-Token": csrf},
        {"Origin": ORIGIN, "X-CSRF-Token": "A" * 43},
        {"Origin": ORIGIN},
    ):
        assert client.post(RESEND_PATH, json=payload, headers=headers).status_code == 403
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
    malformed = client.post(RESEND_PATH, json={**payload, "extra": True}, headers=headers)
    assert malformed.status_code == 400
    assert malformed.json()["error"]["code"] == "invalid_request"
    assert PENDING_PASSWORD not in malformed.text
    oversized = client.post(
        RESEND_PATH,
        content=b" " * 8192 + dumps(payload).encode("ascii"),
        headers={**headers, "Content-Type": "application/json"},
    )
    assert oversized.status_code == 400
    assert [call[0] for call in runtime.rate_limiter.calls] == ["auth_status"]
    assert not sender.deliveries


@pytest.mark.parametrize("advance", [timedelta(minutes=2), timedelta(hours=2)])
def test_resend_replaces_a_lost_or_expired_token_without_existence_signal(
    auth_env, advance, monkeypatch
):
    sender = FakeEmailSender()
    client, runtime = make_registration_client(auth_env, email_sender=sender)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": preauth(client)}
    old_token = register_pending(client, sender, headers)
    auth_env["clock"][0] += advance
    checked_hashes = []

    def record_verification(password, encoded):
        checked_hashes.append(encoded)
        return verify_password(password, encoded)

    monkeypatch.setattr("metaguard_api.email_verification.verify_password", record_verification)
    rejected = []
    for email, password in (
        ("unknown@example.test", PENDING_PASSWORD),
        (auth_env["email"], auth_env["password"]),
        (PENDING_EMAIL, "wrong synthetic password"),
    ):
        rejected.append(
            client.post(RESEND_PATH, json={"email": email, "password": password}, headers=headers)
        )
        assert sender.deliveries == [(PENDING_EMAIL, old_token)]
    assert len(checked_hashes) == 3
    assert checked_hashes[0] == runtime.dummy_password_hash
    assert runtime.dummy_password_hash not in checked_hashes[1:]

    success = client.post(
        RESEND_PATH,
        json={"email": f" {PENDING_EMAIL.upper()} ", "password": PENDING_PASSWORD},
        headers=headers,
    )
    assert success.status_code == 202
    assert success.json() == {"requested": True}
    assert success.headers["cache-control"] == "no-store"
    assert "set-cookie" not in success.headers
    for response in rejected:
        assert (response.status_code, response.content, response.headers) == (
            success.status_code,
            success.content,
            success.headers,
        )
    assert runtime.rate_limiter.calls[-1][2] == sha256(PENDING_EMAIL.encode("ascii")).hexdigest()

    assert len(sender.deliveries) == 2
    recipient, new_token = sender.deliveries[-1]
    assert recipient == PENDING_EMAIL
    assert new_token != old_token
    for private in (new_token, old_token, PENDING_EMAIL, PENDING_PASSWORD):
        assert private not in success.text

    with auth_env["factory"]() as session:
        stored = session.scalar(select(EmailVerificationToken))
        assert stored.token_digest == sha256(new_token.encode("ascii")).hexdigest()
        assert stored.expires_at == auth_env["clock"][0] + timedelta(hours=1)
        assert session.scalar(select(AccountSession)) is None

    verify_path = "/v1/auth/verify-email"
    assert client.post(verify_path, json={"token": old_token}, headers=headers).status_code == 400
    assert client.post(verify_path, json={"token": new_token}, headers=headers).status_code == 200
    assert client.post(verify_path, json={"token": new_token}, headers=headers).status_code == 400


def test_resend_rate_limit_does_not_rotate_or_send(auth_env):
    sender = FakeEmailSender()
    limiter = FakeRateLimiter()
    client, _ = make_registration_client(auth_env, email_sender=sender, rate_limiter=limiter)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": preauth(client)}
    old_token = register_pending(client, sender, headers)
    limiter.allowed = False
    limited = client.post(
        RESEND_PATH, json={"email": PENDING_EMAIL, "password": PENDING_PASSWORD}, headers=headers
    )
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "rate_limited"
    assert sender.deliveries == [(PENDING_EMAIL, old_token)]
    with auth_env["factory"]() as session:
        assert (
            session.scalar(select(EmailVerificationToken)).token_digest
            == sha256(old_token.encode("ascii")).hexdigest()
        )


def test_resend_delivery_failure_keeps_the_previous_code_and_generic_response(auth_env):
    class FailsAfterFirstDelivery(FakeEmailSender):
        def send_verification(self, email, token):
            super().send_verification(email, token)
            if len(self.deliveries) > 1:
                FailingEmailSender().send_verification(email, token)

    sender = FailsAfterFirstDelivery()
    client, _ = make_registration_client(auth_env, email_sender=sender)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": preauth(client)}
    old_token = register_pending(client, sender, headers)
    auth_env["clock"][0] += timedelta(minutes=2)
    failed = client.post(
        RESEND_PATH, json={"email": PENDING_EMAIL, "password": PENDING_PASSWORD}, headers=headers
    )
    assert (failed.status_code, failed.json()) == (202, {"requested": True})
    assert len(sender.deliveries) == 2
    failed_token = sender.deliveries[-1][1]
    assert failed_token != old_token
    for private in (PENDING_EMAIL, PENDING_PASSWORD, failed_token, "synthetic mail failure"):
        assert private not in failed.text
    with auth_env["factory"]() as session:
        assert (
            session.scalar(select(EmailVerificationToken)).token_digest
            == sha256(old_token.encode("ascii")).hexdigest()
        )
    verify_path = "/v1/auth/verify-email"
    assert (
        client.post(verify_path, json={"token": failed_token}, headers=headers).status_code == 400
    )
    assert client.post(verify_path, json={"token": old_token}, headers=headers).status_code == 200


def test_registration_mail_failure_rolls_back_account_and_token(auth_env):
    client, _ = make_registration_client(auth_env, email_sender=FailingEmailSender())
    csrf = preauth(client)
    email = "mail-failure@example.test"
    response = client.post(
        "/v1/auth/register",
        json={"email": email, "password": "another sufficiently long password"},
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
    )
    assert response.status_code == 503
    assert email not in response.text
    assert "synthetic mail failure" not in response.text
    with auth_env["factory"]() as session:
        assert session.scalar(select(Account.id).where(Account.email == email)) is None
        assert (
            session.execute(text("SELECT count(*) FROM email_verification_tokens")).scalar_one()
            == 0
        )


def test_registration_and_verification_share_exact_origin_csrf_and_rate_limit(auth_env):
    client, runtime = make_registration_client(auth_env)
    csrf = preauth(client)
    denied = client.post(
        "/v1/auth/register",
        json={"email": "denied@example.test", "password": "another sufficiently long password"},
        headers={"Origin": "https://evil.example", "X-CSRF-Token": csrf},
    )
    assert denied.status_code == 403
    assert [call[0] for call in runtime.rate_limiter.calls] == ["auth_status"]

    limited_client, limited_runtime = make_registration_client(
        auth_env, rate_limiter=FakeRateLimiter(allowed=False)
    )
    limited_csrf = "A" * 43
    limited_client.cookies.set("__Host-metaguard_csrf", limited_csrf)
    limited = limited_client.post(
        "/v1/auth/register",
        json={"email": "limited@example.test", "password": "another sufficiently long password"},
        headers={"Origin": ORIGIN, "X-CSRF-Token": limited_csrf},
    )
    assert limited.status_code == 429
    assert [call[0] for call in limited_runtime.rate_limiter.calls] == ["auth_register"]
