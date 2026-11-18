from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from metaguard_api.account_credentials import hash_password
from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account, AccountSession
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
