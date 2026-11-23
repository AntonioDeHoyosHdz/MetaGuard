from datetime import timedelta

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_auth_routes import NOW, ORIGIN, SIGNING_KEY, make_runtime, preauth
from test_auth_routes import auth_env as auth_env

from metaguard_api import auth_routes
from metaguard_api.account_credentials import hash_password
from metaguard_api.account_security_events import AccountSecurityEvent, AccountSecurityEventKind
from metaguard_api.accounts import Account, AccountSession
from metaguard_api.auth_routes import AuthRuntime
from metaguard_api.login_email_challenge import LoginEmailChallenge
from metaguard_api.login_risk import AccountLoginFailure, login_address_digest
from metaguard_api.main import create_app
from metaguard_api.security_alerts import SecurityAlertOutbox, dispatch_security_alerts
from metaguard_api.settings import Settings


class _Mail:
    def __init__(self):
        self.challenges = []
        self.alerts = []

    def send_login_challenge(self, email, code):
        self.challenges.append((email, code))

    def send_security_alert(self, email):
        self.alerts.append(email)


def _risk_app(auth_env, mail, *, mfa=False):
    runtime = AuthRuntime(
        **make_runtime(auth_env, with_mfa=mfa), login_risk_enabled=True, email_sender=mail
    )
    return create_app(
        Settings(environment="test", auth_allowed_origins=(ORIGIN,)), auth_runtime=runtime
    )


def _client(app, address):
    client = TestClient(app, base_url="https://api.example", client=(address, 50000))
    return client, {"Origin": ORIGIN, "X-CSRF-Token": preauth(client)}


def _credentials(env, password=None):
    return {"email": env["email"], "password": password or env["password"]}


def _fail_at_distinct_origins(app, env):
    for host in (20, 21, 22):
        client, headers = _client(app, f"192.0.2.{host}")
        response = client.post(
            "/v1/auth/login", json=_credentials(env, "wrong synthetic password"), headers=headers
        )
        assert response.status_code == 401


def test_pair_lock_is_generic_ignores_forwarded_identity_and_does_not_lock_other_address(auth_env):
    mail = _Mail()
    app = _risk_app(auth_env, mail)
    requester, headers = _client(app, "192.0.2.10")
    legitimate, legitimate_headers = _client(app, "192.0.2.11")
    for spoofed in range(10, 15):
        result = requester.post(
            "/v1/auth/login",
            json=_credentials(auth_env, "wrong synthetic password"),
            headers={**headers, "X-Forwarded-For": f"198.51.100.{spoofed}"},
        )
        assert result.status_code == 401
    blocked = requester.post("/v1/auth/login", json=_credentials(auth_env), headers=headers)
    assert blocked.status_code == 401 and blocked.json() == result.json()
    assert "__Host-metaguard_session" not in requester.cookies
    assert legitimate.post(
        "/v1/auth/login", json=_credentials(auth_env), headers=legitimate_headers
    ).json()["authenticated"]
    with auth_env["factory"].begin() as session:
        entry = session.scalar(select(AccountLoginFailure))
        assert entry.address_digest == login_address_digest(
            auth_env["account_id"], "192.0.2.10", SIGNING_KEY
        )
        assert entry.locked_until == NOW + timedelta(minutes=1)
        assert session.scalar(select(func.count()).select_from(SecurityAlertOutbox)) == 1
    assert not mail.alerts
    dispatch_security_alerts(auth_env["factory"], mail, now=NOW)
    assert mail.alerts == [auth_env["email"]]
    auth_env["clock"][0] += timedelta(minutes=1)
    assert requester.post("/v1/auth/login", json=_credentials(auth_env), headers=headers).json()[
        "authenticated"
    ]
    with auth_env["factory"].begin() as session:
        assert session.scalar(select(func.count()).select_from(AccountLoginFailure)) == 0
        assert (
            session.scalar(
                select(AccountSecurityEvent.kind).where(AccountSecurityEvent.kind == "new_ip_login")
            )
            == "new_ip_login"
        )


def test_multi_origin_email_step_up_requires_bound_proof_before_session_and_cannot_replay(auth_env):
    mail = _Mail()
    app = _risk_app(auth_env, mail)
    _fail_at_distinct_origins(app, auth_env)
    client, headers = _client(app, "192.0.2.30")
    same_ip_other_context, other_headers = _client(app, "192.0.2.30")
    other_ip = TestClient(
        app, base_url="https://api.example", client=("192.0.2.31", 50000), cookies=client.cookies
    )
    issued = client.post("/v1/auth/login", json=_credentials(auth_env), headers=headers)
    assert issued.status_code == 200
    assert issued.json() == {
        "authenticated": False,
        "email_challenge_required": True,
        "csrf_token": headers["X-CSRF-Token"],
    }
    assert "__Host-metaguard_session" not in client.cookies
    assert len(mail.challenges) == 1 and mail.challenges[0][0] == auth_env["email"]
    assert issued.headers["cache-control"] == "no-store"
    with auth_env["factory"].begin() as session:
        assert session.scalar(select(func.count()).select_from(AccountSession)) == 0
        assert session.scalar(select(func.count()).select_from(SecurityAlertOutbox)) == 1
    client.post("/v1/auth/login", json=_credentials(auth_env), headers=headers)
    assert len(mail.challenges) == 1
    code = mail.challenges[0][1]
    assert len(code) == 32 and int(code, 16) >= 0
    payload = {**_credentials(auth_env), "code": code}
    for submitter, context in ((same_ip_other_context, other_headers), (other_ip, headers)):
        assert (
            submitter.post("/v1/auth/login/email", json=payload, headers=context).status_code == 401
        )
    invalid = client.post(
        "/v1/auth/login/email",
        json={**payload, "code": "0" * 32 if code != "0" * 32 else "1" * 32},
        headers=headers,
    )
    assert invalid.status_code == 401 and invalid.headers["cache-control"] == "no-store"
    assert invalid.json() == {"error": {"code": "unauthorized", "message": "Invalid credentials"}}
    assert (
        client.post(
            "/v1/auth/login/email", json=payload, headers={**headers, "Origin": "null"}
        ).status_code
        == 403
    )
    accepted = client.post("/v1/auth/login/email", json=payload, headers=headers)
    assert accepted.status_code == 200
    assert accepted.json()["authenticated"] and "__Host-metaguard_session" in client.cookies
    client.cookies.set("__Host-metaguard_csrf", headers["X-CSRF-Token"], domain="api.example")
    assert client.post("/v1/auth/login/email", json=payload, headers=headers).status_code == 401


def test_email_challenge_expires_and_does_not_survive_password_version_changes(auth_env):
    mail = _Mail()
    app = _risk_app(auth_env, mail)
    _fail_at_distinct_origins(app, auth_env)
    expiring, expiring_headers = _client(app, "192.0.2.35")
    expiring.post("/v1/auth/login", json=_credentials(auth_env), headers=expiring_headers)
    expired_code = mail.challenges[-1][1]
    auth_env["clock"][0] += timedelta(minutes=5)
    assert (
        expiring.post(
            "/v1/auth/login/email",
            json={**_credentials(auth_env), "code": expired_code},
            headers=expiring_headers,
        ).status_code
        == 401
    )
    fresh, fresh_headers = _client(app, "192.0.2.36")
    fresh.post("/v1/auth/login", json=_credentials(auth_env), headers=fresh_headers)
    code = mail.challenges[-1][1]
    new_password = "different synthetic password"
    with auth_env["factory"].begin() as session:
        session.get(Account, auth_env["account_id"]).password_hash = hash_password(new_password)
    assert (
        fresh.post(
            "/v1/auth/login/email",
            json={**_credentials(auth_env, new_password), "code": code},
            headers=fresh_headers,
        ).status_code
        == 401
    )
    assert (
        fresh.post(
            "/v1/auth/login/email",
            content=b"x" * 9000,
            headers={**fresh_headers, "Content-Type": "application/json"},
        ).status_code
        == 401
    )


def test_multi_origin_risk_prefers_enrolled_totp_without_sending_a_login_code(auth_env):
    mail = _Mail()
    app = _risk_app(auth_env, mail, mfa=True)
    _fail_at_distinct_origins(app, auth_env)
    client, headers = _client(app, "192.0.2.30")
    response = client.post("/v1/auth/login", json=_credentials(auth_env), headers=headers)
    assert response.json() == {
        "authenticated": False,
        "mfa_required": True,
        "csrf_token": headers["X-CSRF-Token"],
    }
    assert not mail.challenges
    with auth_env["factory"].begin() as session:
        assert session.scalar(select(func.count()).select_from(AccountSession)) == 0
    totp = pyotp.TOTP(auth_env["totp_secret"]).at(int(NOW.timestamp()))
    assert client.post(
        "/v1/auth/login/mfa", json={**_credentials(auth_env), "code": totp}, headers=headers
    ).json()["authenticated"]


def test_email_challenge_cannot_expire_during_current_password_verification(auth_env, monkeypatch):
    mail = _Mail()
    app = _risk_app(auth_env, mail)
    _fail_at_distinct_origins(app, auth_env)
    client, headers = _client(app, "192.0.2.30")
    issued = client.post("/v1/auth/login", json=_credentials(auth_env), headers=headers)
    assert issued.json()["email_challenge_required"]
    code = mail.challenges[-1][1]
    expires_at = NOW + timedelta(minutes=5)
    auth_env["clock"][0] = expires_at - timedelta(microseconds=1)
    real_verify = auth_routes.check_first_factor

    def verify_and_advance(*args, **kwargs):
        result = real_verify(*args, **kwargs)
        auth_env["clock"][0] = expires_at
        return result

    monkeypatch.setattr(auth_routes, "check_first_factor", verify_and_advance)
    denied = client.post(
        "/v1/auth/login/email", json={**_credentials(auth_env), "code": code}, headers=headers
    )
    assert denied.status_code == 401
    assert "__Host-metaguard_session" not in client.cookies


def test_multi_origin_without_email_transport_never_downgrades_to_password_login(auth_env):
    app = _risk_app(auth_env, None)
    _fail_at_distinct_origins(app, auth_env)
    client, headers = _client(app, "192.0.2.30")
    denied = client.post("/v1/auth/login", json=_credentials(auth_env), headers=headers)
    assert denied.status_code == 503 and denied.json()["error"]["code"] == "auth_unavailable"
    assert denied.headers["cache-control"] == "no-store"
    assert "__Host-metaguard_session" not in client.cookies


def test_challenge_is_committed_before_delivery_and_consumed_only_with_session(
    auth_env, monkeypatch
):
    class VerifyCommit(_Mail):
        def send_login_challenge(self, email, code):
            with auth_env["factory"].begin() as session:
                assert (
                    session.scalar(select(LoginEmailChallenge.account_id)) == auth_env["account_id"]
                )
            super().send_login_challenge(email, code)

    mail = VerifyCommit()
    app = _risk_app(auth_env, mail)
    _fail_at_distinct_origins(app, auth_env)
    client, headers = _client(app, "192.0.2.30")
    assert client.post("/v1/auth/login", json=_credentials(auth_env), headers=headers).json()[
        "email_challenge_required"
    ]
    code = mail.challenges[-1][1]
    payload = {**_credentials(auth_env), "code": code}
    with monkeypatch.context() as fake_issue:
        fake_issue.setattr(auth_routes, "issue_session", lambda *_args, **_kwargs: None)
        assert client.post("/v1/auth/login/email", json=payload, headers=headers).status_code == 401
        assert "__Host-metaguard_session" not in client.cookies
    assert client.post("/v1/auth/login/email", json=payload, headers=headers).json()[
        "authenticated"
    ]
    with auth_env["factory"].begin() as session:
        assert session.scalar(select(func.count()).select_from(LoginEmailChallenge)) == 0


def test_bound_wrong_password_counts_and_keeps_email_challenge_for_retry(auth_env):
    mail = _Mail()
    app = _risk_app(auth_env, mail)
    _fail_at_distinct_origins(app, auth_env)
    now = NOW + timedelta(minutes=10)
    auth_env["clock"][0] = now
    address = "192.0.2.30"
    client, headers = _client(app, address)
    assert client.post("/v1/auth/login", json=_credentials(auth_env), headers=headers).json()[
        "email_challenge_required"
    ]
    code = mail.challenges[-1][1]
    response = client.post(
        "/v1/auth/login/email",
        json={**_credentials(auth_env, "wrong synthetic password"), "code": code},
        headers=headers,
    )
    assert response.status_code == 401
    assert response.json() == {"error": {"code": "unauthorized", "message": "Invalid credentials"}}
    assert response.headers["cache-control"] == "no-store"
    assert "__Host-metaguard_session" not in client.cookies
    owner = auth_env["account_id"]
    digest = login_address_digest(owner, address, SIGNING_KEY)
    with auth_env["factory"].begin() as session:
        failure = session.get(AccountLoginFailure, (owner, digest))
        assert failure is not None and failure.consecutive_failures == 1
        assert failure.locked_until is None and failure.last_failed_at == now
        assert (
            session.scalar(
                select(AccountSecurityEvent.kind).where(
                    AccountSecurityEvent.account_id == owner,
                    AccountSecurityEvent.created_at == int(now.timestamp()),
                )
            )
            == AccountSecurityEventKind.LOGIN_FAILED
        )
        assert session.scalar(select(func.count()).select_from(LoginEmailChallenge)) == 1
    accepted = client.post(
        "/v1/auth/login/email", json={**_credentials(auth_env), "code": code}, headers=headers
    )
    assert accepted.json()["authenticated"]
    with auth_env["factory"].begin() as session:
        assert session.get(AccountLoginFailure, (owner, digest)) is None


def test_unbound_expired_or_changed_password_does_not_count_wrong_email_password(auth_env):
    mail = _Mail()
    app = _risk_app(auth_env, mail)
    _fail_at_distinct_origins(app, auth_env)
    now = NOW + timedelta(minutes=10)
    auth_env["clock"][0] = now
    address = "192.0.2.30"
    client, headers = _client(app, address)
    same_address_new_context, other_headers = _client(app, address)
    other_address = TestClient(
        app, base_url="https://api.example", client=("192.0.2.31", 50000), cookies=client.cookies
    )
    assert client.post("/v1/auth/login", json=_credentials(auth_env), headers=headers).json()[
        "email_challenge_required"
    ]
    wrong = {
        **_credentials(auth_env, "wrong synthetic password"),
        "code": mail.challenges[-1][1],
    }
    assert (
        same_address_new_context.post(
            "/v1/auth/login/email", json=wrong, headers=other_headers
        ).status_code
        == 401
    )
    assert (
        other_address.post("/v1/auth/login/email", json=wrong, headers=headers).status_code == 401
    )
    auth_env["clock"][0] = now + timedelta(minutes=5)
    assert client.post("/v1/auth/login/email", json=wrong, headers=headers).status_code == 401
    auth_env["clock"][0] = now + timedelta(minutes=4)
    with auth_env["factory"].begin() as session:
        session.get(Account, auth_env["account_id"]).password_hash = hash_password(
            "different synthetic password"
        )
    assert client.post("/v1/auth/login/email", json=wrong, headers=headers).status_code == 401
    with auth_env["factory"].begin() as session:
        assert session.scalar(select(func.count()).select_from(AccountLoginFailure)) == 3
        assert (
            session.scalar(
                select(func.count())
                .select_from(AccountSecurityEvent)
                .where(AccountSecurityEvent.created_at >= int(now.timestamp()))
            )
            == 0
        )
        assert session.scalar(select(func.count()).select_from(LoginEmailChallenge)) == 1
