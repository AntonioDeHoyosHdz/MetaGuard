from dataclasses import replace
from datetime import timedelta
from hashlib import sha1

import pyotp
from fastapi.testclient import TestClient
from test_account_password_routes import _BLOCKED, _change, _client, _headers, _login
from test_account_password_routes import env as env
from test_auth_routes import auth_env as auth_env
from test_auth_routes import make_client, preauth
from test_report_routes import NOW, ORIGIN, PASSWORD, login_client
from test_report_routes import api_factory as api_factory

HISTORY = "/v1/security/events"


def _csrf(token):
    return {"Origin": ORIGIN, "X-CSRF-Token": token}


def test_history_requires_session_origin_csrf_and_only_returns_own_events(api_factory):
    _, _, app, _, _, _, other_id = api_factory()
    anonymous = TestClient(app, base_url="https://api.example")
    headers = _csrf(preauth(anonymous))
    assert anonymous.get(HISTORY, headers=headers).status_code == 401
    known = anonymous.post(
        "/v1/auth/login",
        headers=headers,
        json={"email": "owner@example.test", "password": "wrong synthetic password"},
    )
    unknown = anonymous.post(
        "/v1/auth/login",
        headers=headers,
        json={"email": "absent@example.test", "password": "wrong synthetic password"},
    )
    assert known.status_code == unknown.status_code == 401
    assert known.json() == unknown.json()

    owner, headers = login_client(app, "owner@example.test")
    other, other_headers = login_client(app, "other@example.test")
    assert owner.get(HISTORY).status_code == 403
    wrong_origin = owner.get(HISTORY, headers={**headers, "Origin": "https://other.test"})
    assert wrong_origin.status_code == 403
    assert owner.get(HISTORY, headers={**headers, "X-CSRF-Token": "x" * 43}).status_code == 403
    response = owner.get(HISTORY, params={"account_id": other_id}, headers=headers)
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json() == {"events": [{"kind": "login_failed", "created_at": NOW.isoformat()}]}
    assert other.get(HISTORY, headers=other_headers).json() == {"events": []}


def test_only_valid_password_and_browser_bound_mfa_rejection_is_recorded(auth_env):
    client, _ = make_client(auth_env, with_mfa=True)
    headers = _csrf(preauth(client))
    login = {"email": auth_env["email"], "password": auth_env["password"]}
    now = auth_env["clock"][0]
    valid_code = pyotp.TOTP(auth_env["totp_secret"]).at(now.timestamp())
    invalid_code = f"{(int(valid_code) + 1) % 1_000_000:06d}"

    def verify(code, credentials=login):
        return client.post(
            "/v1/auth/login/mfa", json={**credentials, "code": code}, headers=headers
        )

    assert verify(invalid_code).status_code == 401
    assert client.post("/v1/auth/login", json=login, headers=headers).json()["mfa_required"]
    wrong_password = {**login, "password": "wrong synthetic password"}
    assert verify(valid_code, wrong_password).status_code == 401
    auth_env["clock"][0] = now + timedelta(seconds=1)
    denied = verify(invalid_code)
    assert denied.status_code == 401
    auth_env["clock"][0] = now + timedelta(seconds=2)
    authenticated = verify(valid_code)
    assert authenticated.status_code == 200
    assert client.get(HISTORY, headers=_csrf(authenticated.json()["csrf_token"])).json() == {
        "events": [{"kind": "mfa_failed", "created_at": (now + timedelta(seconds=1)).isoformat()}]
    }


def test_only_proven_owner_quota_denials_are_recorded_and_history_never_self_audits(api_factory):
    _, _, app, _, limiter, _, _ = api_factory()
    client, headers = login_client(app, "owner@example.test")
    limiter.allow = lambda action, *_: (
        action
        not in {
            "requests_per_minute_per_account",
            "uploads_per_minute_per_ip",
        }
    )
    assert client.get(HISTORY, headers=headers).status_code == 429
    assert client.post("/v1/uploads", content=b"synthetic", headers=headers).status_code == 429
    limiter.allow = lambda *_: True
    assert client.get(HISTORY, headers=headers).json() == {"events": []}
    limiter.allow = lambda action, *_: action != "uploads_per_hour_per_account"
    assert client.post("/v1/uploads", content=b"synthetic", headers=headers).status_code == 429
    assert client.get(HISTORY, headers=headers).json() == {
        "events": [{"kind": "rate_limit_exceeded", "created_at": NOW.isoformat()}]
    }


def test_audit_storage_failure_does_not_mask_generic_login_denial(api_factory):
    engine, _, app, _, _, _, _ = api_factory()
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP TABLE IF EXISTS account_security_events")
    client = TestClient(app, base_url="https://api.example")
    response = client.post(
        "/v1/auth/login",
        json={"email": "owner@example.test", "password": PASSWORD + "!"},
        headers=_csrf(preauth(client)),
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_only_positive_file_signals_are_recorded_without_changing_upload_behavior(api_factory):
    _, _, app, _, _, _, _ = api_factory()
    client, headers = login_client(app, "owner@example.test")
    processor = app.state.file_runtime.processing_client
    ordinary_process = processor.process

    def upload(payload, content_type="image/png"):
        return client.post(
            "/v1/uploads", content=payload, headers={**headers, "Content-Type": content_type}
        )

    def analyse(upload_response):
        assert upload_response.status_code == 201
        return client.post(
            f"/v1/analyses/{upload_response.json()['upload_id']}", json={}, headers=headers
        )

    def fake_processing_failure(*_):
        raise ValueError("synthetic processing failure")

    processor.process = fake_processing_failure
    assert analyse(upload(b"unknown synthetic bytes")).status_code == 503
    assert client.get(HISTORY, headers=headers).json() == {"events": []}

    assert analyse(upload(b"%PDF-1.7\nsynthetic fixture")).status_code == 503

    def processed_active_content(*args):
        result = ordinary_process(*args)
        report = replace(
            result.report, active_content_removed=True, width=None, height=None, page_count=1
        )
        return replace(result, report=report)

    processor.process = processed_active_content
    assert analyse(upload(b"%PDF-1.7\nsynthetic fixture", "application/pdf")).status_code == 200
    assert {event["kind"] for event in client.get(HISTORY, headers=headers).json()["events"]} == {
        "upload_type_mismatch",
        "dangerous_content_detected",
    }


def test_confirmed_breach_not_local_blocklist_records_owner_event(env):
    runtime, _, _, _ = env
    leaked = "synthetic positive breach lookup"
    digest = sha1(leaked.encode(), usedforsecurity=False).hexdigest().upper()
    runtime = replace(
        runtime,
        password_lookup=lambda prefix, _: f"{digest[5:]}:1" if prefix == digest[:5] else "",
    )
    client = _client(runtime)
    headers = _headers(_login(client))
    local_rejection = _change(client, headers, new=_BLOCKED)
    assert local_rejection.status_code == 400
    assert client.get(HISTORY, headers=headers).json() == {"events": []}
    leaked_rejection = _change(client, headers, new=leaked)
    assert leaked_rejection.status_code == 400
    assert leaked_rejection.json() == local_rejection.json()
    assert [item["kind"] for item in client.get(HISTORY, headers=headers).json()["events"]] == [
        "leaked_password_rejected"
    ]
