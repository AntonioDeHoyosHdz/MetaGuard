import re
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from metaguard_api.account_credentials import hash_password
from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account, AccountSession
from metaguard_api.auth_routes import MFA_COOKIE, SESSION_COOKIE, AuthRuntime
from metaguard_api.database import Base
from metaguard_api.main import create_app
from metaguard_api.pending_totp import PendingTotp
from metaguard_api.sessions import MfaLoginChallenge
from metaguard_api.settings import Settings

_ORIGIN = "https://app.example.test"
_EMAIL = "synthetic@example.test"
_PASSWORD = "Long synthetic MFA test password"
_SETUP = "/v1/users/me/totp/setup"
_CONFIRM = "/v1/users/me/totp/confirm"
_RECOVER = "/v1/auth/mfa/recovery"


class Limiter:
    def __init__(self):
        self.denied = set()

    def allow(self, action, _ip, _identity):
        return action not in self.denied


def client_for(runtime):
    return TestClient(
        create_app(
            Settings(environment="test", auth_allowed_origins=(_ORIGIN,)), auth_runtime=runtime
        ),
        base_url=_ORIGIN,
    )


@pytest.fixture
def environment():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    clock = [datetime(2026, 11, 19, tzinfo=UTC)]
    account_id = str(uuid4())
    with factory.begin() as session:
        session.add(
            Account(
                id=account_id,
                email=_EMAIL,
                password_hash=hash_password(_PASSWORD),
                email_verified_at=clock[0],
            )
        )
    runtime = AuthRuntime(
        session_factory=factory,
        rate_limiter=Limiter(),
        signing_key="synthetic-signing-value-for-mfa-route-tests",
        issuer="test-issuer",
        audience="test-audience",
        dummy_password_hash=hash_password("Different synthetic password"),
        totp_encryption_key=b"T" * 32,
        totp_key_version=1,
        session_lifetime=timedelta(minutes=15),
        mfa_challenge_lifetime=timedelta(minutes=5),
        now=lambda: clock[0],
    )
    try:
        yield runtime, factory, clock, account_id
    finally:
        engine.dispose()


def auth_headers(client):
    result = client.get("/v1/auth/status")
    assert result.status_code == 200
    return {"Origin": _ORIGIN, "X-CSRF-Token": result.json()["csrf_token"]}


def login(client, *, expect_mfa=False):
    response = client.post(
        "/v1/auth/login",
        json={"email": _EMAIL, "password": _PASSWORD},
        headers=auth_headers(client),
    )
    assert response.status_code == 200
    assert response.json()["authenticated"] is not expect_mfa
    assert response.json().get("mfa_required", False) is expect_mfa
    return {"Origin": _ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]}


def otp(seed, now):
    return pyotp.HOTP(seed).at(int(now.timestamp()) // 30)


def different_otp(code):
    return "000001" if code == "000000" else "000000"


def assert_codes(response):
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    codes = response.json()["recovery_codes"]
    assert len(set(codes)) == 8
    assert all(re.fullmatch(r"[0-9a-f]{32}", code) for code in codes)
    return codes


def enroll(runtime, clock):
    client = client_for(runtime)
    headers = login(client)
    setup = client.post(_SETUP, json={"password": _PASSWORD}, headers=headers)
    assert setup.status_code == 200
    seed = setup.json()["secret"]
    result = client.post(_CONFIRM, json={"code": otp(seed, clock[0])}, headers=headers)
    return seed, assert_codes(result)


def open_recovery(client, clock, backup_code):
    headers = login(client, expect_mfa=True)
    creds = {"email": _EMAIL, "password": _PASSWORD, "recovery_code": backup_code}
    response = client.post(f"{_RECOVER}/setup", json=creds, headers=headers)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    seed = response.json()["secret"]
    payload = {**creds, "setup_token": response.json()["setup_token"], "code": otp(seed, clock[0])}
    return headers, seed, payload


def test_enrollment_needs_session_origin_csrf_password_and_correct_totp(environment):
    runtime, factory, clock, account_id = environment
    client = client_for(runtime)
    assert (
        client.post(_SETUP, json={"password": _PASSWORD}, headers=auth_headers(client)).status_code
        == 401
    )
    headers = login(client)
    prior_token = client.cookies.get(SESSION_COOKIE)
    second = client_for(runtime)
    login(second)
    assert client.post(_SETUP, json={"password": _PASSWORD}).status_code == 403
    assert (
        client.post(_SETUP, json={"password": "Wrong password"}, headers=headers).status_code == 401
    )
    response = client.post(_SETUP, json={"password": _PASSWORD}, headers=headers)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    seed = response.json()["secret"]
    assert response.json()["otpauth_uri"].startswith("otpauth://totp/")
    assert response.json()["expires_at"] > int(clock[0].timestamp())
    with factory() as session:
        pending = session.get(PendingTotp, account_id)
        assert pending and seed.encode() not in pending.encrypted_secret
        assert session.get(AccountTotp, account_id) is None
    code = otp(seed, clock[0])
    assert (
        client.post(_CONFIRM, json={"code": different_otp(code)}, headers=headers).status_code
        == 401
    )
    result = client.post(_CONFIRM, json={"code": code}, headers=headers)
    codes = assert_codes(result)
    assert client.cookies.get(SESSION_COOKIE) is None
    assert not second.get("/v1/auth/status").json()["authenticated"]
    client.cookies.set(SESSION_COOKIE, prior_token)
    assert not client.get("/v1/auth/status").json()["authenticated"]

    from metaguard_api.mfa_lifecycle import MfaRecoveryCode

    with factory() as session:
        stored = set(session.scalars(select(MfaRecoveryCode.digest)))
        assert stored == {sha256(code.encode("ascii")).hexdigest() for code in codes}
        assert session.get(PendingTotp, account_id) is None
        active_totp = session.get(AccountTotp, account_id)
        assert active_totp and seed.encode() not in active_totp.encrypted_secret
        assert all(
            record.revoked_at is not None for record in session.scalars(select(AccountSession))
        )


def test_recovery_replaces_instead_of_disabling_totp_and_rejects_replay(environment):
    runtime, factory, clock, account_id = environment
    old_seed, old_codes = enroll(runtime, clock)
    clock[0] += timedelta(seconds=30)
    old_client = client_for(runtime)
    old_headers = login(old_client, expect_mfa=True)
    assert (
        old_client.post(
            "/v1/auth/login/mfa",
            headers=old_headers,
            json={
                "email": _EMAIL,
                "password": _PASSWORD,
                "code": otp(old_seed, clock[0]),
            },
        ).status_code
        == 200
    )
    with factory() as session:
        prior = session.get(AccountTotp, account_id).encrypted_secret

    recovering = client_for(runtime)
    headers, seed, payload = open_recovery(recovering, clock, old_codes[0])
    copied = client_for(runtime)
    copied.cookies.set(MFA_COOKIE, recovering.cookies.get(MFA_COOKIE))
    assert (
        copied.post(f"{_RECOVER}/confirm", json=payload, headers=auth_headers(copied)).status_code
        == 401
    )
    invalid = {**payload, "code": different_otp(payload["code"])}
    assert recovering.post(f"{_RECOVER}/confirm", json=invalid, headers=headers).status_code == 401
    wrong_backup = {**payload, "recovery_code": old_codes[1]}
    assert (
        recovering.post(f"{_RECOVER}/confirm", json=wrong_backup, headers=headers).status_code
        == 401
    )
    setup_token = payload["setup_token"]
    forged = {**payload, "setup_token": ("A" if setup_token[0] != "A" else "B") + setup_token[1:]}
    assert recovering.post(f"{_RECOVER}/confirm", json=forged, headers=headers).status_code == 401
    with factory() as session:
        assert session.get(AccountTotp, account_id).encrypted_secret == prior
    assert old_client.get("/v1/auth/status").json()["authenticated"]

    success = recovering.post(f"{_RECOVER}/confirm", json=payload, headers=headers)
    new_codes = assert_codes(success)
    assert set(old_codes).isdisjoint(new_codes)
    assert recovering.cookies.get(MFA_COOKIE) is None
    assert not old_client.get("/v1/auth/status").json()["authenticated"]
    with factory() as session:
        assert session.get(AccountTotp, account_id).encrypted_secret != prior
    headers = login(recovering, expect_mfa=True)
    assert (
        recovering.post(
            f"{_RECOVER}/setup",
            headers=headers,
            json={
                "email": _EMAIL,
                "password": _PASSWORD,
                "recovery_code": old_codes[1],
            },
        ).status_code
        == 401
    )
    assert recovering.post(f"{_RECOVER}/confirm", headers=headers, json=payload).status_code == 401
    clock[0] += timedelta(seconds=30)
    while otp(seed, clock[0]) == otp(old_seed, clock[0]):
        clock[0] += timedelta(seconds=30)
    prior_credentials = {"email": _EMAIL, "password": _PASSWORD, "code": otp(old_seed, clock[0])}
    assert (
        recovering.post("/v1/auth/login/mfa", headers=headers, json=prior_credentials).status_code
        == 401
    )
    assert (
        recovering.post(
            "/v1/auth/login/mfa",
            headers=headers,
            json={
                "email": _EMAIL,
                "password": _PASSWORD,
                "code": otp(seed, clock[0]),
            },
        ).status_code
        == 200
    )


def test_recovery_commit_failure_keeps_factor_code_and_challenge_retryable(environment):
    runtime, factory, clock, account_id = environment
    _, codes = enroll(runtime, clock)
    client = client_for(runtime)
    headers, _, payload = open_recovery(client, clock, codes[0])
    with factory() as session:
        prior = session.get(AccountTotp, account_id).encrypted_secret

    class FailingFactory:
        @contextmanager
        def begin(self):
            with factory.begin() as session:
                yield session
                raise RuntimeError("Synthetic commit failure")

    failure = client_for(replace(runtime, session_factory=FailingFactory()))
    failure.cookies.update(client.cookies)
    result = failure.post(f"{_RECOVER}/confirm", json=payload, headers=headers)
    assert result.status_code == 503
    assert "recovery_codes" not in result.json()
    with factory() as session:
        assert session.get(AccountTotp, account_id).encrypted_secret == prior
        assert session.scalar(select(MfaLoginChallenge.account_id)) == account_id
    assert_codes(client.post(f"{_RECOVER}/confirm", json=payload, headers=headers))


def test_expired_recovery_and_redacted_validation(environment):
    runtime, _, clock, _ = environment
    _, codes = enroll(runtime, clock)
    client = client_for(runtime)
    headers, _, payload = open_recovery(client, clock, codes[0])
    clock[0] += timedelta(minutes=6)
    rejected = client.post(f"{_RECOVER}/confirm", json=payload, headers=headers)
    assert rejected.status_code == 401
    for path in (_SETUP, _CONFIRM, f"{_RECOVER}/confirm"):
        invalid = {"marker": "sensitive-synthetic-value"}
        validation = client.post(path, json=invalid, headers=headers)
        assert validation.status_code == 400
        assert validation.headers["cache-control"] == "no-store"
        assert invalid["marker"] not in validation.text


def test_enrollment_and_recovery_obey_rate_limits_and_expiration(environment):
    runtime, factory, clock, account_id = environment
    client = client_for(runtime)
    headers = login(client)
    runtime.rate_limiter.denied.add("mfa_enrollment_setup")
    assert client.post(_SETUP, json={"password": _PASSWORD}, headers=headers).status_code == 429
    with factory() as session:
        assert session.get(PendingTotp, account_id) is None
    runtime.rate_limiter.denied.clear()
    response = client.post(_SETUP, json={"password": _PASSWORD}, headers=headers)
    assert response.status_code == 200
    old_seed = response.json()["secret"]
    clock[0] += timedelta(seconds=300)
    assert (
        client.post(_CONFIRM, json={"code": otp(old_seed, clock[0])}, headers=headers).status_code
        == 401
    )
    renewed = client.post(_SETUP, json={"password": _PASSWORD}, headers=headers)
    assert renewed.status_code == 200
    seed = renewed.json()["secret"]
    assert seed != old_seed
    runtime.rate_limiter.denied.add("mfa_enrollment_confirm")
    code = {"code": otp(seed, clock[0])}
    assert client.post(_CONFIRM, json=code, headers=headers).status_code == 429
    runtime.rate_limiter.denied.clear()
    codes = assert_codes(client.post(_CONFIRM, json=code, headers=headers))
    headers, _, payload = open_recovery(client, clock, codes[0])
    runtime.rate_limiter.denied.add("mfa_recovery_account")
    assert client.post(f"{_RECOVER}/confirm", json=payload, headers=headers).status_code == 429
    runtime.rate_limiter.denied.clear()
    assert_codes(client.post(f"{_RECOVER}/confirm", json=payload, headers=headers))
