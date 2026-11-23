import asyncio
import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha1, sha256
from threading import Barrier, Event

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import URL, create_engine, delete, event, select, update
from sqlalchemy.orm import sessionmaker

from metaguard_api.account_credentials import hash_password, verify_password
from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account, AccountSession
from metaguard_api.auth_routes import CSRF_COOKIE, AuthRuntime
from metaguard_api.database import Base, Database
from metaguard_api.local_rate_limit import LocalRateLimiter
from metaguard_api.main import create_app
from metaguard_api.maintenance import purge_maintenance_for_api
from metaguard_api.mfa_lifecycle import MfaRecoveryCode
from metaguard_api.password_reset import PasswordResetProof
from metaguard_api.sessions import MfaLoginChallenge
from metaguard_api.settings import Settings

_ORIGIN = "https://app.example.test"
_EMAIL = "synthetic@example.test"
_UNKNOWN = "unknown@example.test"
_UNVERIFIED = "pending@example.test"
_PASSWORD = "An existing synthetic password value"
_NEW_PASSWORD = "A different synthetic reset password"
_BLOCKED_PASSWORD = "A synthetic blocklisted password"
_TIME = datetime(2026, 11, 20, tzinfo=UTC)
_REQUEST = "/v1/auth/password-reset/request"
_CONFIRM = "/v1/auth/password-reset/confirm"
_STATUS = "/v1/auth/status"
_LOGIN = "/v1/auth/login"
_MFA = "/v1/auth/login/mfa"
_RECOVER = "/v1/auth/mfa/recovery"
_SETTINGS = Settings(environment="test", auth_allowed_origins=(_ORIGIN,))


class _Capture:
    def __init__(self):
        self.messages = []

    def send_password_reset(self, email, code):
        self.messages.append((email, code))


class _Limiter:
    def allow(self, _action, _ip, _identity):
        return True


@pytest.fixture
def environment(tmp_path):
    engine = create_engine(URL.create("sqlite", database=str(tmp_path / "reset.sqlite3")))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    clock = [_TIME]
    capture = _Capture()
    with factory.begin() as session:
        existing_hash = hash_password(_PASSWORD)
        session.add_all(
            [
                Account(
                    id="owner", email=_EMAIL, password_hash=existing_hash, email_verified_at=_TIME
                ),
                Account(id="pending", email=_UNVERIFIED, password_hash=existing_hash),
            ]
        )
    runtime = AuthRuntime(
        session_factory=factory,
        rate_limiter=_Limiter(),
        signing_key="synthetic-password-reset-signing-value",
        issuer="test-issuer",
        audience="test-audience",
        dummy_password_hash=hash_password("Non-user synthetic password"),
        totp_encryption_key=b"T" * 32,
        totp_key_version=1,
        session_lifetime=timedelta(minutes=30),
        mfa_challenge_lifetime=timedelta(minutes=5),
        now=lambda: clock[0],
        common_passwords=frozenset({_BLOCKED_PASSWORD}),
        password_lookup=lambda _prefix, _headers: f"{'0' * 35}:0",
        report_password_outage=lambda _event: None,
        email_sender=capture,
    )
    try:
        yield runtime, factory, clock, capture
    finally:
        engine.dispose()


def _client(runtime):
    return TestClient(create_app(_SETTINGS, auth_runtime=runtime), base_url=_ORIGIN)


def _headers(response):
    return {"Origin": _ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]}


def _request(client, email=_EMAIL):
    return client.post(_REQUEST, json={"email": email}, headers=_headers(client.get(_STATUS)))


def _confirm(client, code, password=_NEW_PASSWORD, **fields):
    payload = {"email": _EMAIL, "code": code, "new_password": password, **fields}
    return client.post(_CONFIRM, json=payload, headers=_headers(client.get(_STATUS)))


def _login(client, password=_PASSWORD):
    return client.post(
        _LOGIN, json={"email": _EMAIL, "password": password}, headers=_headers(client.get(_STATUS))
    )


def _enroll(client, now):
    headers = _headers(_login(client))
    setup = client.post("/v1/users/me/totp/setup", headers=headers, json={"password": _PASSWORD})
    seed = setup.json()["secret"]
    confirmed = client.post(
        "/v1/users/me/totp/confirm", headers=headers, json={"code": pyotp.TOTP(seed).at(now)}
    )
    return seed, confirmed.json()["recovery_codes"]


def _assert_error(response, status, code):
    assert response.status_code == status
    assert response.json()["error"]["code"] == code
    assert response.headers["cache-control"] == "no-store"
    assert "set-cookie" not in response.headers


def test_generic_admission_and_verified_only_digest_storage(environment):
    runtime, factory, clock, capture = environment
    client = _client(runtime)
    for email in (_UNKNOWN, _UNVERIFIED, f" {_EMAIL.upper()} "):
        response = _request(client, email)
        assert response.status_code == 202
        assert response.json() == {"requested": True}
        assert response.headers["cache-control"] == "no-store"
        assert "set-cookie" not in response.headers
    [(email, code)] = capture.messages
    assert email == _EMAIL and re.fullmatch(r"[a-f0-9]{32}", code)

    with factory() as session:
        [proof] = session.scalars(select(PasswordResetProof)).all()
        assert proof.account_id == "owner"
        assert proof.digest == sha256(code.encode()).hexdigest()
        assert proof.expires_at == clock[0] + timedelta(minutes=15)


def test_reset_rejects_expired_and_reused_proofs_and_revokes_other_codes_and_sessions(environment):
    runtime, factory, clock, capture = environment
    existing = _client(runtime)
    assert _login(existing).json()["authenticated"]
    client = _client(runtime)
    assert _request(client).status_code == 202
    expired = capture.messages[-1][1]
    clock[0] += timedelta(minutes=15)
    _assert_error(_confirm(client, expired), 401, "invalid_reset")
    assert _request(client).status_code == 202
    assert _request(client).status_code == 202
    code, other = [message[1] for message in capture.messages[-2:]]
    _assert_error(_confirm(client, code, _PASSWORD), 400, "password_rejected")
    result = _confirm(client, code)
    assert result.status_code == 200 and result.json() == {"changed": True}
    assert result.headers["cache-control"] == "no-store"
    assert "set-cookie" not in result.headers
    assert not client.get(_STATUS).json()["authenticated"]
    assert not existing.get(_STATUS).json()["authenticated"]
    for invalid in (code, other):
        _assert_error(_confirm(client, invalid), 401, "invalid_reset")
    assert _login(client, _PASSWORD).status_code == 401
    assert _login(client, _NEW_PASSWORD).json()["authenticated"]
    with factory() as session:
        assert verify_password(_NEW_PASSWORD, session.get(Account, "owner").password_hash)
        assert (
            session.scalar(
                select(AccountSession.revoked_at).where(AccountSession.revoked_at.is_not(None))
            )
            == clock[0]
        )


def test_origin_csrf_payload_and_ip_identity_limits_apply_to_both_routes(environment):
    runtime, _, _, capture = environment
    limiter = LocalRateLimiter(_SETTINGS)
    client = _client(replace(runtime, rate_limiter=limiter))
    headers = _headers(client.get(_STATUS))
    for path, body in (
        (_REQUEST, {"email": _EMAIL}),
        (_CONFIRM, {"email": _EMAIL, "code": "0" * 32, "new_password": _NEW_PASSWORD}),
    ):
        _assert_error(client.post(path, json=body), 403, "origin_or_csrf")
        _assert_error(
            client.post(path, json=body, headers={**headers, "Origin": "https://invalid.test"}),
            403,
            "origin_or_csrf",
        )
        _assert_error(
            client.post(path, json=body, headers={**headers, "X-CSRF-Token": "X" * 43}),
            403,
            "origin_or_csrf",
        )
        _assert_error(
            client.post(path, json={**body, "padding": "x" * 16_384}, headers=headers),
            400,
            "invalid_request",
        )

    issued = client.post(_REQUEST, json={"email": _EMAIL}, headers=headers)
    assert issued.status_code == 202
    _assert_error(
        client.post(_REQUEST, json={"email": f" {_EMAIL.upper()} "}, headers=headers),
        429,
        "rate_limited",
    )
    assert len(capture.messages) == 1
    for _ in range(5):
        _assert_error(_confirm(client, "0" * 32), 401, "invalid_reset")
    _assert_error(_confirm(client, "0" * 32, email=_EMAIL.upper()), 429, "rate_limited")


def test_reset_per_ip_limits_span_different_addresses(environment):
    runtime, _, _, _ = environment
    client = _client(replace(runtime, rate_limiter=LocalRateLimiter(_SETTINGS)))
    headers = _headers(client.get(_STATUS))
    for i in range(11):
        issued = client.post(_REQUEST, headers=headers, json={"email": f"request-{i}@example.test"})
        if i < 10:
            assert issued.status_code == 202
        else:
            _assert_error(issued, 429, "rate_limited")
    for i in range(31):
        confirmed = client.post(
            _CONFIRM,
            headers=headers,
            json={
                "email": f"confirm-{i}@example.test",
                "code": "0" * 32,
                "new_password": _NEW_PASSWORD,
            },
        )
        if i < 30:
            _assert_error(confirmed, 401, "invalid_reset")
        else:
            _assert_error(confirmed, 429, "rate_limited")


def test_mfa_must_validate_before_policy_and_totp_cannot_be_replayed(environment):
    runtime, factory, clock, capture = environment
    seen = []
    runtime = replace(
        runtime, password_lookup=lambda prefix, _headers: seen.append(prefix) or f"{'0' * 35}:0"
    )
    normal = _client(runtime)
    seed, _ = _enroll(normal, clock[0])
    clock[0] += timedelta(seconds=30)
    login = _login(normal)
    assert login.json()["mfa_required"]
    client = _client(runtime)
    _request(client)
    code = capture.messages[-1][1]
    _assert_error(_confirm(client, code, _BLOCKED_PASSWORD), 401, "invalid_reset")
    assert seen == []
    totp = pyotp.TOTP(seed).at(clock[0])
    wrong = f"{(int(totp) + 1) % 1_000_000:06d}"
    _assert_error(_confirm(client, code, mfa_code=wrong), 401, "invalid_reset")
    assert seen == []
    _assert_error(
        _confirm(client, code, _BLOCKED_PASSWORD, mfa_code=totp), 400, "password_rejected"
    )
    assert _confirm(client, code, mfa_code=totp).status_code == 200
    with factory() as session:
        assert (
            session.get(AccountTotp, "owner").last_accepted_step == int(clock[0].timestamp()) // 30
        )
        assert session.scalar(select(MfaLoginChallenge)) is None
    next_login = _login(client, _NEW_PASSWORD)
    payload = {"email": _EMAIL, "password": _NEW_PASSWORD, "code": totp}
    _assert_error(
        client.post(_MFA, headers=_headers(next_login), json=payload), 401, "unauthorized"
    )
    clock[0] += timedelta(seconds=30)
    payload["code"] = pyotp.TOTP(seed).at(clock[0])
    assert client.post(_MFA, headers=_headers(next_login), json=payload).json()["authenticated"]


def test_last_backup_is_reserved_for_existing_mfa_replacement_only(environment):
    runtime, factory, clock, capture = environment
    client = _client(runtime)
    original_seed, codes = _enroll(client, clock[0])
    last = codes[-1]
    with factory.begin() as session:
        session.execute(
            delete(MfaRecoveryCode).where(
                MfaRecoveryCode.digest != sha256(last.encode()).hexdigest()
            )
        )
        prior = session.get(AccountTotp, "owner").encrypted_secret
    _request(client)
    assert _confirm(client, capture.messages[-1][1], mfa_code=last).status_code == 200
    _request(client)
    _assert_error(_confirm(client, capture.messages[-1][1], mfa_code=last), 401, "invalid_reset")
    with factory() as session:
        assert session.get(AccountTotp, "owner").encrypted_secret == prior
    headers = _headers(_login(client, _NEW_PASSWORD))
    recovery = {"email": _EMAIL, "password": _NEW_PASSWORD, "recovery_code": last}
    setup = client.post(f"{_RECOVER}/setup", headers=headers, json=recovery)
    data = setup.json()
    assert data["secret"] != original_seed
    confirmation = client.post(
        f"{_RECOVER}/confirm",
        headers=headers,
        json={
            **recovery,
            "setup_token": data["setup_token"],
            "code": pyotp.TOTP(data["secret"]).at(clock[0]),
        },
    )
    assert confirmation.status_code == 200
    assert last not in confirmation.json()["recovery_codes"]
    with factory() as session:
        assert session.get(MfaRecoveryCode, ("owner", sha256(last.encode()).hexdigest())) is None


def test_parallel_confirmations_accept_exactly_one_password(environment):
    runtime, factory, _, capture = environment
    barrier = Barrier(2, timeout=5)

    def concurrent_screen(_prefix, _headers):
        barrier.wait()
        return f"{'0' * 35}:0"

    runtime = replace(runtime, password_lookup=concurrent_screen)
    assert _request(_client(runtime)).status_code == 202
    code = capture.messages[-1][1]
    passwords = (_NEW_PASSWORD, "Another different synthetic reset password")
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(
            executor.map(lambda password: _confirm(_client(runtime), code, password), passwords)
        )
    assert sorted(result.status_code for result in outcomes) == [200, 401]
    winner = passwords[
        next(index for index, result in enumerate(outcomes) if result.status_code == 200)
    ]
    with factory() as session:
        assert verify_password(winner, session.get(Account, "owner").password_hash)


def test_admission_body_precedes_mail_with_no_account_lock_during_delivery(environment):
    runtime, factory, _, _ = environment
    release_mail = Event()
    mail_started = Event()
    observations = []

    class _Mail:
        def send_password_reset(self, _email, _code):
            with factory.begin() as session:
                assert session.scalar(select(PasswordResetProof.account_id)) == "owner"
                session.execute(update(Account).where(Account.id == "owner").values(email=_EMAIL))
            observations.append("mail-running")
            mail_started.set()
            if not release_mail.wait(timeout=5):
                raise RuntimeError("Synthetic SMTP did not finish")

    async def run():
        app = create_app(_SETTINGS, auth_runtime=replace(runtime, email_sender=_Mail()))
        body = json.dumps({"email": _EMAIL}).encode()
        csrf = "a" * 43
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": _REQUEST,
            "query_string": b"",
            "client": ("192.0.2.1", 1234),
            "headers": [
                (b"origin", _ORIGIN.encode()),
                (b"content-type", b"application/json"),
                (b"x-csrf-token", csrf.encode()),
                (b"cookie", f"{CSRF_COOKIE}={csrf}".encode()),
            ],
        }
        sent_request = False
        messages = []

        async def receive():
            nonlocal sent_request
            if sent_request:
                await asyncio.Event().wait()
            sent_request = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            messages.append(message)
            if message["type"] == "http.response.body" and not message.get("more_body"):
                observations.append("admission-complete")

        task = asyncio.create_task(app(scope, receive, send))
        try:
            assert await asyncio.to_thread(mail_started.wait, 3)
            assert messages[0]["status"] == 202
            assert observations == ["admission-complete", "mail-running"]
            assert not task.done()
        finally:
            release_mail.set()
            await asyncio.wait_for(task, timeout=3)

    asyncio.run(run())


def test_reset_loses_to_authenticated_password_change_during_screening(environment):
    runtime, factory, _, capture = environment
    entered = Event()
    release = Event()
    reset_prefix = sha1(_NEW_PASSWORD.encode(), usedforsecurity=False).hexdigest()[:5].upper()
    change_password = "The authenticated password change value"

    def screen(prefix, _headers):
        if prefix == reset_prefix:
            entered.set()
            if not release.wait(timeout=5):
                raise RuntimeError("Synthetic password screening did not finish")
        return f"{'0' * 35}:0"

    runtime = replace(runtime, password_lookup=screen)
    owner = _client(runtime)
    headers = _headers(_login(owner))
    client = _client(runtime)
    assert _request(client).status_code == 202
    code = capture.messages[-1][1]
    with ThreadPoolExecutor(max_workers=1) as executor:
        outcome = executor.submit(_confirm, client, code)
        try:
            assert entered.wait(timeout=3)
            response = owner.post(
                "/v1/users/me/password",
                headers=headers,
                json={"current_password": _PASSWORD, "new_password": change_password},
            )
            assert response.status_code == 200
        finally:
            release.set()
        _assert_error(outcome.result(timeout=3), 401, "invalid_reset")
    with factory() as session:
        assert session.scalar(select(PasswordResetProof)) is None
        assert verify_password(change_password, session.get(Account, "owner").password_hash)


def test_reset_rechecks_expiration_after_password_screening(environment):
    runtime, factory, clock, capture = environment

    def screen(_prefix, _headers):
        clock[0] += timedelta(minutes=15)
        return f"{'0' * 35}:0"

    client = _client(replace(runtime, password_lookup=screen))
    assert _request(client).status_code == 202
    _assert_error(_confirm(client, capture.messages[-1][1]), 401, "invalid_reset")
    with factory() as session:
        assert verify_password(_PASSWORD, session.get(Account, "owner").password_hash)


def test_failed_reset_update_rolls_back_mfa_step_password_proof_and_session(environment):
    runtime, factory, clock, capture = environment
    client = _client(runtime)
    seed, _ = _enroll(client, clock[0])
    clock[0] += timedelta(seconds=30)
    login = _login(client)
    assert client.post(
        _MFA,
        headers=_headers(login),
        json={"email": _EMAIL, "password": _PASSWORD, "code": pyotp.TOTP(seed).at(clock[0])},
    ).json()["authenticated"]
    clock[0] += timedelta(seconds=30)
    assert _request(client).status_code == 202
    code = capture.messages[-1][1]
    engine = factory.kw["bind"]

    def fail_last_write(_conn, _cursor, sql, _params, _context, _executemany):
        if sql.startswith("DELETE FROM pending_totp"):
            raise RuntimeError("Synthetic database failure after proof and session changes")

    event.listen(engine, "before_cursor_execute", fail_last_write)
    try:
        _assert_error(
            _confirm(client, code, mfa_code=pyotp.TOTP(seed).at(clock[0])), 503, "auth_unavailable"
        )
    finally:
        event.remove(engine, "before_cursor_execute", fail_last_write)
    with factory() as session:
        assert verify_password(_PASSWORD, session.get(Account, "owner").password_hash)
        assert session.get(PasswordResetProof, sha256(code.encode()).hexdigest()) is not None
        assert (
            session.get(AccountTotp, "owner").last_accepted_step < int(clock[0].timestamp()) // 30
        )
    assert client.get(_STATUS).json()["authenticated"]
    assert _confirm(client, code, mfa_code=pyotp.TOTP(seed).at(clock[0])).status_code == 200


def test_joint_maintenance_removes_expired_reset_proofs_only(environment, monkeypatch, capsys):
    runtime, factory, clock, capture = environment
    client = _client(runtime)
    _request(client)
    clock[0] += timedelta(minutes=1)
    _request(client)
    active_digest = sha256(capture.messages[-1][1].encode()).hexdigest()
    clock[0] += timedelta(minutes=14)
    monkeypatch.setattr("metaguard_api.maintenance.time.time", lambda: clock[0].timestamp())
    assert purge_maintenance_for_api(database=Database(factory.kw["bind"])) == 0
    assert "Purged 1 expired password reset proofs." in capsys.readouterr().out
    with factory() as session:
        assert session.scalars(select(PasswordResetProof.digest)).all() == [active_digest]
