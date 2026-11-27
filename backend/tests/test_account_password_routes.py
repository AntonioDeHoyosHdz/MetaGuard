from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha1
from threading import Barrier, Event
from uuid import uuid4

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import URL, create_engine, event, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from metaguard_api.account_credentials import hash_password, verify_password
from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account, AccountSession
from metaguard_api.auth_routes import CSRF_COOKIE, MFA_COOKIE, SESSION_COOKIE, AuthRuntime
from metaguard_api.database import Base
from metaguard_api.main import create_app
from metaguard_api.mfa_lifecycle import MfaRecoveryCode
from metaguard_api.pwned_passwords import RangeServiceUnavailable
from metaguard_api.sessions import MfaLoginChallenge
from metaguard_api.settings import Settings

_ORIGIN = "https://app.example.test"
_EMAIL = "synthetic@example.test"
_OTHER_EMAIL = "other@example.test"
_PASSWORD = "The account's existing synthetic password"
_NEW = "An unrelated replacement synthetic password"
_BLOCKED = "A synthetic password in the local blocklist"
_TIME = datetime(2026, 11, 20, tzinfo=UTC)
_CHANGE = "/v1/users/me/password"
_LOGIN = "/v1/auth/login"
_MFA = "/v1/auth/login/mfa"
_STATUS = "/v1/auth/status"


class Limiter:
    def __init__(self):
        self.denied = set()

    def allow(self, action, _ip, _identity):
        return action not in self.denied


@pytest.fixture
def env(tmp_path):
    engine = create_engine(URL.create("sqlite", database=str(tmp_path / "test.sqlite3")))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    owner = str(uuid4())
    other = str(uuid4())
    existing_hash = hash_password(_PASSWORD)
    with factory.begin() as session:
        session.add_all(
            (
                Account(
                    id=account_id, email=email, password_hash=existing_hash, email_verified_at=_TIME
                )
                for account_id, email in ((owner, _EMAIL), (other, _OTHER_EMAIL))
            )
        )
    runtime = AuthRuntime(
        session_factory=factory,
        rate_limiter=Limiter(),
        signing_key="synthetic-account-password-signing-value",
        issuer="test-issuer",
        audience="test-audience",
        dummy_password_hash=hash_password("Different synthetic password"),
        totp_encryption_key=b"T" * 32,
        totp_key_version=1,
        session_lifetime=timedelta(minutes=15),
        mfa_challenge_lifetime=timedelta(minutes=5),
        now=lambda: _TIME,
        common_passwords=frozenset({_BLOCKED}),
        password_lookup=lambda _prefix, _headers: f"{'0' * 35}:0",
        report_password_outage=lambda _event: None,
    )
    try:
        yield runtime, factory, owner, other
    finally:
        engine.dispose()


def _client(runtime):
    return TestClient(
        create_app(
            Settings(environment="test", auth_allowed_origins=(_ORIGIN,)), auth_runtime=runtime
        ),
        base_url=_ORIGIN,
    )


def _headers(response):
    return {"Origin": _ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]}


def _login(client, password=_PASSWORD, email=_EMAIL):
    return client.post(
        _LOGIN, headers=_headers(client.get(_STATUS)), json={"email": email, "password": password}
    )


def _change(client, headers, *, current=_PASSWORD, new=_NEW):
    return client.post(
        _CHANGE, headers=headers, json={"current_password": current, "new_password": new}
    )


def _mfa_login(client, seed, now, password=_PASSWORD):
    first = _login(client, password)
    code = pyotp.TOTP(seed).at(now)
    return client.post(
        _MFA,
        headers=_headers(first),
        json={"email": _EMAIL, "password": password, "code": code},
    )


def _enroll(client, now):
    headers = _headers(_login(client))
    setup = client.post("/v1/users/me/totp/setup", headers=headers, json={"password": _PASSWORD})
    seed = setup.json()["secret"]
    confirmed = client.post(
        "/v1/users/me/totp/confirm", headers=headers, json={"code": pyotp.TOTP(seed).at(now)}
    )
    assert confirmed.status_code == 200
    return seed, confirmed.json()["recovery_codes"]


def _assert_error(result, status, code):
    assert result.status_code == status
    assert result.json()["error"]["code"] == code
    assert result.headers["cache-control"] == "no-store"
    assert "set-cookie" not in result.headers


def test_password_change_revokes_every_owner_session_and_challenge_without_touching_mfa(env):
    runtime, factory, owner, other = env
    clock = [_TIME]
    runtime = replace(runtime, now=lambda: clock[0])
    enrolled = _client(runtime)
    seed, _ = _enroll(enrolled, clock[0])
    first = _client(runtime)
    second = _client(runtime)
    challenge_client = _client(runtime)
    other_client = _client(runtime)
    clock[0] += timedelta(seconds=30)
    headers = _headers(_mfa_login(first, seed, clock[0]))
    clock[0] += timedelta(seconds=30)
    assert _mfa_login(second, seed, clock[0]).status_code == 200
    assert _login(other_client, email=_OTHER_EMAIL).json()["authenticated"]
    challenge_headers = _headers(_login(challenge_client))
    assert challenge_client.cookies.get(MFA_COOKIE)
    with factory() as session:
        prior_codes = set(session.scalars(select(MfaRecoveryCode.digest)))
        prior_totp = session.get(AccountTotp, owner)
        prior_secret = prior_totp.encrypted_secret
        prior_email_verified_at = session.get(Account, owner).email_verified_at
        assert session.scalar(select(MfaLoginChallenge.account_id)) == owner

    result = _change(first, headers)
    assert result.status_code == 200
    assert result.json() == {"changed": True}
    assert result.headers["cache-control"] == "no-store"
    assert len(result.headers.get_list("set-cookie")) == 3
    for cookie in (SESSION_COOKIE, CSRF_COOKIE, MFA_COOKIE):
        assert any(
            header.startswith(cookie + '=""') and "Max-Age=0" in header
            for header in result.headers.get_list("set-cookie")
        )
    assert not second.get(_STATUS).json()["authenticated"]
    assert other_client.get(_STATUS).json()["authenticated"]
    clock[0] += timedelta(seconds=30)
    _assert_error(
        challenge_client.post(
            _MFA,
            headers=challenge_headers,
            json={"email": _EMAIL, "password": _NEW, "code": pyotp.TOTP(seed).at(clock[0])},
        ),
        401,
        "unauthorized",
    )
    _assert_error(_login(first), 401, "unauthorized")
    assert _mfa_login(first, seed, clock[0], _NEW).json()["authenticated"]
    with factory() as session:
        account = session.get(Account, owner)
        assert account.email_verified_at == prior_email_verified_at
        assert verify_password(_NEW, account.password_hash)
        assert not verify_password(_PASSWORD, account.password_hash)
        assert verify_password(_PASSWORD, session.get(Account, other).password_hash)
        assert session.get(AccountTotp, owner).encrypted_secret == prior_secret
        assert set(session.scalars(select(MfaRecoveryCode.digest))) == prior_codes
        assert list(session.scalars(select(MfaLoginChallenge))) == []


def test_mfa_login_and_recovery_touch_only_the_owner_account_before_consuming_challenge(env):
    runtime, factory, owner, other = env
    clock = [_TIME]
    runtime = replace(runtime, now=lambda: clock[0])
    client = _client(runtime)
    seed, recovery_codes = _enroll(client, clock[0])
    clock[0] += timedelta(seconds=30)
    headers = _headers(_login(client))
    engine = factory.kw["bind"]
    statements = []

    def capture_sql(_conn, _cursor, statement, parameters, *_rest):
        statements.append((statement, parameters))

    event.listen(engine, "before_cursor_execute", capture_sql)
    code = pyotp.TOTP(seed).at(clock[0])
    _assert_error(
        client.post(
            _MFA, headers=headers, json={"email": _OTHER_EMAIL, "password": _PASSWORD, "code": code}
        ),
        401,
        "unauthorized",
    )
    assert any(sql.startswith("UPDATE accounts") and owner in args for sql, args in statements)
    assert not any(other in args or _OTHER_EMAIL in args for _, args in statements)
    assert not any(sql.startswith("DELETE FROM mfa_login_challenges") for sql, _ in statements)

    statements.clear()
    assert client.post(
        _MFA, headers=headers, json={"email": _EMAIL, "password": _PASSWORD, "code": code}
    ).json()["authenticated"]
    lock_index = next(
        i for i, (sql, _) in enumerate(statements) if sql.startswith("UPDATE accounts")
    )
    consume_index = next(
        i
        for i, (sql, _) in enumerate(statements)
        if sql.startswith("DELETE FROM mfa_login_challenges")
    )
    assert lock_index < consume_index

    recovery = _client(runtime)
    headers = _headers(_login(recovery))
    proof = {"email": _EMAIL, "password": _PASSWORD, "recovery_code": recovery_codes[0]}
    setup = recovery.post("/v1/auth/mfa/recovery/setup", json=proof, headers=headers)
    assert setup.status_code == 200
    new_seed = setup.json()["secret"]
    statements.clear()
    confirmed = recovery.post(
        "/v1/auth/mfa/recovery/confirm",
        headers=headers,
        json={
            **proof,
            "setup_token": setup.json()["setup_token"],
            "code": pyotp.TOTP(new_seed).at(clock[0]),
        },
    )
    assert confirmed.status_code == 200
    owner_read_index = next(
        i
        for i, (sql, args) in enumerate(statements)
        if "FROM accounts" in sql and sql.startswith("SELECT") and owner in args
    )
    consume_index = next(
        i
        for i, (sql, _) in enumerate(statements)
        if sql.startswith("DELETE FROM mfa_login_challenges")
    )
    assert owner_read_index < consume_index


def test_bad_request_origin_csrf_credentials_or_policy_do_not_mutate_state(env):
    runtime, factory, owner, _ = env
    looked_up = []
    runtime = replace(runtime, password_lookup=lambda prefix, _headers: looked_up.append(prefix))
    client = _client(runtime)
    anonymous = _headers(client.get(_STATUS))
    _assert_error(_change(client, anonymous), 401, "unauthorized")
    headers = _headers(_login(client))
    _assert_error(
        _change(client, {**headers, "Origin": "https://other.example"}), 403, "origin_or_csrf"
    )
    _assert_error(_change(client, {"Origin": _ORIGIN}), 403, "origin_or_csrf")
    _assert_error(_change(client, headers, current="wrong"), 401, "unauthorized")
    _assert_error(_change(client, headers, new=_PASSWORD), 400, "password_rejected")
    _assert_error(_change(client, headers, new=_BLOCKED), 400, "password_rejected")
    _assert_error(_change(client, headers, new="short"), 400, "password_rejected")
    _assert_error(_change(client, headers, new="🙂" * 257), 400, "password_rejected")
    for data in (
        '{"current_password":"reflected-secret","new_password":',
        '{"current_password":"reflected-secret","extra":true}',
        '{"current_password":"reflected-secret","new_password":"' + ("x" * 20_000) + '"}',
    ):
        response = client.post(
            _CHANGE, headers={**headers, "Content-Type": "application/json"}, content=data
        )
        _assert_error(response, 400, "invalid_request")
        assert "reflected-secret" not in response.text
    assert looked_up == []
    assert client.get(_STATUS).json()["authenticated"]
    with factory() as session:
        assert verify_password(_PASSWORD, session.get(Account, owner).password_hash)


def test_reputation_check_respects_breaches_and_recorded_fallback(env):
    runtime, _, _, _ = env
    suffix = sha1(_NEW.encode(), usedforsecurity=False).hexdigest().upper()[5:]
    pwned = _client(replace(runtime, password_lookup=lambda _prefix, _headers: f"{suffix}:42"))
    _assert_error(_change(pwned, _headers(_login(pwned))), 400, "password_rejected")

    def outage(_prefix, _headers):
        raise RangeServiceUnavailable("synthetic outage")

    def unavailable(_evt):
        raise RuntimeError("private database error")

    missing = _client(replace(runtime, common_passwords=None))
    _assert_error(_change(missing, _headers(_login(missing))), 503, "auth_unavailable")
    failed = _client(replace(runtime, password_lookup=outage, report_password_outage=unavailable))
    result = _change(failed, _headers(_login(failed)))
    _assert_error(result, 503, "auth_unavailable")
    assert "private database error" not in result.text

    events = []
    reduced = _client(
        replace(runtime, password_lookup=outage, report_password_outage=events.append)
    )
    assert _change(reduced, _headers(_login(reduced))).status_code == 200
    assert events == ["password_breach_check_unavailable"]


def test_rate_limiter_blocks_before_password_screening_or_hashing(env, monkeypatch):
    from metaguard_api import account_credentials

    runtime, _, _, _ = env
    client = _client(runtime)
    headers = _headers(_login(client))
    calls = []
    monkeypatch.setattr(account_credentials._HASHER.__class__, "verify", lambda *_: calls.append(1))
    for action in ("account_password_change_ip", "account_password_change_account"):
        runtime.rate_limiter.denied = {action}
        _assert_error(_change(client, headers), 429, "rate_limited")
    assert calls == []


def test_failure_during_challenge_revocation_rolls_back_password_and_session_revocation(env):
    runtime, factory, owner, _ = env
    client = _client(runtime)
    headers = _headers(_login(client))
    engine = factory.kw["bind"]

    def fail_delete(_conn, _cursor, statement, *_rest):
        if statement.startswith("DELETE FROM mfa_login_challenges"):
            raise SQLAlchemyError("synthetic revocation failure")

    event.listen(engine, "before_cursor_execute", fail_delete)
    result = _change(client, headers)
    _assert_error(result, 503, "auth_unavailable")
    assert "revocation failure" not in result.text
    assert client.get(_STATUS).json()["authenticated"]
    with factory() as session:
        assert verify_password(_PASSWORD, session.get(Account, owner).password_hash)
        assert all(row.revoked_at is None for row in session.scalars(select(AccountSession)))


def test_two_password_changes_with_same_old_password_cannot_both_commit(env):
    runtime, factory, owner, _ = env
    barrier = Barrier(2, timeout=5)

    def screen(_prefix, _headers):
        barrier.wait()
        return f"{'0' * 35}:0"

    runtime = replace(runtime, password_lookup=screen)
    clients = [_client(runtime), _client(runtime)]
    headers = [_headers(_login(client)) for client in clients]
    new_passwords = [_NEW, "Another synthetic competing password"]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(_change, client, header, new=password)
            for client, header, password in zip(clients, headers, new_passwords, strict=True)
        ]
        responses = [future.result(timeout=10) for future in futures]
    assert sorted(response.status_code for response in responses) == [200, 401]
    winner = next(index for index, response in enumerate(responses) if response.status_code == 200)
    with factory() as session:
        assert verify_password(new_passwords[winner], session.get(Account, owner).password_hash)


def test_session_revoked_during_screening_cannot_change_password(env):
    runtime, factory, owner, _ = env
    started, done = Event(), Event()

    def screen(_prefix, _headers):
        started.set()
        if not done.wait(timeout=5):
            raise RuntimeError("Test screening timed out")
        return f"{'0' * 35}:0"

    runtime = replace(runtime, password_lookup=screen)
    client = _client(runtime)
    headers = _headers(_login(client))
    logout = _client(runtime)
    for cookie in (SESSION_COOKIE, CSRF_COOKIE):
        logout.cookies.set(cookie, client.cookies.get(cookie), domain="app.example.test", path="/")
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_change, client, headers)
        try:
            assert started.wait(timeout=5)
            assert logout.post("/v1/auth/logout", headers=headers).status_code == 200
        finally:
            done.set()
        result = future.result(timeout=5)
    _assert_error(result, 401, "unauthorized")
    with factory() as session:
        assert verify_password(_PASSWORD, session.get(Account, owner).password_hash)
