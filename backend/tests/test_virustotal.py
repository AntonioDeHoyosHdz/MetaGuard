from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from urllib.error import HTTPError
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from metaguard_api.database import Base, Database
from metaguard_api.reputation_cache import (
    CacheVerdict,
    VirusTotalQuota,
    reserve_virustotal_request,
    save_verdict,
)
from metaguard_api.secrets import SecretName, SecretStore
from metaguard_api.virustotal import (
    VirusTotalClient,
    VirusTotalStatus,
    fetch_file_report,
)


class FakeResponse:
    status = 200

    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit):
        import json

        return json.dumps(self.payload).encode("utf-8")


class FakeOpener:
    def __init__(self, response):
        self.response = response
        self.request = None
        self.timeout = None

    def open(self, request, *, timeout):
        self.request = request
        self.timeout = timeout
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def payload():
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 2, "suspicious": 1, "undetected": 7},
                "last_analysis_date": 1_800_000_000,
                "meaningful_name": "must-not-escape.png",
                "names": ["private-name.png"],
            }
        }
    }


def test_fetches_only_fixed_hash_url_and_projects_minimal_result(monkeypatch):
    opener = FakeOpener(FakeResponse(payload()))
    key = uuid4().hex
    monkeypatch.setattr("metaguard_api.virustotal.build_opener", lambda *handlers: opener)
    digest = sha256(b"synthetic original").hexdigest()

    result = fetch_file_report(digest, key)

    assert opener.request.full_url == f"https://www.virustotal.com/api/v3/files/{digest}"
    assert opener.request.get_method() == "GET"
    assert opener.request.get_header("X-apikey") == key
    assert opener.timeout == 10
    assert result.status is VirusTotalStatus.FOUND
    assert result.last_analysis_stats == {"malicious": 2, "suspicious": 1, "undetected": 7}
    assert result.last_analysis_date == 1_800_000_000
    assert result.report_url == f"https://www.virustotal.com/gui/file/{digest}"
    assert "private-name" not in repr(result)


@pytest.mark.parametrize(
    ("code", "status"),
    [
        (404, VirusTotalStatus.NOT_FOUND),
        (401, VirusTotalStatus.KEY_UNAVAILABLE),
        (403, VirusTotalStatus.KEY_UNAVAILABLE),
        (429, VirusTotalStatus.RATE_LIMITED),
    ],
)
def test_http_errors_are_minimized(monkeypatch, code, status):
    opener = FakeOpener(HTTPError("https://www.virustotal.com/", code, "private body", {}, None))
    monkeypatch.setattr("metaguard_api.virustotal.build_opener", lambda *handlers: opener)

    result = fetch_file_report("a" * 64, uuid4().hex)

    assert result.status is status
    assert result.last_analysis_stats is None
    assert result.last_analysis_date is None
    assert "private body" not in repr(result)


def test_invalid_hash_and_network_errors_never_escape_or_use_user_url(monkeypatch):
    opener = FakeOpener(TimeoutError("private transport details"))
    monkeypatch.setattr("metaguard_api.virustotal.build_opener", lambda *handlers: opener)

    invalid = fetch_file_report("https://attacker.invalid/file", uuid4().hex)
    failed = fetch_file_report("b" * 64, uuid4().hex)

    assert invalid.status is VirusTotalStatus.UNAVAILABLE
    assert opener.request is not None
    assert opener.request.full_url == f"https://www.virustotal.com/api/v3/files/{'b' * 64}"
    assert failed.status is VirusTotalStatus.UNAVAILABLE
    assert "private transport details" not in repr(failed)


def test_cache_hit_reuses_minimized_verdict_without_a_second_request(tmp_path, monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    database = Database(engine)
    secret_store = SecretStore(tmp_path)
    calls = []
    monkeypatch.setattr(SecretStore, "read_text", lambda self, _name: uuid4().hex)

    def transport(digest, api_key):
        calls.append((digest, api_key))
        from metaguard_api.virustotal import VirusTotalResult

        return VirusTotalResult(
            status=VirusTotalStatus.FOUND,
            last_analysis_stats={"malicious": 1},
            last_analysis_date=1_800_000_000,
            report_url=f"https://www.virustotal.com/gui/file/{digest}",
        )

    client = VirusTotalClient(secret_store, transport=transport)
    digest = "c" * 64
    first = client.lookup(digest, database, now=1_800_000_000)
    second = client.lookup(digest, database, now=1_800_000_001)

    assert first.status is VirusTotalStatus.FOUND
    assert second.status is VirusTotalStatus.FOUND
    assert second.last_analysis_stats == {"malicious": 1}
    assert len(calls) == 1
    database.close()


def test_secret_is_read_only_through_allowlisted_secret_store(tmp_path, monkeypatch):
    key = uuid4().hex
    monkeypatch.setattr(
        SecretStore,
        "read_text",
        lambda self, name: key if name is SecretName.VIRUSTOTAL_API_KEY else "",
    )
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    database = Database(engine)
    seen = []

    def transport(digest, api_key):
        seen.append((digest, api_key))
        from metaguard_api.virustotal import VirusTotalResult

        return VirusTotalResult(
            status=VirusTotalStatus.FOUND,
            last_analysis_stats={"harmless": 5},
            last_analysis_date=1_800_000_000,
            report_url=f"https://www.virustotal.com/gui/file/{digest}",
        )

    client = VirusTotalClient(SecretStore(tmp_path), transport=transport)
    digest = "d" * 64
    result = client.lookup(digest, database, now=1_800_000_000)

    assert result.status is VirusTotalStatus.FOUND
    assert seen == [(digest, key)]
    assert key not in repr(result)
    database.close()


def test_missing_key_does_not_call_transport(tmp_path):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    database = Database(engine)
    calls = []
    client = VirusTotalClient(SecretStore(tmp_path), transport=lambda *args: calls.append(args))

    result = client.lookup("b" * 64, database, now=1_800_000_000)

    assert result.status is VirusTotalStatus.KEY_UNAVAILABLE
    assert calls == []
    database.close()


def test_global_quota_allows_four_per_minute_and_five_hundred_per_utc_day():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        assert [reserve_virustotal_request(session, now=1_800_000_001) for _ in range(5)] == [
            True,
            True,
            True,
            True,
            False,
        ]
        session.commit()
        assert reserve_virustotal_request(session, now=1_800_000_060) is False
        session.rollback()
        assert reserve_virustotal_request(session, now=1_800_000_061) is True
        session.commit()
        for index in range(495):
            assert reserve_virustotal_request(session, now=1_800_000_120 + index * 60) is True
        assert reserve_virustotal_request(session, now=1_800_000_120 + 495 * 60) is False
        session.rollback()
    engine.dispose()


def test_quota_resets_at_utc_day_and_rejects_clock_rollback():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        assert reserve_virustotal_request(session, now=1_800_000_100)
        session.commit()
        assert not reserve_virustotal_request(session, now=1_800_000_040)
        session.rollback()
        tomorrow = ((1_800_000_100 // 86_400) + 1) * 86_400
        assert reserve_virustotal_request(session, now=tomorrow)
    engine.dispose()


def test_parallel_quota_admission_is_shared_across_sessions(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'quota.sqlite'}", connect_args={"timeout": 10})
    Base.metadata.create_all(engine)

    def reserve():
        with Session(engine) as session:
            allowed = reserve_virustotal_request(session, now=1_800_000_001)
            session.commit()
            return allowed

    with ThreadPoolExecutor(max_workers=12) as workers:
        results = list(workers.map(lambda _index: reserve(), range(12)))

    assert sum(results) == 4
    engine.dispose()


def test_legacy_non_not_found_cache_row_is_refreshed_with_minimized_report(tmp_path, monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    database = Database(engine)
    digest = "e" * 64
    with database.transaction() as session:
        save_verdict(session, digest, CacheVerdict.MALICIOUS, now=1_800_000_000)
    monkeypatch.setattr(
        SecretStore,
        "read_text",
        lambda self, name: "test-key" if name is SecretName.VIRUSTOTAL_API_KEY else "",
    )
    calls = []

    def transport(file_hash, _api_key):
        calls.append(file_hash)
        from metaguard_api.virustotal import VirusTotalResult

        return VirusTotalResult(
            status=VirusTotalStatus.FOUND,
            last_analysis_stats={"malicious": 1},
            last_analysis_date=1_800_000_001,
            report_url=f"https://www.virustotal.com/gui/file/{file_hash}",
        )

    client = VirusTotalClient(
        SecretStore(tmp_path), transport=transport, clock=lambda: 1_800_000_001
    )
    result = client.lookup(digest, database, now=1_800_000_000)

    assert result.status is VirusTotalStatus.FOUND
    assert result.last_analysis_stats == {"malicious": 1}
    assert calls == [digest]
    database.close()


def test_quota_reservation_uses_current_clock_not_analysis_start(tmp_path, monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    database = Database(engine)
    monkeypatch.setattr(
        SecretStore,
        "read_text",
        lambda self, name: "test-key" if name is SecretName.VIRUSTOTAL_API_KEY else "",
    )
    from metaguard_api.virustotal import VirusTotalResult

    client = VirusTotalClient(
        SecretStore(tmp_path),
        transport=lambda digest, _key: VirusTotalResult(
            status=VirusTotalStatus.FOUND,
            last_analysis_stats={"harmless": 1},
            last_analysis_date=1_800_000_001,
            report_url=f"https://www.virustotal.com/gui/file/{digest}",
        ),
        clock=lambda: 1_800_000_020,
    )

    result = client.lookup("f" * 64, database, now=1_800_000_000)
    with database.transaction() as session:
        quota = session.get(VirusTotalQuota, 1)
        reserved_at = quota.recent_1

    assert result.status is VirusTotalStatus.FOUND
    assert reserved_at == 1_800_000_020
    database.close()
