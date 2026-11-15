import subprocess
import sys

import pytest
from sqlalchemy import create_engine

from metaguard_api.database import Base, Database
from metaguard_api.maintenance import main
from metaguard_api.reputation_cache import CacheVerdict, get_verdict, save_verdict


def test_command_help_is_available_without_database() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "metaguard_api.maintenance", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "purge-reputation" in result.stdout


def test_invalid_command_never_opens_database(monkeypatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Database must not be opened")

    monkeypatch.setattr("metaguard_api.maintenance.create_database", fail)
    with pytest.raises(SystemExit) as result:
        main(["not-a-command"])
    assert result.value.code == 2


def test_purge_command_commits_only_expired_entries(tmp_path, monkeypatch, capsys) -> None:
    url = f"sqlite:///{tmp_path / 'cache.sqlite'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    db = Database(engine)
    with db.transaction() as session:
        save_verdict(session, "a" * 64, CacheVerdict.NO_RECORD, now=100)
        save_verdict(session, "b" * 64, CacheVerdict.MALICIOUS, now=200)
    monkeypatch.setattr("metaguard_api.maintenance.create_database", lambda *_args, **_kwargs: db)
    monkeypatch.setattr("metaguard_api.maintenance.time.time", lambda: 86_500)

    assert main(["purge-reputation"]) == 0
    assert "1" in capsys.readouterr().out
    check_db = Database(create_engine(url))
    with check_db.transaction() as session:
        assert get_verdict(session, "a" * 64, now=100) is None
        assert get_verdict(session, "b" * 64, now=200) == CacheVerdict.MALICIOUS
    check_db.close()


def test_purge_failure_rolls_back_and_hides_details(tmp_path, monkeypatch, capsys) -> None:
    url = f"sqlite:///{tmp_path / 'cache.sqlite'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    db = Database(engine)
    with db.transaction() as session:
        save_verdict(session, "a" * 64, CacheVerdict.NO_RECORD, now=100)

    def fail_after_delete(session, *, now):
        from metaguard_api.reputation_cache import purge_expired

        purge_expired(session, now=now)
        raise RuntimeError("sensitive error details")

    monkeypatch.setattr("metaguard_api.maintenance.create_database", lambda *_args, **_kwargs: db)
    monkeypatch.setattr("metaguard_api.maintenance.purge_expired", fail_after_delete)
    monkeypatch.setattr("metaguard_api.maintenance.time.time", lambda: 100_000)
    assert main(["purge-reputation"]) == 1
    assert "sensitive" not in capsys.readouterr().err
    check_db = Database(create_engine(url))
    with check_db.transaction() as session:
        assert get_verdict(session, "a" * 64, now=100) == CacheVerdict.NO_RECORD
    check_db.close()
