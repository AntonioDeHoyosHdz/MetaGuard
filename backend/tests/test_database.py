from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, text

from metaguard_api.database import Database, DatabaseSettings, create_database
from metaguard_api.secrets import SecretUnavailable


def test_transactions_commit_and_rollback() -> None:
    database = Database(create_engine("sqlite://"))
    with database.transaction() as session:
        session.execute(text("CREATE TABLE entries (value INTEGER)"))
        session.execute(text("INSERT INTO entries VALUES (1)"))
    with pytest.raises(RuntimeError), database.transaction() as session:
        session.execute(text("INSERT INTO entries VALUES (2)"))
        raise RuntimeError("abort")
    with database.transaction() as session:
        assert session.execute(text("SELECT value FROM entries")).scalars().all() == [1]
    database.close()


def test_password_is_read_from_file_without_url_interpolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = "test:@/password#?"
    (tmp_path / "postgres_password").write_text(password, encoding="utf-8")
    captured = {}

    def fake_engine(url, **kwargs):
        captured.update(url=url, options=kwargs)
        return create_engine("sqlite://")

    monkeypatch.setattr("metaguard_api.database.create_engine", fake_engine)
    settings = DatabaseSettings(secret_dir=tmp_path, _env_file=None)
    database = create_database(settings)
    assert captured["url"].password == password
    assert password not in repr(captured["url"])
    assert captured["options"]["hide_parameters"] is True
    assert captured["options"]["echo"] is False
    assert password not in repr(settings)
    database.close()


def test_missing_password_prevents_engine_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("METAGUARD_DB_PASSWORD", "ignored-environment-password")
    with pytest.raises(SecretUnavailable):
        create_database(DatabaseSettings(secret_dir=tmp_path, _env_file=None))


@pytest.mark.parametrize("port", [0, 65536])
def test_invalid_port_is_rejected(port: int) -> None:
    with pytest.raises(ValidationError):
        DatabaseSettings(port=port, _env_file=None)
