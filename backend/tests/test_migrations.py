from io import StringIO
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from metaguard_api.database import Base


def config() -> Config:
    return Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))


def test_offline_migration_does_not_require_secrets() -> None:
    cfg = config()
    cfg.output_buffer = StringIO()
    command.upgrade(cfg, "head", sql=True)
    assert "BEGIN" in cfg.output_buffer.getvalue()
    assert "CREATE TABLE reputation_cache" in cfg.output_buffer.getvalue()
    assert "reputation_cache" in Base.metadata.tables


def test_alembic_runs_with_caller_owned_connection() -> None:
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            cfg = config()
            cfg.attributes["connection"] = connection
            command.upgrade(cfg, "head")
            command.check(cfg)
            assert "reputation_cache" in inspect(connection).get_table_names()
            command.downgrade(cfg, "base")
            assert "reputation_cache" not in inspect(connection).get_table_names()
    finally:
        engine.dispose()


def test_account_schema_migration() -> None:
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            cfg = config()
            cfg.attributes["connection"] = connection
            command.upgrade(cfg, "head")
            columns = {item["name"] for item in inspect(connection).get_columns("accounts")}
            assert columns == {"id", "email", "password_hash"}
            command.check(cfg)
            command.downgrade(cfg, "0001_reputation_cache")
            assert "accounts" not in inspect(connection).get_table_names()
            assert "reputation_cache" in inspect(connection).get_table_names()
    finally:
        engine.dispose()


def test_account_email_constraints() -> None:
    import pytest
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            cfg = config()
            cfg.attributes["connection"] = connection
            command.upgrade(cfg, "head")
            insert = text(
                "INSERT INTO accounts (id, email, password_hash) VALUES (:id, :email, :hash)"
            )
            connection.execute(
                insert, {"id": "1", "email": "synthetic@example.test", "hash": "synthetic"}
            )
            for account_id, email in [
                ("2", "synthetic@example.test"),
                ("3", "Upper@example.test"),
                ("4", "x"),
            ]:
                with pytest.raises(IntegrityError), connection.begin_nested():
                    connection.execute(
                        insert, {"id": account_id, "email": email, "hash": "synthetic"}
                    )
    finally:
        engine.dispose()
