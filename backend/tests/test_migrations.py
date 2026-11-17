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
            assert columns == {"id", "email", "password_hash", "email_verified_at"}
            assert "email_verification_tokens" in inspect(connection).get_table_names()
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


def test_totp_schema_migration_preserves_account_data() -> None:
    from sqlalchemy import text

    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            cfg = config()
            cfg.attributes["connection"] = connection
            command.upgrade(cfg, "0002_accounts")
            connection.execute(
                text("INSERT INTO accounts (id,email,password_hash) VALUES ('1','a@b','hash')")
            )
            command.upgrade(cfg, "head")
            assert {c["name"] for c in inspect(connection).get_columns("account_totp")} == {
                "account_id",
                "encrypted_secret",
                "key_version",
                "last_accepted_step",
            }
            command.check(cfg)
            command.downgrade(cfg, "0002_accounts")
            assert "account_totp" not in inspect(connection).get_table_names()
            assert connection.execute(text("SELECT count(*) FROM accounts")).scalar_one() == 1
    finally:
        engine.dispose()


def test_totp_storage_constraints_and_account_deletion() -> None:
    import pytest
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    from metaguard_api.totp_secrets import encrypt_totp_secret

    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.execute(text("PRAGMA foreign_keys=ON"))
            cfg = config()
            cfg.attributes["connection"] = connection
            command.upgrade(cfg, "head")
            connection.execute(
                text("INSERT INTO accounts (id,email,password_hash) VALUES ('1','a@b','hash')")
            )
            insert = text(
                "INSERT INTO account_totp (account_id, encrypted_secret, "
                "key_version, last_accepted_step) "
                "VALUES (:id,:secret,:version,:step)"
            )
            secret = encrypt_totp_secret(bytes(32), "1", "synthetic-secret")
            for values in [
                {"id": "missing", "secret": secret, "version": 1, "step": None},
                {"id": "1", "secret": secret, "version": 0, "step": None},
                {"id": "1", "secret": b"bad", "version": 1, "step": None},
                {"id": "1", "secret": secret, "version": 1, "step": -1},
            ]:
                with pytest.raises(IntegrityError), connection.begin_nested():
                    connection.execute(insert, values)
            connection.execute(insert, {"id": "1", "secret": secret, "version": 1, "step": None})
            connection.execute(text("DELETE FROM accounts WHERE id='1'"))
            assert connection.execute(text("SELECT count(*) FROM account_totp")).scalar_one() == 0
    finally:
        engine.dispose()


def test_system_events_migration_preserves_existing_data() -> None:
    from sqlalchemy import text

    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            cfg = config()
            cfg.attributes["connection"] = connection
            command.upgrade(cfg, "0004_pending_totp")
            connection.execute(
                text("INSERT INTO accounts (id,email,password_hash) VALUES ('1','a@b','hash')")
            )
            command.upgrade(cfg, "head")
            assert "system_security_events" in inspect(connection).get_table_names()
            command.check(cfg)
            command.downgrade(cfg, "0004_pending_totp")
            assert "system_security_events" not in inspect(connection).get_table_names()
            assert connection.execute(text("SELECT count(*) FROM accounts")).scalar_one() == 1
    finally:
        engine.dispose()


def test_email_verification_migration_preserves_legacy_account_data() -> None:
    from sqlalchemy import text

    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            cfg = config()
            cfg.attributes["connection"] = connection
            command.upgrade(cfg, "0005_system_security_events")
            connection.execute(
                text(
                    "INSERT INTO accounts (id,email,password_hash) "
                    "VALUES ('legacy-1','legacy@example.test','unchanged-hash')"
                )
            )
            command.upgrade(cfg, "head")
            legacy = connection.execute(
                text(
                    "SELECT id,email,password_hash,email_verified_at "
                    "FROM accounts WHERE id='legacy-1'"
                )
            ).one()
            assert legacy == ("legacy-1", "legacy@example.test", "unchanged-hash", None)
            columns = {
                column["name"]
                for column in inspect(connection).get_columns("email_verification_tokens")
            }
            assert columns == {"account_id", "token_digest", "expires_at"}
            command.check(cfg)
            command.downgrade(cfg, "0005_system_security_events")
            assert "email_verification_tokens" not in inspect(connection).get_table_names()
            assert connection.execute(
                text("SELECT id,email,password_hash FROM accounts WHERE id='legacy-1'")
            ).one() == ("legacy-1", "legacy@example.test", "unchanged-hash")
    finally:
        engine.dispose()
