from io import StringIO
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

from metaguard_api.database import Base


def config() -> Config:
    return Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))


def test_offline_migration_does_not_require_secrets() -> None:
    cfg = config()
    cfg.output_buffer = StringIO()
    command.upgrade(cfg, "head", sql=True)
    assert "BEGIN" in cfg.output_buffer.getvalue()
    assert not Base.metadata.tables


def test_alembic_runs_with_caller_owned_connection() -> None:
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            cfg = config()
            cfg.attributes["connection"] = connection
            command.upgrade(cfg, "head")
            command.check(cfg)
    finally:
        engine.dispose()
