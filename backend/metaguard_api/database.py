"""Explicit PostgreSQL connection setup; never connects at module import."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL, Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from metaguard_api.secrets import SecretName, SecretStore


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="METAGUARD_DB_", env_file=None)

    host: str = Field(default="db", min_length=1)
    port: int = Field(default=5432, ge=1, le=65535)
    name: str = Field(default="metaguard", min_length=1)
    user: str = Field(default="metaguard", min_length=1)
    secret_dir: Path = Path("/run/secrets")


class Base(DeclarativeBase):
    """Empty metadata until the business schema is explicitly resolved."""


class Database:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self._sessions = sessionmaker(engine, expire_on_commit=False)

    @contextmanager
    def transaction(self) -> Iterator[Session]:
        """Use a fresh session, commit on success, rollback on failure, always close."""
        with self._sessions.begin() as session:
            yield session

    def close(self) -> None:
        self.engine.dispose()


def create_database(
    settings: DatabaseSettings, *, connect_timeout_seconds: int | None = None
) -> Database:
    password = SecretStore(settings.secret_dir).read_text(SecretName.POSTGRES_PASSWORD)
    url = URL.create(
        "postgresql+psycopg",
        username=settings.user,
        password=password,
        host=settings.host,
        port=settings.port,
        database=settings.name,
    )
    connect_args = {"connect_timeout": connect_timeout_seconds} if connect_timeout_seconds else {}
    engine = create_engine(
        url, echo=False, hide_parameters=True, pool_pre_ping=True, connect_args=connect_args
    )
    return Database(engine)
