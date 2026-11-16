"""Alembic environment: offline PostgreSQL SQL or explicit online connection."""

from alembic import context

from metaguard_api import account_totp, reputation_cache  # noqa: F401
from metaguard_api.accounts import Account
from metaguard_api.database import DatabaseSettings, create_database

config = context.config
target_metadata = Account.metadata


def run_with_connection(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    context.configure(
        dialect_name="postgresql",
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()
elif config.attributes.get("connection") is not None:
    # Test harness / caller-owned transaction: never dispose the caller's connection.
    run_with_connection(config.attributes["connection"])
else:
    database = create_database(DatabaseSettings())
    try:
        with database.engine.connect() as connection:
            run_with_connection(connection)
    finally:
        database.close()
