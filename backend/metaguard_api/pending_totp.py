"""Pending TOTP enrollment is not an active MFA credential."""

import re

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    delete,
    exists,
    literal,
    select,
)
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Mapped, Session, mapped_column

from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account
from metaguard_api.database import Base
from metaguard_api.totp_secrets import encrypt_totp_secret


class PendingTotp(Base):
    __tablename__ = "pending_totp"
    __table_args__ = (
        CheckConstraint(
            "length(encrypted_secret) BETWEEN 30 AND 1053", name="ck_pending_totp_secret_length"
        ),
        CheckConstraint("key_version > 0", name="ck_pending_totp_key_version"),
        CheckConstraint("expires_at > 0", name="ck_pending_totp_expiry"),
    )
    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True
    )
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


def stage_totp(
    session: Session,
    account_id: str,
    secret: str,
    *,
    key: bytes,
    key_version: int,
    now: int,
    expires_at: int,
) -> bool:
    """Stage once only; caller commits, enforces authorization and supplies trusted expiry."""
    if (
        not isinstance(account_id, str)
        or not account_id
        or not isinstance(secret, str)
        or re.fullmatch(r"[A-Z2-7]{32}", secret) is None
        or type(key_version) is not int
        or key_version < 1
        or key_version > 2147483647
        or type(now) is not int
        or type(expires_at) is not int
        or not 0 <= now < expires_at <= 2**63 - 1
    ):
        return False
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert = postgres_insert
    elif dialect == "sqlite":
        insert = sqlite_insert
    else:
        raise ValueError("Unsupported database dialect")
    encrypted = encrypt_totp_secret(key, account_id, secret)
    source = select(
        Account.id, literal(encrypted), literal(key_version), literal(expires_at)
    ).where(
        Account.id == account_id,
        ~exists(select(AccountTotp.account_id).where(AccountTotp.account_id == Account.id)),
    )
    statement = (
        insert(PendingTotp)
        .from_select(["account_id", "encrypted_secret", "key_version", "expires_at"], source)
        .on_conflict_do_nothing(index_elements=[PendingTotp.account_id])
    )
    return session.execute(statement).rowcount == 1


def remove_expired_pending(session: Session, account_id: str, *, now: int) -> bool:
    """Delete only this account's expired pending setup in the caller transaction."""
    if (
        not isinstance(account_id, str)
        or not account_id
        or len(account_id) > 128
        or type(now) is not int
        or not 0 <= now <= 2**63 - 1
    ):
        return False
    result = session.execute(
        delete(PendingTotp).where(
            PendingTotp.account_id == account_id,
            PendingTotp.expires_at <= now,
        )
    )
    return result.rowcount == 1
