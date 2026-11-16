"""Pending TOTP enrollment is not an active MFA credential."""

import binascii
import hmac
import re

import pyotp
from cryptography.exceptions import InvalidTag
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
    update,
)
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Mapped, Session, mapped_column

from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import Account
from metaguard_api.database import Base
from metaguard_api.totp_secrets import decrypt_totp_secret, encrypt_totp_secret


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


def _lock_account(session: Session, account_id: str) -> bool:
    """Serialize enrollment operations on the owning account until transaction end."""
    result = session.execute(update(Account).where(Account.id == account_id).values(id=Account.id))
    return result.rowcount == 1


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
    if not _lock_account(session, account_id):
        return False
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
        .returning(PendingTotp.account_id)
    )
    return session.execute(statement).scalar_one_or_none() is not None


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
    if not _lock_account(session, account_id):
        return False
    result = session.execute(
        delete(PendingTotp).where(
            PendingTotp.account_id == account_id,
            PendingTotp.expires_at <= now,
        )
    )
    return result.rowcount == 1


def confirm_totp(
    session: Session, account_id: str, code: str, *, key: bytes, key_version: int, now: int
) -> bool:
    """Activate an unexpired pending credential; caller must commit before using it."""
    if (
        not isinstance(account_id, str)
        or not account_id
        or len(account_id) > 128
        or not isinstance(code, str)
        or re.fullmatch(r"[0-9]{6}", code) is None
        or type(key_version) is not int
        or not 1 <= key_version <= 2147483647
        or type(now) is not int
        or not 0 <= now <= 2**63 - 1
    ):
        return False
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert = postgres_insert
    elif dialect == "sqlite":
        insert = sqlite_insert
    else:
        raise ValueError("Unsupported database dialect")
    if not _lock_account(session, account_id):
        return False
    pending = session.execute(
        select(PendingTotp.encrypted_secret, PendingTotp.key_version, PendingTotp.expires_at).where(
            PendingTotp.account_id == account_id
        )
    ).one_or_none()
    if pending is None or pending.expires_at <= now or pending.key_version != key_version:
        return False
    try:
        secret = decrypt_totp_secret(key, account_id, pending.encrypted_secret)
        expected = pyotp.HOTP(secret).at(now // 30)
    except (ValueError, UnicodeError, InvalidTag, binascii.Error):
        return False
    if not hmac.compare_digest(code, expected):
        return False
    with session.begin_nested():
        result = session.execute(
            insert(AccountTotp)
            .values(
                account_id=account_id,
                encrypted_secret=pending.encrypted_secret,
                key_version=key_version,
                last_accepted_step=now // 30,
            )
            .on_conflict_do_nothing(index_elements=[AccountTotp.account_id])
            .returning(AccountTotp.account_id)
        )
        if result.scalar_one_or_none() is None:
            return False
        deleted = session.execute(delete(PendingTotp).where(PendingTotp.account_id == account_id))
        if deleted.rowcount != 1:
            raise RuntimeError("Pending TOTP credential changed during activation")
    return True
