"""Transaction-owned TOTP replacement and digest-only recovery credentials."""

import base64
import binascii
import hmac
import re
import secrets
from datetime import datetime
from hashlib import sha256

import pyotp
from cryptography.exceptions import InvalidTag
from sqlalchemy import Boolean, CheckConstraint, ForeignKey, String, delete, false, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column

from metaguard_api.account_totp import AccountTotp
from metaguard_api.accounts import AccountSession
from metaguard_api.database import Base
from metaguard_api.totp_secrets import decrypt_totp_secret, encrypt_totp_secret

RECOVERY_CODE_PATTERN = r"^[0-9a-f]{32}$"
RECOVERY_SETUP_TOKEN_MAX_LENGTH = 160
_TOKEN_PATTERN = r"[A-Za-z0-9_-]+"
_SEED_PATTERN = r"[A-Z2-7]{32}"
_RECOVERY_CODE_COUNT = 8


class MfaRecoveryCode(Base):
    """Account-owned, unused credential; raw recovery codes are never persisted."""

    __tablename__ = "mfa_recovery_codes"
    __table_args__ = (
        CheckConstraint("length(digest) = 64", name="ck_mfa_recovery_codes_digest_length"),
    )

    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True
    )
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    password_reset_used: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=false()
    )


def check_password_reset_recovery_code(
    session: Session, account_id: str, code: str, *, consume: bool
) -> bool:
    """Reserve a backup for reset once; leave its authenticator replacement use intact."""
    if re.fullmatch(RECOVERY_CODE_PATTERN, code) is None:
        return False
    conditions = (
        MfaRecoveryCode.account_id == account_id,
        MfaRecoveryCode.digest == sha256(code.encode("ascii")).hexdigest(),
        MfaRecoveryCode.password_reset_used.is_(False),
    )
    if not consume:
        return session.scalar(select(MfaRecoveryCode.digest).where(*conditions)) is not None
    return (
        session.scalar(
            update(MfaRecoveryCode)
            .where(*conditions)
            .values(password_reset_used=True)
            .returning(MfaRecoveryCode.digest)
        )
        is not None
    )


def has_recovery_code(session: Session, account_id: str, code: str) -> bool:
    if re.fullmatch(RECOVERY_CODE_PATTERN, code) is None:
        return False
    digest = sha256(code.encode("ascii")).hexdigest()
    return (
        session.scalar(
            select(MfaRecoveryCode.digest).where(
                MfaRecoveryCode.account_id == account_id,
                MfaRecoveryCode.digest == digest,
            )
        )
        is not None
    )


def rotate_recovery_codes_and_revoke_sessions(
    session: Session, account_id: str, *, now: datetime
) -> tuple[str, ...]:
    """Call with the owning account locked; return codes to the caller only after commit."""
    codes = tuple(secrets.token_hex(16) for _ in range(_RECOVERY_CODE_COUNT))
    if len(set(codes)) != _RECOVERY_CODE_COUNT:
        raise RuntimeError("Recovery code generation failed")
    session.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.account_id == account_id))
    session.add_all(
        MfaRecoveryCode(account_id=account_id, digest=sha256(code.encode("ascii")).hexdigest())
        for code in codes
    )
    session.execute(
        update(AccountSession)
        .where(AccountSession.account_id == account_id, AccountSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    return codes


def recovery_setup_binding(account_id: str, challenge: str, csrf: str, code: str) -> str:
    # The length/prefix cannot be a persisted Account.id (at most 36 bytes).
    # All inner digests have a fixed size, so the composition is unambiguous.
    binding = sha256(
        b"".join(
            sha256(value.encode("utf-8")).digest() for value in (account_id, challenge, csrf, code)
        )
    ).hexdigest()
    return f"recovery-setup:v1:{binding}"


def make_recovery_setup_token(key: bytes, binding: str, seed: str, expires_at: int) -> str:
    ciphertext = encrypt_totp_secret(key, binding, f"{seed}:{expires_at}")
    return base64.urlsafe_b64encode(ciphertext).decode("ascii").rstrip("=")


def open_recovery_setup_token(key: bytes, binding: str, token: str, now: int) -> str | None:
    if len(token) > RECOVERY_SETUP_TOKEN_MAX_LENGTH or re.fullmatch(_TOKEN_PATTERN, token) is None:
        return None
    try:
        envelope = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(envelope).decode("ascii").rstrip("=") != token:
            return None
        plaintext = decrypt_totp_secret(key, binding, envelope)
    except (InvalidTag, ValueError, UnicodeError, binascii.Error):
        return None
    seed, sep, expires = plaintext.partition(":")
    if not (
        sep
        and re.fullmatch(_SEED_PATTERN, seed)
        and re.fullmatch(r"[0-9]{1,19}", expires)
        and int(expires) > now
    ):
        return None
    return seed


def replace_totp(
    session: Session,
    account_id: str,
    seed: str,
    code: str,
    *,
    key: bytes,
    key_version: int,
    now: int,
) -> bool:
    """Require a valid code for the replacement and never leave the account without TOTP."""
    if not hmac.compare_digest(pyotp.HOTP(seed).at(now // 30), code):
        return False
    return (
        session.execute(
            update(AccountTotp)
            .where(AccountTotp.account_id == account_id)
            .values(
                encrypted_secret=encrypt_totp_secret(key, account_id, seed),
                key_version=key_version,
                last_accepted_step=now // 30,
            )
            .returning(AccountTotp.account_id)
        ).scalar_one_or_none()
        == account_id
    )
