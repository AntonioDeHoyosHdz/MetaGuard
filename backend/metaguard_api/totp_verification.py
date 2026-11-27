"""Internal TOTP step consumption; not an authentication endpoint."""

import binascii
import hmac
import re

import pyotp
from cryptography.exceptions import InvalidTag
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from metaguard_api.account_totp import AccountTotp
from metaguard_api.totp_secrets import decrypt_totp_secret


def _matching_step(
    session: Session, account_id: str, code: str, *, key: bytes, key_version: int, now: int
) -> tuple[int, bytes] | None:
    if (
        not isinstance(account_id, str)
        or not account_id
        or not isinstance(code, str)
        or re.fullmatch(r"[0-9]{6}", code) is None
        or type(now) is not int
        or not 0 <= now <= (2**63 - 1)
        or type(key_version) is not int
        or key_version < 1
    ):
        return None
    step = now // 30
    record = session.execute(
        select(
            AccountTotp.encrypted_secret, AccountTotp.key_version, AccountTotp.last_accepted_step
        ).where(AccountTotp.account_id == account_id)
    ).one_or_none()
    if (
        record is None
        or record.key_version != key_version
        or (record.last_accepted_step is not None and record.last_accepted_step >= step)
    ):
        return None
    try:
        secret = decrypt_totp_secret(key, account_id, record.encrypted_secret)
        expected = pyotp.HOTP(secret).at(step)
    except (ValueError, UnicodeError, InvalidTag, binascii.Error):
        return None
    if not hmac.compare_digest(code, expected):
        return None
    return step, record.encrypted_secret


def is_totp_usable(
    session: Session, account_id: str, code: str, *, key: bytes, key_version: int, now: int
) -> bool:
    """Check a proof without consuming it; never grant access based on this alone."""
    return (
        _matching_step(session, account_id, code, key=key, key_version=key_version, now=now)
        is not None
    )


def consume_totp(
    session: Session, account_id: str, code: str, *, key: bytes, key_version: int, now: int
) -> bool:
    """Consume the current 30-second step once, subject to caller commit or rollback.

    The caller supplies trusted server time and must commit before granting access.
    No drift window, rate limiting, enrollment or login flow is implemented here.
    """
    matching = _matching_step(session, account_id, code, key=key, key_version=key_version, now=now)
    if matching is None:
        return False
    step, encrypted_secret = matching
    result = session.execute(
        update(AccountTotp)
        .where(
            AccountTotp.account_id == account_id,
            AccountTotp.encrypted_secret == encrypted_secret,
            AccountTotp.key_version == key_version,
            or_(AccountTotp.last_accepted_step.is_(None), AccountTotp.last_accepted_step < step),
        )
        .values(last_accepted_step=step)
    )
    return result.rowcount == 1
