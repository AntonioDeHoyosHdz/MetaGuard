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


def consume_totp(
    session: Session, account_id: str, code: str, *, key: bytes, key_version: int, now: int
) -> bool:
    """Consume the current 30-second step once, subject to caller commit or rollback.

    The caller supplies trusted server time and must commit before granting access.
    No drift window, rate limiting, enrollment or login flow is implemented here.
    """
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
        return False
    step = now // 30
    record = session.execute(
        select(AccountTotp.encrypted_secret, AccountTotp.key_version).where(
            AccountTotp.account_id == account_id
        )
    ).one_or_none()
    if record is None or record.key_version != key_version:
        return False
    try:
        secret = decrypt_totp_secret(key, account_id, record.encrypted_secret)
        expected = pyotp.HOTP(secret).at(step)
    except (ValueError, UnicodeError, InvalidTag, binascii.Error):
        return False
    if not hmac.compare_digest(code, expected):
        return False
    result = session.execute(
        update(AccountTotp)
        .where(
            AccountTotp.account_id == account_id,
            AccountTotp.encrypted_secret == record.encrypted_secret,
            AccountTotp.key_version == key_version,
            or_(AccountTotp.last_accepted_step.is_(None), AccountTotp.last_accepted_step < step),
        )
        .values(last_accepted_step=step)
    )
    return result.rowcount == 1
