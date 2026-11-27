"""Private provisional two-factor verification; never grants a session."""

from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from metaguard_api.accounts import Account
from metaguard_api.first_factor import FirstFactorStatus, _valid_email, check_first_factor
from metaguard_api.totp_verification import consume_totp


def check_second_factor(
    session: Session,
    email: str,
    password: str,
    code: str,
    *,
    dummy_password_hash: str,
    key: bytes,
    key_version: int,
    now: int,
    on_mfa_rejected: Callable[[], None] | None = None,
    on_bad_password: Callable[[str], None] | None = None,
) -> str | None:
    """Return a provisional account ID only for both factors in this transaction.

    The caller must supply a session without pending ORM changes and commit
    before access is granted. This is not a complete authentication policy.
    """
    if session.new or session.dirty or session.deleted:
        return None
    locked_id = None
    if _valid_email(email):
        with session.no_autoflush:
            locked_id = session.scalar(
                select(Account.id).where(Account.email == email).with_for_update()
            )
    first = check_first_factor(
        session,
        email,
        password,
        dummy_password_hash=dummy_password_hash,
        on_bad_password=on_bad_password,
    )
    if (
        first.status is not FirstFactorStatus.MFA_REQUIRED
        or first.account_id is None
        or first.account_id != locked_id
    ):
        return None
    if not consume_totp(session, locked_id, code, key=key, key_version=key_version, now=now):
        if on_mfa_rejected is not None:
            on_mfa_rejected()
        return None
    return locked_id
