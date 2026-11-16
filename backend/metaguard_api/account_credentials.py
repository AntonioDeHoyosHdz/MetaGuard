"""Internal password hashing primitives, not an authentication or password-policy API."""

import re

from argon2 import PasswordHasher, Type, extract_parameters
from argon2.exceptions import HashingError, InvalidHashError, VerificationError

_HASHER = PasswordHasher(
    time_cost=2, memory_cost=19_456, parallelism=1, hash_len=32, salt_len=16, type=Type.ID
)
_MAX_PASSWORD_BYTES = 1024
_HASH_FORMAT = re.compile(
    r"\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}"
)


def _valid_password(password: object) -> bool:
    if not isinstance(password, str) or not 1 <= len(password) <= _MAX_PASSWORD_BYTES:
        return False
    try:
        return len(password.encode("utf-8")) <= _MAX_PASSWORD_BYTES
    except UnicodeError:
        return False


def hash_password(password: str) -> str:
    """Hash a nonempty bounded input; account policy must be enforced separately."""
    if not _valid_password(password):
        raise ValueError("Invalid password input")
    try:
        return _HASHER.hash(password)
    except HashingError:
        raise RuntimeError("Password hashing unavailable") from None


def verify_password(password: str, encoded: str) -> bool:
    """Reject malformed or unapproved parameters before invoking Argon2."""
    if not _valid_password(password) or not isinstance(encoded, str):
        return False
    if _HASH_FORMAT.fullmatch(encoded) is None:
        return False
    try:
        params = extract_parameters(encoded)
        if (
            params.type != Type.ID
            or params.version != 19
            or params.memory_cost != 19_456
            or params.time_cost != 2
            or params.parallelism != 1
            or params.salt_len != 16
            or params.hash_len != 32
        ):
            return False
        return _HASHER.verify(encoded, password)
    except (InvalidHashError, VerificationError):
        return False
