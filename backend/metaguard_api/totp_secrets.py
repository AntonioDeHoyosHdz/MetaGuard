"""Internal authenticated encryption for TOTP secrets; not an MFA implementation."""

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_VERSION = b"\x01"
_NONCE_BYTES = 12
_TAG_BYTES = 16
_MAX_SECRET_BYTES = 1024


def _aad(key: bytes, account: str) -> bytes:
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("A 256-bit encryption key is required")
    if not isinstance(account, str) or not account or len(account) > 128:
        raise ValueError("Invalid account identifier")
    try:
        encoded = account.encode("utf-8")
    except UnicodeError:
        raise ValueError("Invalid account identifier") from None
    if len(encoded) > 128:
        raise ValueError("Invalid account identifier")
    return b"MetaGuard:TOTP:v1:" + encoded


def encrypt_totp_secret(key: bytes, account: str, secret: str) -> bytes:
    """Encrypt with a fresh nonce and authenticate the owning account identifier."""
    aad = _aad(key, account)
    if not isinstance(secret, str) or not secret or len(secret) > _MAX_SECRET_BYTES:
        raise ValueError("Invalid TOTP secret")
    try:
        plaintext = secret.encode("utf-8")
    except UnicodeError:
        raise ValueError("Invalid TOTP secret") from None
    if len(plaintext) > _MAX_SECRET_BYTES:
        raise ValueError("Invalid TOTP secret")
    nonce = secrets.token_bytes(_NONCE_BYTES)
    return _VERSION + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt_totp_secret(key: bytes, account: str, envelope: bytes) -> str:
    """Reject malformed envelopes; authentication failures never return plaintext."""
    aad = _aad(key, account)
    if (
        not isinstance(envelope, bytes)
        or not 1 + _NONCE_BYTES + _TAG_BYTES
        < len(envelope)
        <= 1 + _NONCE_BYTES + _TAG_BYTES + _MAX_SECRET_BYTES
        or envelope[:1] != _VERSION
    ):
        raise ValueError("Invalid encrypted TOTP secret")
    nonce = envelope[1 : 1 + _NONCE_BYTES]
    plaintext = AESGCM(key).decrypt(nonce, envelope[1 + _NONCE_BYTES :], aad)
    return plaintext.decode("utf-8")
