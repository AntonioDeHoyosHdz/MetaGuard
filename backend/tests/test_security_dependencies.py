"""Smoke-test installed primitives; these tests do not implement account security."""

import jwt
import pyotp
import pytest
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def test_argon2id_hash_and_verification() -> None:
    hasher = PasswordHasher(time_cost=2, memory_cost=19_456, parallelism=1)
    encoded = hasher.hash("synthetic-password")
    assert encoded.startswith("$argon2id$")
    assert hasher.verify(encoded, "synthetic-password")
    with pytest.raises(VerifyMismatchError):
        hasher.verify(encoded, "wrong-password")


def test_aes_gcm_requires_matching_associated_data() -> None:
    cipher = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(cipher)
    nonce = b"synthetic-iv"
    encrypted = aes.encrypt(nonce, b"synthetic-data", b"purpose")
    assert aes.decrypt(nonce, encrypted, b"purpose") == b"synthetic-data"
    with pytest.raises(InvalidTag):
        aes.decrypt(nonce, encrypted, b"wrong-purpose")


def test_jwt_and_totp_primitives() -> None:
    key = b"synthetic-test-key-not-for-production"
    token = jwt.encode({"sub": "synthetic-account"}, key, algorithm="HS256")
    assert jwt.decode(token, key, algorithms=["HS256"])["sub"] == "synthetic-account"
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token, b"different-synthetic-key-32-bytes", algorithms=["HS256"])
    totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")
    assert totp.verify(totp.at(1_700_000_000), for_time=1_700_000_000)
