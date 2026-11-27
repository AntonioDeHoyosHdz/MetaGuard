import pytest
from cryptography.exceptions import InvalidTag

from metaguard_api.totp_secrets import decrypt_totp_secret, encrypt_totp_secret


def test_totp_secret_round_trip_and_account_binding() -> None:
    key = bytes(range(32))
    first = encrypt_totp_secret(key, "account-1", "synthetic-secret")
    second = encrypt_totp_secret(key, "account-1", "synthetic-secret")
    assert first != second
    assert b"synthetic-secret" not in first
    assert decrypt_totp_secret(key, "account-1", first) == "synthetic-secret"
    with pytest.raises(InvalidTag):
        decrypt_totp_secret(key, "account-2", first)
    with pytest.raises(InvalidTag):
        decrypt_totp_secret(bytes(reversed(key)), "account-1", first)
    damaged = first[:-1] + bytes([first[-1] ^ 1])
    with pytest.raises(InvalidTag):
        decrypt_totp_secret(key, "account-1", damaged)


@pytest.mark.parametrize("key", [b"", b"x" * 16, b"x" * 33])
def test_invalid_key_is_rejected(key: bytes) -> None:
    with pytest.raises(ValueError):
        encrypt_totp_secret(key, "account-1", "synthetic-secret")
    with pytest.raises(ValueError):
        decrypt_totp_secret(key, "account-1", b"x" * 30)


@pytest.mark.parametrize(
    "account,secret", [("", "secret"), ("account-1", ""), ("account-1", "x" * 1025)]
)
def test_invalid_inputs_are_rejected(account: str, secret: str) -> None:
    with pytest.raises(ValueError):
        encrypt_totp_secret(bytes(32), account, secret)
