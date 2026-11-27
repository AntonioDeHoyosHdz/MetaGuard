import pytest
from argon2 import PasswordHasher

from metaguard_api.account_credentials import (
    hash_password,
    is_approved_password_hash,
    verify_password,
)


def test_hash_uses_argon2id_with_unique_salts_and_verifies() -> None:
    first = hash_password("synthetic-password")
    second = hash_password("synthetic-password")
    assert first.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert first != second
    assert verify_password("synthetic-password", first)
    assert not verify_password("wrong-password", first)


@pytest.mark.parametrize("password", ["", "x" * 1025, "\ud800"])
def test_invalid_password_input_fails_without_exposing_it(password) -> None:
    with pytest.raises(ValueError) as error:
        hash_password(password)
    assert str(error.value) == "Invalid password input"
    assert not verify_password(password, "invalid")


def test_invalid_or_unbounded_hash_is_rejected_before_argon2(monkeypatch) -> None:
    valid = hash_password("synthetic-password")
    weak = valid.replace("m=19456", "m=8")
    huge = valid.replace("m=19456", "m=999999999")
    prefix, salt, digest = valid.rsplit("$", maxsplit=2)
    noncanonical_salt = f"{prefix}${salt[:-1]}B${digest}"
    noncanonical_digest = f"{prefix}${salt}${digest[:-1]}B"

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Untrusted parameters must not reach Argon2")

    monkeypatch.setattr(PasswordHasher, "verify", forbidden)
    for encoded in [
        "invalid",
        weak,
        huge,
        "x" * 513,
        noncanonical_salt,
        noncanonical_digest,
    ]:
        assert not is_approved_password_hash(encoded)
        assert not verify_password("synthetic-password", encoded)


def test_non_ascii_hash_is_rejected() -> None:
    encoded = hash_password("synthetic-password")
    assert not verify_password("synthetic-password", encoded.replace("t=2", "t=２"))
    assert not verify_password("synthetic-password", encoded + "\ud800")


def test_hash_with_embedded_nul_is_rejected() -> None:
    shorter = PasswordHasher(
        time_cost=2, memory_cost=19_456, parallelism=1, hash_len=31, salt_len=16
    ).hash("synthetic-password")
    assert not verify_password("synthetic-password", shorter + "\x00")
