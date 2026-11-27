from pathlib import Path

import pytest

from metaguard_api.secrets import SecretName, SecretStore, SecretUnavailable


def test_secret_store_preserves_all_raw_secret_bytes(
    tmp_path: Path,
) -> None:
    (tmp_path / SecretName.JWT_SIGNING_KEY.value).write_bytes(b"demo-key \r\n")

    value = SecretStore(tmp_path).read(SecretName.JWT_SIGNING_KEY)

    assert value == b"demo-key \r\n"


def test_secret_store_strips_file_newline_only_for_text_secrets(tmp_path: Path) -> None:
    (tmp_path / SecretName.POSTGRES_PASSWORD.value).write_bytes(b"demo-password \r\n")

    value = SecretStore(tmp_path).read_text(SecretName.POSTGRES_PASSWORD)

    assert value == "demo-password "


def test_missing_secret_fails_without_exposing_path_or_value(tmp_path: Path) -> None:
    with pytest.raises(SecretUnavailable) as error:
        SecretStore(tmp_path).read(SecretName.DATA_ENCRYPTION_KEY)

    assert str(tmp_path) not in str(error.value)
    assert "DATA_ENCRYPTION_KEY" not in str(error.value)
    assert "data_encryption_key" in str(error.value)


def test_empty_secret_fails_closed(tmp_path: Path) -> None:
    (tmp_path / SecretName.POSTGRES_PASSWORD.value).write_bytes(b"")

    with pytest.raises(SecretUnavailable):
        SecretStore(tmp_path).read(SecretName.POSTGRES_PASSWORD)


def test_empty_text_secret_fails_closed_after_newline_removal(tmp_path: Path) -> None:
    (tmp_path / SecretName.POSTGRES_PASSWORD.value).write_bytes(b"\r\n")

    with pytest.raises(SecretUnavailable):
        SecretStore(tmp_path).read_text(SecretName.POSTGRES_PASSWORD)


def test_text_secret_with_invalid_encoding_fails_closed(tmp_path: Path) -> None:
    (tmp_path / SecretName.POSTGRES_PASSWORD.value).write_bytes(b"\xff")

    with pytest.raises(SecretUnavailable):
        SecretStore(tmp_path).read_text(SecretName.POSTGRES_PASSWORD)


def test_secret_name_cannot_be_supplied_as_a_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not allowlisted"):
        SecretStore(tmp_path).read("../outside")  # type: ignore[arg-type]
