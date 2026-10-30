"""Read allowlisted runtime secrets without environment or development fallbacks."""

from enum import StrEnum
from pathlib import Path


class SecretName(StrEnum):
    POSTGRES_PASSWORD = "postgres_password"
    JWT_SIGNING_KEY = "jwt_signing_key"
    CSRF_SIGNING_KEY = "csrf_signing_key"
    DATA_ENCRYPTION_KEY = "data_encryption_key"
    TOTP_ENCRYPTION_KEY = "totp_encryption_key"
    HIBP_API_KEY = "hibp_api_key"
    VIRUSTOTAL_API_KEY = "virustotal_api_key"
    SMTP_CREDENTIALS = "smtp_credentials"


class SecretUnavailable(RuntimeError):
    """A required secret is absent or empty; the secret value is never included."""

    def __init__(self, name: SecretName) -> None:
        super().__init__(f"Required runtime secret '{name.value}' is unavailable or empty.")


class SecretStore:
    """Read secrets mounted as files, e.g. Docker Secrets under ``/run/secrets``."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory

    def read(self, name: SecretName) -> bytes:
        """Return secret bytes unchanged; binary keys must not be normalized."""
        if not isinstance(name, SecretName):
            raise ValueError("Secret name is not allowlisted.")

        try:
            value = (self._directory / name.value).read_bytes()
        except OSError:
            raise SecretUnavailable(name) from None

        if not value:
            raise SecretUnavailable(name)
        return value

    def read_text(self, name: SecretName, encoding: str = "utf-8") -> str:
        """Read a textual secret and remove file-ending newlines, not binary key bytes."""
        try:
            value = self.read(name).decode(encoding).rstrip("\r\n")
        except (LookupError, UnicodeError):
            raise SecretUnavailable(name) from None

        if not value:
            raise SecretUnavailable(name)
        return value
