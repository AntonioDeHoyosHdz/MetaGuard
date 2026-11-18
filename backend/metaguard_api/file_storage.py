"""Private in-memory encrypted temporary-file storage; no routes or disk writes."""

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_BYTES = 12
_TAG_BYTES = 16
_KEY_BYTES = 32
_MAX_IDENTIFIER_BYTES = 128
_TTL = timedelta(minutes=10)
_AAD_PREFIX = b"MetaGuard:temporary-file:v1\x00"


@dataclass(frozen=True, slots=True)
class _Entry:
    """Encrypted content and minimal in-memory ownership/expiry metadata."""

    owner_id: str
    expires_at: datetime
    plaintext_size: int
    sealed: bytes


class InMemoryTemporaryFileStore:
    """Store only AES-GCM-sealed payloads, bounded by caller-configured bytes.

    The AES-256 key and UTC clock are supplied for each operation and are never
    retained by the store. The byte limit caps total retained plaintext size.
    """

    def __init__(self, *, max_bytes: int) -> None:
        if type(max_bytes) is not int or max_bytes <= 0:
            raise ValueError("A positive byte limit is required")
        self._max_bytes = max_bytes
        self._entries: dict[str, _Entry] = {}
        self._size_bytes = 0
        self._lock = RLock()

    @property
    def size_bytes(self) -> int:
        """Return the total plaintext-equivalent size currently retained."""
        with self._lock:
            return self._size_bytes

    @staticmethod
    def _utc(value: datetime) -> datetime | None:
        if not isinstance(value, datetime):
            return None
        try:
            if value.utcoffset() != timedelta(0):
                return None
            return value.astimezone(UTC)
        except (OverflowError, TypeError, ValueError):
            return None

    @staticmethod
    def _identifier(value: str) -> bytes | None:
        if not isinstance(value, str) or not value or len(value) > _MAX_IDENTIFIER_BYTES:
            return None
        try:
            encoded = value.encode("utf-8")
        except UnicodeError:
            return None
        if len(encoded) > _MAX_IDENTIFIER_BYTES:
            return None
        return encoded

    @classmethod
    def _aad(cls, file_id: str, owner_id: str) -> bytes | None:
        encoded_file = cls._identifier(file_id)
        encoded_owner = cls._identifier(owner_id)
        if encoded_file is None or encoded_owner is None:
            return None
        return (
            _AAD_PREFIX
            + len(encoded_file).to_bytes(2, "big")
            + encoded_file
            + len(encoded_owner).to_bytes(2, "big")
            + encoded_owner
        )

    @staticmethod
    def _valid_key(key: bytes) -> bool:
        return isinstance(key, bytes) and len(key) == _KEY_BYTES

    def put(
        self,
        file_id: str,
        owner_id: str,
        content: bytes,
        *,
        key: bytes,
        now: datetime,
    ) -> bool:
        """Encrypt and insert nonempty bytes; invalid or over-limit input fails closed."""
        aad = self._aad(file_id, owner_id)
        current_time = self._utc(now)
        if (
            aad is None
            or not self._valid_key(key)
            or not isinstance(content, bytes)
            or not content
            or len(content) > self._max_bytes
            or current_time is None
        ):
            return False
        try:
            expires_at = current_time + _TTL
        except OverflowError:
            return False

        with self._lock:
            if file_id in self._entries or self._size_bytes + len(content) > self._max_bytes:
                return False
            nonce = secrets.token_bytes(_NONCE_BYTES)
            sealed = nonce + AESGCM(key).encrypt(nonce, content, aad)
            self._entries[file_id] = _Entry(owner_id, expires_at, len(content), sealed)
            self._size_bytes += len(content)
        return True

    def get(
        self,
        file_id: str,
        owner_id: str,
        *,
        key: bytes,
        now: datetime,
    ) -> bytes | None:
        """Decrypt only for the recorded owner before the caller-clock expiry."""
        aad = self._aad(file_id, owner_id)
        current_time = self._utc(now)
        if aad is None or not self._valid_key(key) or current_time is None:
            return None
        with self._lock:
            entry = self._entries.get(file_id)
            if entry is None or entry.owner_id != owner_id:
                return None
            if current_time >= entry.expires_at:
                self._remove(file_id, entry)
                return None
            if len(entry.sealed) < _NONCE_BYTES + _TAG_BYTES:
                return None
            nonce = entry.sealed[:_NONCE_BYTES]
            try:
                return AESGCM(key).decrypt(nonce, entry.sealed[_NONCE_BYTES:], aad)
            except (InvalidTag, ValueError):
                return None

    def delete(self, file_id: str, owner_id: str) -> bool:
        """Delete one entry only when the supplied owner matches."""
        if self._aad(file_id, owner_id) is None:
            return False
        with self._lock:
            entry = self._entries.get(file_id)
            if entry is None or entry.owner_id != owner_id:
                return False
            self._remove(file_id, entry)
            return True

    def delete_owner(self, owner_id: str) -> int:
        """Delete all entries belonging to one valid owner identifier."""
        if self._identifier(owner_id) is None:
            return 0
        with self._lock:
            file_ids = [
                file_id for file_id, entry in self._entries.items() if entry.owner_id == owner_id
            ]
            for file_id in file_ids:
                self._remove(file_id, self._entries[file_id])
            return len(file_ids)

    def purge_expired(self, *, now: datetime) -> int:
        """Purge all entries expired at the supplied UTC time."""
        current_time = self._utc(now)
        if current_time is None:
            return 0
        with self._lock:
            file_ids = [
                file_id
                for file_id, entry in self._entries.items()
                if current_time >= entry.expires_at
            ]
            for file_id in file_ids:
                self._remove(file_id, self._entries[file_id])
            return len(file_ids)

    def _remove(self, file_id: str, entry: _Entry) -> None:
        del self._entries[file_id]
        self._size_bytes -= entry.plaintext_size
