from datetime import UTC, datetime, timedelta

import pytest

from metaguard_api.file_storage import InMemoryTemporaryFileStore

KEY = bytes(range(32))
NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


def test_store_encrypts_round_trips_and_binds_owner_and_file_identity():
    store = InMemoryTemporaryFileStore(max_bytes=128)
    plaintext = b"synthetic private file bytes"

    assert store.put("file-1", "owner-1", plaintext, key=KEY, now=NOW)
    entry = store._entries["file-1"]
    assert isinstance(entry.sealed, bytes)
    assert plaintext not in entry.sealed
    assert plaintext.decode("ascii") not in repr(entry)
    assert store.get("file-1", "owner-1", key=KEY, now=NOW) == plaintext
    assert store.get("file-1", "owner-2", key=KEY, now=NOW) is None
    assert store.get("file-2", "owner-1", key=KEY, now=NOW) is None
    assert store.get("file-1", "owner-1", key=bytes(reversed(KEY)), now=NOW) is None


def test_store_enforces_aggregate_byte_limit_and_owner_deletion():
    store = InMemoryTemporaryFileStore(max_bytes=6)
    assert store.put("file-a", "owner-a", b"abc", key=KEY, now=NOW)
    assert store.put("file-b", "owner-b", b"def", key=KEY, now=NOW)
    assert not store.put("file-c", "owner-a", b"g", key=KEY, now=NOW)
    assert not store.delete("file-a", "owner-b")
    assert store.delete_owner("owner-a") == 1
    assert store.get("file-a", "owner-a", key=KEY, now=NOW) is None
    assert store.get("file-b", "owner-b", key=KEY, now=NOW) == b"def"
    assert store.put("file-c", "owner-a", b"g", key=KEY, now=NOW)


def test_store_expires_at_ten_minutes_and_purges_using_supplied_utc_time():
    store = InMemoryTemporaryFileStore(max_bytes=128)
    assert store.put("read-file", "owner", b"read", key=KEY, now=NOW)
    assert (
        store.get("read-file", "owner", key=KEY, now=NOW + timedelta(minutes=9, seconds=59))
        == b"read"
    )
    assert store.get("read-file", "owner", key=KEY, now=NOW + timedelta(minutes=10)) is None

    assert store.put("purge-file", "owner", b"purge", key=KEY, now=NOW)
    assert store.purge_expired(now=NOW + timedelta(minutes=10)) == 1
    assert store.purge_expired(now=NOW + timedelta(minutes=10)) == 0


@pytest.mark.parametrize("key", [b"", b"x" * 31, b"x" * 33, "x" * 32, bytearray(32)])
def test_store_fails_closed_on_invalid_key(key):
    store = InMemoryTemporaryFileStore(max_bytes=128)
    assert not store.put("file", "owner", b"payload", key=key, now=NOW)
    assert store.get("file", "owner", key=key, now=NOW) is None
    assert store.size_bytes == 0


def test_store_fails_closed_on_invalid_identifiers_content_and_time():
    store = InMemoryTemporaryFileStore(max_bytes=128)
    assert not store.put("", "owner", b"payload", key=KEY, now=NOW)
    assert not store.put("file", "", b"payload", key=KEY, now=NOW)
    assert not store.put("file", "owner", "payload", key=KEY, now=NOW)
    assert not store.put("file", "owner", b"payload", key=KEY, now=NOW.replace(tzinfo=None))
    assert store.get("file", "owner", key=KEY, now=NOW.replace(tzinfo=None)) is None
    assert store.purge_expired(now=NOW.replace(tzinfo=None)) == 0
    assert store.size_bytes == 0


def test_store_rejects_duplicate_file_ids_without_replacing_owner_or_content():
    store = InMemoryTemporaryFileStore(max_bytes=128)
    assert store.put("file", "owner-a", b"first", key=KEY, now=NOW)
    assert not store.put("file", "owner-b", b"second", key=KEY, now=NOW)
    assert store.get("file", "owner-a", key=KEY, now=NOW) == b"first"
    assert store.get("file", "owner-b", key=KEY, now=NOW) is None
