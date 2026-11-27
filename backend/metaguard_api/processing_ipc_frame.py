"""Bounded frame codec only; this module does not implement an IPC service.

An eventual transport must authenticate peers, enforce deadlines and quotas,
read a header before allocating its payload, require EOF after one frame, and
validate each message's worker schema. Decoding bytes is not authorization.
"""

from enum import IntEnum
from struct import Struct

from metaguard_api.processing_limits import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES

_HEADER = Struct("!4sBBHI")
_MAGIC = b"MGIP"
_VERSION = 1
HEADER_SIZE = _HEADER.size


class FrameKind(IntEnum):
    REQUEST = 1
    SUCCESS = 2
    ERROR = 3


class FrameProtocolError(ValueError):
    """A frame is invalid; no payload or internal details are exposed."""


def _valid_size(kind: FrameKind, size: int) -> bool:
    if kind is FrameKind.ERROR:
        return size == 0
    maximum = MAX_REQUEST_BYTES if kind is FrameKind.REQUEST else MAX_RESPONSE_BYTES
    return 1 <= size <= maximum


def decode_header(header: bytes) -> tuple[FrameKind, int]:
    """Validate an exact fixed-size header before a transport reads its body."""
    if not isinstance(header, bytes) or len(header) != HEADER_SIZE:
        raise FrameProtocolError("Invalid processing frame")
    magic, version, raw_kind, flags, size = _HEADER.unpack(header)
    try:
        kind = FrameKind(raw_kind)
    except ValueError:
        raise FrameProtocolError("Invalid processing frame") from None
    if magic != _MAGIC or version != _VERSION or flags != 0 or not _valid_size(kind, size):
        raise FrameProtocolError("Invalid processing frame")
    return kind, size


def encode_frame(kind: FrameKind, payload: bytes) -> bytes:
    """Encode one bounded frame; errors are empty and contain no details."""
    if type(kind) is not FrameKind or not isinstance(payload, bytes):
        raise FrameProtocolError("Invalid processing frame")
    if not _valid_size(kind, len(payload)):
        raise FrameProtocolError("Invalid processing frame")
    return _HEADER.pack(_MAGIC, _VERSION, kind.value, 0, len(payload)) + payload


def decode_frame(frame: bytes) -> tuple[FrameKind, bytes]:
    """Decode exactly one already bounded frame; reject partial or trailing data."""
    if not isinstance(frame, bytes) or len(frame) < HEADER_SIZE:
        raise FrameProtocolError("Invalid processing frame")
    kind, size = decode_header(frame[:HEADER_SIZE])
    if len(frame) != HEADER_SIZE + size:
        raise FrameProtocolError("Invalid processing frame")
    return kind, frame[HEADER_SIZE:]
