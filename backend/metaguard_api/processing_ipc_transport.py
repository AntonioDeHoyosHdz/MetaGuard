"""Linux-only authenticated frame transport; it does not create a listener.

Callers must close the socket on success and failure. This layer does not
validate worker JSON, authorize end users, or enforce global job quotas.
"""

import array
import math
import os
import socket
import struct
import sys
import time

from metaguard_api.processing_ipc_frame import (
    HEADER_SIZE,
    FrameKind,
    FrameProtocolError,
    decode_header,
    encode_frame,
)

_LINUX = sys.platform == "linux"
_SO_PEERCRED = getattr(socket, "SO_PEERCRED", None)
_SCM_RIGHTS = getattr(socket, "SCM_RIGHTS", None)
_CMSG_SPACE = getattr(socket, "CMSG_SPACE", None)
_MSG_CTRUNC = getattr(socket, "MSG_CTRUNC", None)
_MSG_TRUNC = getattr(socket, "MSG_TRUNC", None)
_MSG_CMSG_CLOEXEC = getattr(socket, "MSG_CMSG_CLOEXEC", None)
_CREDENTIALS = struct.Struct("iII")
_CHUNK_BYTES = 64 * 1024
_MAX_TIMEOUT = 120.0


class TransportError(ValueError):
    """An authenticated frame could not be safely transferred."""


def _deadline(timeout: float) -> float:
    if (
        type(timeout) not in (int, float)
        or not 0 < timeout <= _MAX_TIMEOUT
        or not math.isfinite(timeout)
    ):
        raise TransportError("Invalid processing transport")
    return time.monotonic() + timeout


def _authenticate(stream: socket.socket, expected_uid: int) -> None:
    if (
        not _LINUX
        or any(
            x is None
            for x in (
                _SO_PEERCRED,
                _SCM_RIGHTS,
                _CMSG_SPACE,
                _MSG_CTRUNC,
                _MSG_TRUNC,
                _MSG_CMSG_CLOEXEC,
            )
        )
        or type(expected_uid) is not int
        or not 0 <= expected_uid <= 2**32 - 1
        or stream.family != socket.AF_UNIX
        or stream.type != socket.SOCK_STREAM
    ):
        raise TransportError("Invalid processing transport")
    credentials = stream.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, _CREDENTIALS.size)
    if len(credentials) != _CREDENTIALS.size:
        raise TransportError("Invalid processing transport")
    pid, uid, _gid = _CREDENTIALS.unpack(credentials)
    if pid <= 0 or uid != expected_uid:
        raise TransportError("Invalid processing transport")


def _set_timeout(stream: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransportError("Invalid processing transport")
    stream.settimeout(remaining)


def _reject_ancillary(ancillary, flags: int) -> None:
    received = bool(ancillary) or bool(flags & (_MSG_CTRUNC | _MSG_TRUNC))
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == _SCM_RIGHTS:
            fds = array.array("i")
            fds.frombytes(data[: len(data) - len(data) % fds.itemsize])
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
    if received:
        raise TransportError("Invalid processing transport")


def _read_chunk(stream: socket.socket, count: int, deadline: float) -> bytes:
    _set_timeout(stream, deadline)
    data, ancillary, flags, _address = stream.recvmsg(
        count, _CMSG_SPACE(16 * array.array("i").itemsize), _MSG_CMSG_CLOEXEC
    )
    _reject_ancillary(ancillary, flags)
    if not isinstance(data, bytes) or len(data) > count:
        raise TransportError("Invalid processing transport")
    return data


def _read_exact(stream: socket.socket, size: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < size:
        data = _read_chunk(stream, min(size - len(result), _CHUNK_BYTES), deadline)
        if not data:
            raise TransportError("Invalid processing transport")
        result.extend(data)
    return bytes(result)


def receive_frame(
    stream: socket.socket, *, expected_uid: int, allowed_kinds: frozenset[FrameKind], timeout: float
) -> tuple[FrameKind, bytes]:
    """Authenticate a peer, read exactly one bounded frame, and require EOF."""
    try:
        deadline = _deadline(timeout)
        if (
            not isinstance(allowed_kinds, frozenset)
            or not allowed_kinds
            or any(type(kind) is not FrameKind for kind in allowed_kinds)
        ):
            raise TransportError("Invalid processing transport")
        _authenticate(stream, expected_uid)
        kind, size = decode_header(_read_exact(stream, HEADER_SIZE, deadline))
        if kind not in allowed_kinds:
            raise TransportError("Invalid processing transport")
        body = _read_exact(stream, size, deadline)
        if _read_chunk(stream, 1, deadline):
            raise TransportError("Invalid processing transport")
        return kind, body
    except (OSError, FrameProtocolError, struct.error, TypeError):
        raise TransportError("Invalid processing transport") from None


def send_frame(
    stream: socket.socket, kind: FrameKind, payload: bytes, *, expected_uid: int, timeout: float
) -> None:
    """Authenticate a peer, send one bounded frame, then half-close writing."""
    try:
        deadline = _deadline(timeout)
        _authenticate(stream, expected_uid)
        frame = memoryview(encode_frame(kind, payload))
        while frame:
            _set_timeout(stream, deadline)
            sent = stream.send(frame)
            if not isinstance(sent, int) or sent <= 0 or sent > len(frame):
                raise TransportError("Invalid processing transport")
            frame = frame[sent:]
        stream.shutdown(socket.SHUT_WR)
    except (OSError, FrameProtocolError, struct.error, TypeError):
        raise TransportError("Invalid processing transport") from None
