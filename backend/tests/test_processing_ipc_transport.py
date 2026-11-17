"""Tests use fake streams only; no peer-credential or OS isolation claim."""

import array
import socket
import struct
import subprocess
import sys
from types import SimpleNamespace

import pytest

import metaguard_api.processing_ipc_transport as transport
from metaguard_api.processing_ipc_frame import FrameKind, encode_frame
from metaguard_api.processing_ipc_transport import TransportError, receive_frame, send_frame
from metaguard_api.processing_worker import MAX_REQUEST_BYTES


class FakeStream:
    family = getattr(socket, "AF_UNIX", 1)
    type = socket.SOCK_STREAM

    def __init__(self, chunks=(), uid=123):
        self.chunks = list(chunks)
        self.uid = uid
        self.read_calls = 0
        self.sent = bytearray()
        self.closed_write = False
        self.ancillary = []
        self.flags = 0

    def getsockopt(self, *_args):
        return struct.pack("3i", 99, self.uid, 10)

    def settimeout(self, _value):
        pass

    def recvmsg(self, limit, _ancillary_size, _flags):
        self.read_calls += 1
        data = self.chunks.pop(0) if self.chunks else b""
        if len(data) > limit:
            self.chunks.insert(0, data[limit:])
            data = data[:limit]
        ancillary, self.ancillary = self.ancillary, []
        return data, ancillary, self.flags, None

    def send(self, value):
        count = min(3, len(value))
        self.sent.extend(value[:count])
        return count

    def shutdown(self, direction):
        assert direction == socket.SHUT_WR
        self.closed_write = True


@pytest.fixture(autouse=True)
def fake_linux_features(monkeypatch):
    monkeypatch.setattr(socket, "AF_UNIX", FakeStream.family, raising=False)
    monkeypatch.setattr(transport, "_LINUX", True)
    monkeypatch.setattr(transport, "_SO_PEERCRED", 17)
    monkeypatch.setattr(transport, "_SCM_RIGHTS", 1)
    monkeypatch.setattr(transport, "_CMSG_SPACE", lambda size: size + 16)
    monkeypatch.setattr(transport, "_MSG_CTRUNC", 8)
    monkeypatch.setattr(transport, "_MSG_TRUNC", 32)
    monkeypatch.setattr(transport, "_MSG_CMSG_CLOEXEC", 0)


def test_fragmented_receive_checks_uid_and_single_frame_eof():
    frame = encode_frame(FrameKind.REQUEST, b"synthetic payload")
    stream = FakeStream([frame[:1], frame[1:9], frame[9:15], frame[15:], b""])
    assert receive_frame(
        stream, expected_uid=123, allowed_kinds=frozenset({FrameKind.REQUEST}), timeout=5
    ) == (FrameKind.REQUEST, b"synthetic payload")


def test_bad_peer_is_rejected_before_any_read_or_send():
    stream = FakeStream(uid=124)
    with pytest.raises(TransportError):
        receive_frame(
            stream, expected_uid=123, allowed_kinds=frozenset({FrameKind.REQUEST}), timeout=5
        )
    assert stream.read_calls == 0
    with pytest.raises(TransportError):
        send_frame(stream, FrameKind.REQUEST, b"sensitive content", expected_uid=123, timeout=5)
    assert not stream.sent


@pytest.mark.parametrize(
    "data",
    [
        b"",
        encode_frame(FrameKind.REQUEST, b"x")[:-1],
        encode_frame(FrameKind.REQUEST, b"x") + b"extra",
    ],
)
def test_truncation_and_trailing_bytes_are_rejected(data):
    with pytest.raises(TransportError):
        receive_frame(
            FakeStream([data]),
            expected_uid=123,
            allowed_kinds=frozenset({FrameKind.REQUEST}),
            timeout=5,
        )


def test_header_over_limit_is_rejected_without_reading_body():
    header = struct.pack("!4sBBHI", b"MGIP", 1, 1, 0, MAX_REQUEST_BYTES + 1)
    stream = FakeStream([header, b"not read"])
    with pytest.raises(TransportError):
        receive_frame(
            stream, expected_uid=123, allowed_kinds=frozenset({FrameKind.REQUEST}), timeout=5
        )
    assert stream.read_calls == 1


def test_unexpected_fd_is_closed_and_rejected(monkeypatch):
    closed = []
    monkeypatch.setattr(transport.os, "close", closed.append)
    stream = FakeStream([encode_frame(FrameKind.REQUEST, b"x")])
    stream.ancillary = [(socket.SOL_SOCKET, 1, array.array("i", [41, 42]).tobytes())]
    with pytest.raises(TransportError):
        receive_frame(
            stream, expected_uid=123, allowed_kinds=frozenset({FrameKind.REQUEST}), timeout=5
        )
    assert closed == [41, 42]


def test_send_handles_partial_writes_and_half_closes():
    stream = FakeStream()
    send_frame(stream, FrameKind.REQUEST, b"synthetic", expected_uid=123, timeout=5)
    assert bytes(stream.sent) == encode_frame(FrameKind.REQUEST, b"synthetic")
    assert stream.closed_write


def test_unsupported_os_fails_before_io(monkeypatch):
    monkeypatch.setattr(transport, "_LINUX", False)
    stream = FakeStream()
    with pytest.raises(TransportError):
        receive_frame(
            stream, expected_uid=123, allowed_kinds=frozenset({FrameKind.REQUEST}), timeout=5
        )
    assert stream.read_calls == 0


def test_wrong_kind_and_ancillary_truncation_reject_before_body():
    stream = FakeStream([encode_frame(FrameKind.SUCCESS, b"x")])
    with pytest.raises(TransportError):
        receive_frame(
            stream, expected_uid=123, allowed_kinds=frozenset({FrameKind.REQUEST}), timeout=5
        )
    assert stream.read_calls == 1
    stream = FakeStream([encode_frame(FrameKind.REQUEST, b"x")])
    stream.flags = 8
    with pytest.raises(TransportError):
        receive_frame(
            stream, expected_uid=123, allowed_kinds=frozenset({FrameKind.REQUEST}), timeout=5
        )


def test_absolute_deadline_does_not_restart_between_fragments(monkeypatch):
    moments = iter([0.0, 0.1, 1.1])
    monkeypatch.setattr(transport, "time", SimpleNamespace(monotonic=lambda: next(moments)))
    stream = FakeStream([b"M", b"GIP"])
    with pytest.raises(TransportError):
        receive_frame(
            stream, expected_uid=123, allowed_kinds=frozenset({FrameKind.REQUEST}), timeout=1
        )
    assert stream.read_calls == 1


def test_short_send_failure_is_generic_and_does_not_half_close():
    stream = FakeStream()
    stream.send = lambda _data: 0
    with pytest.raises(TransportError) as error:
        send_frame(stream, FrameKind.REQUEST, b"private payload", expected_uid=123, timeout=5)
    assert "private payload" not in str(error.value)
    assert not stream.closed_write


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), 10**1000, True])
def test_invalid_timeouts_fail_closed(timeout):
    stream = FakeStream()
    with pytest.raises(TransportError):
        receive_frame(
            stream, expected_uid=123, allowed_kinds=frozenset({FrameKind.REQUEST}), timeout=timeout
        )
    assert stream.read_calls == 0


def test_transport_import_does_not_load_native_parsers():
    command = (
        "import sys; import metaguard_api.processing_ipc_transport; "
        "assert 'pikepdf' not in sys.modules; assert 'PIL' not in sys.modules; "
        "assert 'metaguard_api.processing_worker' not in sys.modules"
    )
    result = subprocess.run([sys.executable, "-c", command], capture_output=True, check=False)
    assert result.returncode == 0
