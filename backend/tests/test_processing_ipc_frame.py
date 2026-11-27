"""In-memory protocol checks; these do not authenticate peers or run a service."""

import struct

import pytest

from metaguard_api.processing_ipc_frame import (
    HEADER_SIZE,
    FrameKind,
    FrameProtocolError,
    decode_frame,
    decode_header,
    encode_frame,
)
from metaguard_api.processing_worker import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES


@pytest.mark.parametrize("kind", [FrameKind.REQUEST, FrameKind.SUCCESS, FrameKind.ERROR])
def test_round_trip_one_frame(kind):
    payload = b"" if kind is FrameKind.ERROR else b"synthetic payload"
    frame = encode_frame(kind, payload)
    assert decode_frame(frame) == (kind, payload)
    assert decode_header(frame[:HEADER_SIZE]) == (kind, len(payload))


@pytest.mark.parametrize(
    "header",
    [
        b"",
        struct.pack("!4sBBHI", b"BAD!", 1, 1, 0, 1),
        struct.pack("!4sBBHI", b"MGIP", 2, 1, 0, 1),
        struct.pack("!4sBBHI", b"MGIP", 1, 9, 0, 1),
        struct.pack("!4sBBHI", b"MGIP", 1, 1, 1, 1),
        struct.pack("!4sBBHI", b"MGIP", 1, 1, 0, 0),
        struct.pack("!4sBBHI", b"MGIP", 1, 3, 0, 1),
        struct.pack("!4sBBHI", b"MGIP", 1, 1, 0, MAX_REQUEST_BYTES + 1),
        struct.pack("!4sBBHI", b"MGIP", 1, 2, 0, MAX_RESPONSE_BYTES + 1),
        struct.pack("!4sBBHI", b"MGIP", 1, 1, 0, 2**32 - 1),
    ],
)
def test_rejects_invalid_or_oversized_header_before_body(header):
    with pytest.raises(FrameProtocolError):
        decode_header(header)


@pytest.mark.parametrize(
    "kind,maximum",
    [(FrameKind.REQUEST, MAX_REQUEST_BYTES), (FrameKind.SUCCESS, MAX_RESPONSE_BYTES)],
)
def test_header_allows_exact_size_limit(kind, maximum):
    header = struct.pack("!4sBBHI", b"MGIP", 1, kind.value, 0, maximum)
    assert decode_header(header) == (kind, maximum)


def test_frame_rejects_truncation_trailing_data_and_second_frame():
    frame = encode_frame(FrameKind.REQUEST, b"synthetic")
    for candidate in (frame[:-1], frame + b"x", frame + frame):
        with pytest.raises(FrameProtocolError):
            decode_frame(candidate)


@pytest.mark.parametrize(
    "kind,payload",
    [
        (FrameKind.REQUEST, b""),
        (FrameKind.SUCCESS, b""),
        (FrameKind.ERROR, b"private detail"),
        (1, b"x"),
        (FrameKind.REQUEST, "x"),
    ],
)
def test_encoder_rejects_invalid_values_without_leaking_payload(kind, payload):
    with pytest.raises(FrameProtocolError) as error:
        encode_frame(kind, payload)
    assert "private detail" not in str(error.value)


def test_encoder_rejects_oversized_body():
    with pytest.raises(FrameProtocolError):
        encode_frame(FrameKind.REQUEST, b"x" * (MAX_REQUEST_BYTES + 1))


@pytest.mark.parametrize(
    "kind,maximum",
    [(FrameKind.REQUEST, MAX_REQUEST_BYTES), (FrameKind.SUCCESS, MAX_RESPONSE_BYTES)],
)
def test_exact_limit_payload_round_trips(kind, maximum):
    payload = b"x" * maximum
    assert decode_frame(encode_frame(kind, payload)) == (kind, payload)
