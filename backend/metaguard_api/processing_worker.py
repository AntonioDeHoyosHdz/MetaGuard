"""Strict stdin/stdout protocol for the isolated file-processing container."""

from __future__ import annotations

import base64
import binascii
import json
import sys
from dataclasses import asdict
from typing import Any

from metaguard_api.file_processing import (
    MAX_FILE_SIZE,
    FileProcessingError,
    ProcessedFile,
    process_file,
)
from metaguard_api.processing_limits import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES

_ALLOWED_MEDIA_TYPES = frozenset({"image/jpeg", "image/png", "application/pdf"})
_REQUEST_KEYS = frozenset({"content_type", "data_base64"})


class WorkerProtocolError(ValueError):
    """Raised when a worker message is malformed or outside its fixed schema."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WorkerProtocolError("Duplicate request keys are not allowed")
        result[key] = value
    return result


def decode_worker_request(request_bytes: bytes) -> tuple[bytes, str]:
    """Decode only the fixed worker input schema without processing the file."""
    if not isinstance(request_bytes, bytes) or not request_bytes:
        raise WorkerProtocolError("Request must be non-empty bytes")
    if len(request_bytes) > MAX_REQUEST_BYTES:
        raise WorkerProtocolError("Request exceeds the protocol size limit")

    try:
        payload = json.loads(
            request_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise WorkerProtocolError("Request is not valid JSON") from exc
    if not isinstance(payload, dict) or frozenset(payload) != _REQUEST_KEYS:
        raise WorkerProtocolError("Request does not match the worker schema")

    content_type = payload["content_type"]
    encoded_data = payload["data_base64"]
    if not isinstance(content_type, str) or content_type not in _ALLOWED_MEDIA_TYPES:
        raise WorkerProtocolError("Unsupported media type")
    if not isinstance(encoded_data, str):
        raise WorkerProtocolError("Encoded file must be a string")
    try:
        data = base64.b64decode(encoded_data.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise WorkerProtocolError("Encoded file is invalid") from exc
    if not data or len(data) > MAX_FILE_SIZE:
        raise WorkerProtocolError("File exceeds the processor size limit")

    return data, content_type


def process_request(request_bytes: bytes) -> bytes:
    """Decode one bounded request, call the pure processor, and encode its result."""
    data, content_type = decode_worker_request(request_bytes)

    try:
        result = process_file(data, content_type)
    except FileProcessingError:
        raise
    if not isinstance(result, ProcessedFile):
        raise WorkerProtocolError("Processor returned an invalid result")
    if (
        not isinstance(result.cleaned_bytes, bytes)
        or not result.cleaned_bytes
        or len(result.cleaned_bytes) > MAX_FILE_SIZE
        or result.media_type != content_type
        or not result.report.output_verified
    ):
        raise WorkerProtocolError("Processor returned an invalid result")

    response = json.dumps(
        {
            "cleaned_bytes_base64": base64.b64encode(result.cleaned_bytes).decode("ascii"),
            "media_type": result.media_type,
            "report": asdict(result.report),
        },
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(response) > MAX_RESPONSE_BYTES:
        raise WorkerProtocolError("Processor output exceeds the protocol size limit")
    return response


def main() -> int:
    """Read one request from stdin and emit only its result on stdout."""
    request = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    try:
        response = process_request(request)
    except (WorkerProtocolError, FileProcessingError):
        sys.stderr.write("processing request rejected\n")
        return 2
    sys.stdout.buffer.write(response)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
