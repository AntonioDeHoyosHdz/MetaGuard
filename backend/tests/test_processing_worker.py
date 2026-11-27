"""Tests for the worker's strict stdin/stdout protocol."""

from __future__ import annotations

import base64
import json

import pytest

from metaguard_api.file_processing import ProcessedFile, ProcessingReport
from metaguard_api.processing_worker import WorkerProtocolError, process_request


def _request(data: bytes = b"source", **extra: object) -> bytes:
    payload: dict[str, object] = {
        "content_type": "image/png",
        "data_base64": base64.b64encode(data).decode("ascii"),
    }
    payload.update(extra)
    return json.dumps(payload).encode()


def test_worker_accepts_only_bytes_and_mime_and_returns_processor_output(monkeypatch) -> None:
    expected = ProcessedFile(
        b"clean",
        "image/png",
        ProcessingReport("image/png", (), True, width=1, height=1),
    )
    seen: list[tuple[bytes, str]] = []

    def processor(data: bytes, content_type: str) -> ProcessedFile:
        seen.append((data, content_type))
        return expected

    monkeypatch.setattr("metaguard_api.processing_worker.process_file", processor)
    result = json.loads(process_request(_request()))

    assert seen == [(b"source", "image/png")]
    assert set(result) == {"cleaned_bytes_base64", "media_type", "report"}
    assert base64.b64decode(result["cleaned_bytes_base64"]) == b"clean"
    assert result["media_type"] == "image/png"


def test_worker_emits_pdf_inventory_as_top_level_field(monkeypatch) -> None:
    def processor(_data: bytes, _content_type: str) -> ProcessedFile:
        return ProcessedFile(
            b"clean",
            "application/pdf",
            ProcessingReport("application/pdf", (), True, page_count=1, uri_links_removed=1),
            removed_pdf_links=("https://example.invalid/document",),
        )

    monkeypatch.setattr("metaguard_api.processing_worker.process_file", processor)
    result = json.loads(process_request(_request(content_type="application/pdf")))

    assert result["removed_pdf_links"] == ["https://example.invalid/document"]
    assert result["report"]["uri_links_removed"] == 1
    assert "removed_pdf_links" not in result["report"]


@pytest.mark.parametrize(
    "payload",
    [
        _request(extra="not allowed"),
        _request(docker_args=["--privileged"]),
        b'{"content_type":"image/png","content_type":"image/jpeg","data_base64":"eA=="}',
        b'{"content_type":"image/png","data_base64":"%%%"}',
        b'{"content_type":"text/plain","data_base64":"eA=="}',
    ],
)
def test_worker_rejects_non_strict_requests(payload: bytes) -> None:
    with pytest.raises(WorkerProtocolError):
        process_request(payload)


def test_worker_rejects_oversized_request_before_parsing() -> None:
    with pytest.raises(WorkerProtocolError, match="size limit"):
        process_request(b" " * (36 * 1024 * 1024 + 1))


def test_worker_rejects_empty_or_non_object_json() -> None:
    for payload in (b"", b"[]", b"null"):
        with pytest.raises(WorkerProtocolError):
            process_request(payload)
