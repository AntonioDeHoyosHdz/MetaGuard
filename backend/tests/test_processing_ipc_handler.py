"""Private connection handler with simulated transport and supervisor."""

import base64
import json
import subprocess
import threading

import pytest

import metaguard_api.processing_ipc_handler as handler
from metaguard_api.file_processing import ProcessedFile, ProcessingReport
from metaguard_api.processing_ipc_frame import FrameKind
from metaguard_api.processing_ipc_transport import TransportError
from metaguard_api.processing_supervisor import (
    DockerRuntimeConfig,
    ProcessingSupervisor,
    ProcessingSupervisorCleanupError,
    ProcessingSupervisorError,
)


class Connection:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class Supervisor:
    def __init__(self):
        self.calls = []
        self.error = None
        self.result = ProcessedFile(
            b"clean", "image/png", ProcessingReport("image/png", (), True, width=1, height=1)
        )

    def process(self, data, media_type):
        self.calls.append((data, media_type))
        if self.error is not None:
            raise self.error
        return self.result


def request():
    return json.dumps(
        {"content_type": "image/png", "data_base64": base64.b64encode(b"source").decode()}
    ).encode()


@pytest.fixture
def io(monkeypatch):
    calls = {"payload": request(), "responses": [], "error": None}

    def receive(_stream, **kwargs):
        assert kwargs["allowed_kinds"] == frozenset({FrameKind.REQUEST})
        assert kwargs["expected_uid"] == 123
        if calls["error"]:
            raise calls["error"]
        return FrameKind.REQUEST, calls["payload"]

    def send(_stream, kind, payload, **kwargs):
        assert kwargs["expected_uid"] == 123
        calls["responses"].append((kind, payload))

    monkeypatch.setattr(handler, "receive_frame", receive)
    monkeypatch.setattr(handler, "send_frame", send)
    return calls


def test_valid_request_invokes_supervisor_and_emits_closed_response(io):
    supervisor = Supervisor()
    connection = Connection()
    worker = handler.ProcessingRequestHandler(supervisor, expected_uid=123, timeout=5)
    worker.handle(connection)
    assert supervisor.calls == [(b"source", "image/png")]
    kind, raw = io["responses"][0]
    result = json.loads(raw)
    assert kind is FrameKind.SUCCESS
    assert base64.b64decode(result["cleaned_bytes_base64"]) == b"clean"
    assert result["report"]["output_verified"] is True
    assert connection.closed


def test_pdf_inventory_survives_private_handler_round_trip(io):
    io["payload"] = request().replace(b"image/png", b"application/pdf")
    preview = "https://example.invalid/document"
    supervisor = Supervisor()
    supervisor.result = ProcessedFile(
        b"clean",
        "application/pdf",
        ProcessingReport("application/pdf", (), True, page_count=1, uri_links_removed=1),
        removed_pdf_links=(preview,),
    )
    connection = Connection()
    handler.ProcessingRequestHandler(supervisor, expected_uid=123, timeout=5).handle(connection)

    kind, raw = io["responses"][0]
    assert kind is FrameKind.SUCCESS
    assert json.loads(raw)["removed_pdf_links"] == [preview]
    assert handler._decode_response(raw, "application/pdf") == supervisor.result
    assert connection.closed


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b'{"content_type":"image/png","content_type":"image/png","data_base64":"eA=="}',
        b"bad",
        b"[" * 2000 + b"]" * 2000,
        b'{"number":' + b"1" * 5000 + b"}",
    ],
)
def test_invalid_payload_does_not_reach_supervisor(io, payload):
    io["payload"] = payload
    supervisor, connection = Supervisor(), Connection()
    handler.ProcessingRequestHandler(supervisor, expected_uid=123, timeout=5).handle(connection)
    assert supervisor.calls == []
    assert io["responses"] == [(FrameKind.ERROR, b"")]
    assert connection.closed


def test_failed_peer_receives_no_response_or_processing(io):
    io["error"] = TransportError("private detail")
    supervisor, connection = Supervisor(), Connection()
    handler.ProcessingRequestHandler(supervisor, expected_uid=123, timeout=5).handle(connection)
    assert supervisor.calls == [] and io["responses"] == [] and connection.closed


def test_supervisor_failure_is_generic_and_cleanup_failure_latches(io):
    supervisor = Supervisor()
    supervisor.error = ProcessingSupervisorCleanupError("private detail")
    worker = handler.ProcessingRequestHandler(supervisor, expected_uid=123, timeout=5)
    first, second = Connection(), Connection()
    worker.handle(first)
    worker.handle(second)
    assert io["responses"] == [(FrameKind.ERROR, b"")]
    assert len(supervisor.calls) == 1
    assert first.closed and second.closed and worker.disabled


def test_normal_processing_failure_allows_later_request(io):
    supervisor = Supervisor()
    supervisor.error = ProcessingSupervisorError("bad file")
    worker = handler.ProcessingRequestHandler(supervisor, expected_uid=123, timeout=5)
    worker.handle(Connection())
    supervisor.error = None
    worker.handle(Connection())
    assert [kind for kind, _ in io["responses"]] == [FrameKind.ERROR, FrameKind.SUCCESS]
    assert not worker.disabled


def test_unverified_result_never_emits_success(io):
    supervisor, connection = Supervisor(), Connection()
    supervisor.result = ProcessedFile(
        b"clean", "image/png", ProcessingReport("image/png", (), False, width=1, height=1)
    )
    worker = handler.ProcessingRequestHandler(supervisor, expected_uid=123, timeout=5)
    worker.handle(connection)
    assert io["responses"] == [(FrameKind.ERROR, b"")]
    assert connection.closed


def test_unexpected_supervisor_error_disables_future_jobs(io):
    supervisor = Supervisor()
    supervisor.error = RuntimeError("sensitive exception")
    worker = handler.ProcessingRequestHandler(supervisor, expected_uid=123, timeout=5)
    first, second = Connection(), Connection()
    worker.handle(first)
    worker.handle(second)
    assert io["responses"] == [(FrameKind.ERROR, b"")]
    assert len(supervisor.calls) == 1 and worker.disabled
    assert first.closed and second.closed


def test_failed_response_transport_closes_without_retry(io, monkeypatch):
    calls = []

    def failed_send(_connection, kind, _payload, **_kwargs):
        calls.append(kind)
        raise TransportError("private detail")

    monkeypatch.setattr(handler, "send_frame", failed_send)
    supervisor, connection = Supervisor(), Connection()
    handler.ProcessingRequestHandler(supervisor, expected_uid=123, timeout=5).handle(connection)
    assert calls == [FrameKind.SUCCESS]
    assert connection.closed


def test_admission_stays_held_until_supervisor_returns(io):
    entered, release = threading.Event(), threading.Event()
    supervisor = Supervisor()
    original = supervisor.process

    def slow(data, mime):
        entered.set()
        assert release.wait(5)
        return original(data, mime)

    supervisor.process = slow
    worker = handler.ProcessingRequestHandler(supervisor, expected_uid=123, timeout=5)
    first, second = Connection(), Connection()
    thread = threading.Thread(target=worker.handle, args=(first,))
    thread.start()
    try:
        assert entered.wait(5)
        worker.handle(second)
        assert second.closed and not first.closed and supervisor.calls == []
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive() and first.closed and len(supervisor.calls) == 1


def test_cleanup_runner_error_disables_handler_before_another_job(io):
    calls = []

    def runner(command, **_kwargs):
        calls.append(command[1])
        if command[1] == "rm":
            raise ProcessingSupervisorError("stream failure")
        return subprocess.CompletedProcess(command, 1, b"", b"")

    runtime = DockerRuntimeConfig(
        "/usr/bin/docker", "/run/docker.sock", "/etc/docker", "sha256:" + "a" * 64
    )
    worker = handler.ProcessingRequestHandler(
        ProcessingSupervisor(runtime, runner), expected_uid=123, timeout=5
    )
    worker.handle(Connection())
    worker.handle(Connection())
    assert calls == ["run", "rm"]
    assert worker.disabled


def test_malformed_worker_integer_rejects_without_disabling_after_cleanup(io):
    calls = []

    def runner(command, **_kwargs):
        calls.append(command[1])
        output = b'{"x":' + b"1" * 5000 + b"}" if command[1] == "run" else b""
        return subprocess.CompletedProcess(command, 0, output, b"")

    runtime = DockerRuntimeConfig(
        "/usr/bin/docker", "/run/docker.sock", "/etc/docker", "sha256:" + "a" * 64
    )
    worker = handler.ProcessingRequestHandler(
        ProcessingSupervisor(runtime, runner), expected_uid=123, timeout=5
    )
    worker.handle(Connection())
    assert calls == ["run", "rm"]
    assert io["responses"] == [(FrameKind.ERROR, b"")]
    assert not worker.disabled
