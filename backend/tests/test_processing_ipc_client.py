"""Private IPC client tests; fake streams do not establish Linux isolation."""

import base64
import json
import queue
import socket
import struct
import subprocess
import sys
import threading

import pytest

import metaguard_api.processing_ipc_client as client_module
from metaguard_api.processing_ipc_client import (
    ProcessingClient,
    ProcessingClientConfig,
    ProcessingClientError,
)
from metaguard_api.processing_ipc_frame import FrameKind
from metaguard_api.processing_ipc_transport import TransportError


class Socket:
    def __init__(self):
        self.closed = False
        self.path = None
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def connect(self, path):
        self.path = path

    def close(self):
        self.closed = True


def response():
    return json.dumps(
        {
            "cleaned_bytes_base64": base64.b64encode(b"clean").decode(),
            "media_type": "image/png",
            "report": {
                "media_type": "image/png",
                "metadata_categories": [],
                "output_verified": True,
                "width": 1,
                "height": 1,
                "page_count": None,
                "active_content_removed": False,
                "uri_links_removed": 0,
            },
        }
    ).encode()


@pytest.fixture
def io(monkeypatch):
    stream = Socket()
    state = {"sent": [], "kind": FrameKind.SUCCESS, "response": response(), "error": None}
    monkeypatch.setattr(client_module, "_LINUX", True)
    monkeypatch.setattr(socket, "AF_UNIX", getattr(socket, "AF_UNIX", 1), raising=False)
    monkeypatch.setattr(client_module.socket, "socket", lambda *_args: stream)

    def send(_stream, kind, payload, **kwargs):
        state["sent"].append((kind, payload, kwargs))

    def receive(_stream, **kwargs):
        assert kwargs["allowed_kinds"] == frozenset({FrameKind.SUCCESS, FrameKind.ERROR})
        if state["error"]:
            raise state["error"]
        return state["kind"], state["response"]

    monkeypatch.setattr(client_module, "send_frame", send)
    monkeypatch.setattr(client_module, "receive_frame", receive)
    return stream, state


def test_client_sends_only_file_and_type_and_validates_response(io):
    stream, state = io
    client = ProcessingClient(ProcessingClientConfig("/run/metaguard/processor.sock", 123, 90))
    result = client.process(b"source", "image/png")
    assert stream.path == "/run/metaguard/processor.sock" and stream.closed
    kind, payload, options = state["sent"][0]
    assert kind is FrameKind.REQUEST and options["expected_uid"] == 123
    request = json.loads(payload)
    assert set(request) == {"content_type", "data_base64"}
    assert base64.b64decode(request["data_base64"]) == b"source"
    assert request["content_type"] == "image/png"
    assert result.cleaned_bytes == b"clean" and result.report.output_verified is True


@pytest.mark.parametrize(
    "kind,payload",
    [
        (FrameKind.ERROR, b""),
        (FrameKind.SUCCESS, b"{}"),
        (FrameKind.SUCCESS, b'{"media_type":"image/png","media_type":"image/png"}'),
        (FrameKind.SUCCESS, b'{"private":"metadata"}'),
    ],
)
def test_failed_or_malformed_response_is_generic_and_closes(io, kind, payload):
    stream, state = io
    state["kind"], state["response"] = kind, payload
    with pytest.raises(ProcessingClientError) as error:
        ProcessingClient(ProcessingClientConfig("/run/metaguard/processor.sock", 123, 90)).process(
            b"x", "image/png"
        )
    assert "metadata" not in str(error.value)
    assert stream.closed


def test_transport_failure_is_sanitized_and_closes(io):
    stream, state = io
    state["error"] = TransportError("private system detail")
    with pytest.raises(ProcessingClientError) as error:
        ProcessingClient(ProcessingClientConfig("/run/metaguard/processor.sock", 123, 90)).process(
            b"x", "image/png"
        )
    assert "private" not in str(error.value) and stream.closed


@pytest.mark.parametrize(
    "path", ["relative.sock", "/run/../tmp/x", "//tmp/x", "/tmp/\x00sock", "/" + "a" * 108]
)
def test_untrusted_socket_path_is_rejected(path):
    with pytest.raises(ValueError):
        ProcessingClientConfig(path, 123, 90)


def test_invalid_upload_is_rejected_before_socket_creation(io):
    stream, state = io
    client = ProcessingClient(ProcessingClientConfig("/run/metaguard/processor.sock", 123, 90))
    with pytest.raises(ProcessingClientError):
        client.process(b"", "image/png")
    assert stream.path is None and not state["sent"]


def test_client_import_does_not_load_native_file_parsers():
    code = (
        "import sys; import metaguard_api.processing_ipc_client; "
        "assert 'PIL' not in sys.modules; assert 'pikepdf' not in sys.modules; "
        "assert 'metaguard_api.file_processing' not in sys.modules"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, check=False)
    assert result.returncode == 0


def test_client_and_handler_exchange_fragmented_frames_without_real_socket(monkeypatch):
    import metaguard_api.processing_ipc_transport as transport
    from metaguard_api.processing_ipc_handler import ProcessingRequestHandler
    from metaguard_api.processing_types import ProcessedFile, ProcessingReport

    monkeypatch.setattr(client_module, "_LINUX", True)
    monkeypatch.setattr(transport, "_LINUX", True)
    monkeypatch.setattr(socket, "AF_UNIX", getattr(socket, "AF_UNIX", 1), raising=False)
    for name, value in {
        "_SO_PEERCRED": 17,
        "_SCM_RIGHTS": 1,
        "_MSG_CTRUNC": 8,
        "_MSG_TRUNC": 32,
        "_MSG_CMSG_CLOEXEC": 0,
    }.items():
        monkeypatch.setattr(transport, name, value)
    monkeypatch.setattr(transport, "_CMSG_SPACE", lambda size: size + 16)

    class Stream:
        family = socket.AF_UNIX
        type = socket.SOCK_STREAM

        def __init__(self, peer_uid):
            self.peer_uid = peer_uid
            self.incoming = queue.Queue()
            self.pending = b""
            self.timeout = 2
            self.closed = False

        def getsockopt(self, *_args):
            return struct.pack("iII", 12, self.peer_uid, 0)

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, path):
            assert path == "/run/metaguard/worker.sock"

        def send(self, data):
            count = min(len(data), 7)
            self.peer.incoming.put(bytes(data[:count]))
            return count

        def shutdown(self, _direction):
            self.peer.incoming.put(b"")

        def recvmsg(self, count, *_args):
            if not self.pending:
                try:
                    self.pending = self.incoming.get(timeout=self.timeout)
                except queue.Empty:
                    raise TimeoutError from None
            data, self.pending = self.pending[:count], self.pending[count:]
            return data, [], 0, None

        def close(self):
            self.closed = True

    class Supervisor:
        def process(self, data, media):
            assert data == b"source" and media == "image/png"
            return ProcessedFile(
                b"clean", media, ProcessingReport(media, (), True, width=1, height=1)
            )

    client_stream, server_stream = Stream(222), Stream(111)
    client_stream.peer, server_stream.peer = server_stream, client_stream
    worker = ProcessingRequestHandler(Supervisor(), expected_uid=111, timeout=2)
    thread = threading.Thread(target=worker.handle, args=(server_stream,), daemon=True)
    thread.start()
    monkeypatch.setattr(client_module.socket, "socket", lambda *_args: client_stream)
    try:
        result = ProcessingClient(
            ProcessingClientConfig("/run/metaguard/worker.sock", 222, 2)
        ).process(b"source", "image/png")
    finally:
        thread.join(3)
    assert not thread.is_alive()
    assert result.cleaned_bytes == b"clean"
    assert client_stream.closed and server_stream.closed
