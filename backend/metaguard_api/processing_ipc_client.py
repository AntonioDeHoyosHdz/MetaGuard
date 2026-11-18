"""Private Linux IPC client; no public endpoint or file parser is provided."""

import base64
import json
import math
import posixpath
import socket
import sys
from dataclasses import dataclass

from metaguard_api.processing_errors import ProcessingSupervisorError
from metaguard_api.processing_ipc_frame import FrameKind
from metaguard_api.processing_ipc_transport import TransportError, receive_frame, send_frame
from metaguard_api.processing_limits import MAX_FILE_SIZE
from metaguard_api.processing_response import _decode_response
from metaguard_api.processing_types import ProcessedFile

_LINUX = sys.platform == "linux"
_MEDIA_TYPES = frozenset({"image/jpeg", "image/png", "application/pdf"})


class ProcessingClientError(RuntimeError):
    """Private processing could not be completed; details are never exposed."""


@dataclass(frozen=True, slots=True)
class ProcessingClientConfig:
    """Trusted operator configuration; request data must not select these values."""

    socket_path: str
    server_uid: int
    timeout: float

    def __post_init__(self) -> None:
        if (
            not isinstance(self.socket_path, str)
            or not self.socket_path.isprintable()
            or not self.socket_path.startswith("/")
            or self.socket_path.startswith("//")
            or self.socket_path == "/"
            or posixpath.normpath(self.socket_path) != self.socket_path
            or len(self.socket_path.encode("utf-8")) > 107
            or type(self.server_uid) is not int
            or not 0 <= self.server_uid <= 2**32 - 1
            or type(self.timeout) not in (int, float)
            or not 0 < self.timeout <= 120
            or not math.isfinite(self.timeout)
        ):
            raise ValueError("Invalid processing client configuration")


class ProcessingClient:
    """Submit one bounded file to the configured private supervisor."""

    def __init__(self, config: ProcessingClientConfig) -> None:
        if not isinstance(config, ProcessingClientConfig):
            raise ValueError("Trusted processing client configuration is required")
        self._config = config

    def process(self, data: bytes, content_type: str) -> ProcessedFile:
        """Return a schema-validated result; caller handles auth and safe delivery."""
        if (
            not _LINUX
            or not isinstance(data, bytes)
            or not data
            or len(data) > MAX_FILE_SIZE
            or not isinstance(content_type, str)
            or content_type not in _MEDIA_TYPES
        ):
            raise ProcessingClientError("Processing unavailable")
        request = json.dumps(
            {"content_type": content_type, "data_base64": base64.b64encode(data).decode("ascii")},
            separators=(",", ":"),
        ).encode("utf-8")
        stream = None
        try:
            stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stream.settimeout(self._config.timeout)
            stream.connect(self._config.socket_path)
            send_frame(
                stream,
                FrameKind.REQUEST,
                request,
                expected_uid=self._config.server_uid,
                timeout=self._config.timeout,
            )
            kind, response = receive_frame(
                stream,
                expected_uid=self._config.server_uid,
                allowed_kinds=frozenset({FrameKind.SUCCESS, FrameKind.ERROR}),
                timeout=self._config.timeout,
            )
            if kind is not FrameKind.SUCCESS:
                raise ProcessingClientError("Processing unavailable")
            return _decode_response(response, content_type)
        except (OSError, TransportError, ProcessingSupervisorError):
            raise ProcessingClientError("Processing unavailable") from None
        finally:
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
