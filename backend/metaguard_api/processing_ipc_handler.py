"""Private one-connection handler; no listener or public API is created."""

import base64
import json
import math
import threading
from dataclasses import asdict

from metaguard_api.file_processing import ProcessedFile
from metaguard_api.processing_ipc_frame import FrameKind
from metaguard_api.processing_ipc_transport import TransportError, receive_frame, send_frame
from metaguard_api.processing_limits import MAX_RESPONSE_BYTES
from metaguard_api.processing_supervisor import (
    ProcessingSupervisorCleanupError,
    ProcessingSupervisorError,
    _decode_response,
)
from metaguard_api.processing_worker import WorkerProtocolError, decode_worker_request


def _serialize_result(result: ProcessedFile, media_type: str) -> bytes:
    if not isinstance(result, ProcessedFile):
        raise ProcessingSupervisorError("Processor returned an invalid response")
    payload: dict[str, object] = {
        "cleaned_bytes_base64": base64.b64encode(result.cleaned_bytes).decode("ascii"),
        "media_type": result.media_type,
        "report": asdict(result.report),
    }
    if result.removed_pdf_links is not None:
        payload["removed_pdf_links"] = result.removed_pdf_links
    response = json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(response) > MAX_RESPONSE_BYTES:
        raise ProcessingSupervisorError("Processor returned an invalid response")
    _decode_response(response, media_type)
    return response


class ProcessingRequestHandler:
    """One shared handler admits one job at a time; uncertain cleanup disables it.

    This object is not a listener or recovery mechanism. A future service must
    share one handler across connections, close its listener when disabled, and
    reconcile orphaned containers before restarting after uncertain cleanup.
    """

    def __init__(self, supervisor, *, expected_uid: int, timeout: float) -> None:
        if (
            type(expected_uid) is not int
            or not 0 <= expected_uid <= 2**32 - 1
            or type(timeout) not in (int, float)
            or not 0 < timeout <= 120
            or not math.isfinite(timeout)
        ):
            raise ValueError("Invalid processing handler configuration")
        self._supervisor = supervisor
        self._expected_uid = expected_uid
        self._timeout = timeout
        self._admission = threading.Lock()
        self._state = threading.Lock()
        self._disabled = False

    @property
    def disabled(self) -> bool:
        with self._state:
            return self._disabled

    def _disable(self) -> None:
        with self._state:
            self._disabled = True

    def _send_error(self, connection) -> None:
        try:
            send_frame(
                connection,
                FrameKind.ERROR,
                b"",
                expected_uid=self._expected_uid,
                timeout=self._timeout,
            )
        except TransportError:
            pass

    def handle(self, connection) -> None:
        """Process one connection; close it even if admission or transfer fails."""
        acquired = self._admission.acquire(blocking=False)
        try:
            if not acquired or self.disabled:
                return
            try:
                _kind, payload = receive_frame(
                    connection,
                    expected_uid=self._expected_uid,
                    allowed_kinds=frozenset({FrameKind.REQUEST}),
                    timeout=self._timeout,
                )
            except TransportError:
                return
            try:
                data, media_type = decode_worker_request(payload)
            except WorkerProtocolError:
                self._send_error(connection)
                return
            try:
                result = self._supervisor.process(data, media_type)
                response = _serialize_result(result, media_type)
            except ProcessingSupervisorCleanupError:
                self._disable()
                self._send_error(connection)
                return
            except ProcessingSupervisorError:
                self._send_error(connection)
                return
            except Exception:
                self._disable()
                self._send_error(connection)
                return
            try:
                send_frame(
                    connection,
                    FrameKind.SUCCESS,
                    response,
                    expected_uid=self._expected_uid,
                    timeout=self._timeout,
                )
            except TransportError:
                pass
        finally:
            if acquired:
                self._admission.release()
            try:
                connection.close()
            except OSError:
                pass
