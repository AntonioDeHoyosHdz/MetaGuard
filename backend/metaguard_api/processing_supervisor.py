"""Fixed-schema Docker supervisor for the private file processor."""

from __future__ import annotations

import base64
import binascii
import json
import subprocess
import threading
import uuid
from collections.abc import Callable
from typing import BinaryIO

from metaguard_api.file_processing import (
    MAX_FILE_SIZE,
    MAX_IMAGE_PIXELS,
    MAX_IMAGE_SIDE,
    MAX_PDF_PAGES,
    ProcessedFile,
    ProcessingReport,
)
from metaguard_api.processing_worker import MAX_RESPONSE_BYTES

PROCESSOR_IMAGE = "metaguard-processor:local"
PROCESSOR_TIMEOUT_SECONDS = 60
CONTAINER_MEMORY = "1g"
CONTAINER_CPUS = "1.0"
CONTAINER_PIDS_LIMIT = "64"
MAX_OUTPUT_BYTES = MAX_RESPONSE_BYTES
CONTAINER_TMPFS_BYTES = 64 * 1024 * 1024
_ALLOWED_MEDIA_TYPES = frozenset({"image/jpeg", "image/png", "application/pdf"})
_ALLOWED_METADATA_CATEGORIES = frozenset(
    {
        "author",
        "color_profile",
        "date_time",
        "device_model",
        "document_info",
        "gps",
        "image_metadata",
        "manufacturer_notes",
        "path",
        "serial_number",
        "software",
        "thumbnail",
        "xmp",
    }
)
_REPORT_KEYS = frozenset(
    {
        "media_type",
        "metadata_categories",
        "output_verified",
        "width",
        "height",
        "page_count",
        "active_content_removed",
        "uri_links_removed",
    }
)

Runner = Callable[..., subprocess.CompletedProcess[bytes]]


class ProcessingSupervisorError(RuntimeError):
    """Raised when an isolated processing job cannot safely complete."""


class ProcessorOutputLimitExceeded(RuntimeError):
    """Raised when the worker writes more than the bounded stdout allowance."""


class BoundedProcessRunner:
    """Collect bounded stdout while discarding stderr and killing overproducers."""

    def __init__(self, process_factory: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen):
        self._process_factory = process_factory

    def __call__(
        self,
        command: list[str],
        *,
        input: bytes,
        timeout: int,
        max_stdout_bytes: int,
    ) -> subprocess.CompletedProcess[bytes]:
        process = self._process_factory(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
        if process.stdin is None or process.stdout is None:
            process.kill()
            raise ProcessingSupervisorError("Processor streams could not be opened")

        output = bytearray()
        output_exceeded = threading.Event()
        stream_errors: list[Exception] = []

        def collect_stdout(stream: BinaryIO) -> None:
            try:
                while True:
                    remaining = max_stdout_bytes - len(output)
                    chunk = stream.read(min(64 * 1024, remaining + 1))
                    if not chunk:
                        break
                    if len(chunk) > remaining:
                        output.extend(chunk[:remaining])
                        output_exceeded.set()
                        _kill_process(process)
                        break
                    output.extend(chunk)
            except Exception as exc:  # pragma: no cover - platform pipe failure
                stream_errors.append(exc)

        def send_input(stream: BinaryIO) -> None:
            try:
                stream.write(input)
                stream.flush()
            except (BrokenPipeError, OSError, ValueError):
                # A worker may reject early or be killed for output/time limits.
                pass
            finally:
                try:
                    stream.close()
                except OSError:
                    pass

        reader = threading.Thread(target=collect_stdout, args=(process.stdout,), daemon=True)
        writer = threading.Thread(target=send_input, args=(process.stdin,), daemon=True)
        reader.start()
        writer.start()
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process(process)
        finally:
            if timed_out or output_exceeded.is_set():
                _kill_process(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _kill_process(process)
            writer.join(timeout=5)
            reader.join(timeout=5)
            if writer.is_alive() or reader.is_alive():
                _close_process_streams(process)
                _kill_process(process)

        if timed_out:
            raise subprocess.TimeoutExpired(command, timeout)
        if output_exceeded.is_set():
            raise ProcessorOutputLimitExceeded("Processor output exceeds the size limit")
        if writer.is_alive() or reader.is_alive() or stream_errors:
            raise ProcessingSupervisorError("Processor streams did not close safely")
        return subprocess.CompletedProcess(command, process.returncode, bytes(output), b"")


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.kill()
    except OSError:
        pass


def _close_process_streams(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdin, process.stdout):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProcessingSupervisorError("Processor returned an invalid response")
        result[key] = value
    return result


class ProcessingSupervisor:
    """Run exactly one processor request with fixed, non-configurable Docker flags."""

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner = runner or BoundedProcessRunner()

    def process(self, data: bytes, content_type: str) -> ProcessedFile:
        """Process bytes through the fixed worker image and enforce its response schema."""
        if not isinstance(data, bytes) or not data or len(data) > MAX_FILE_SIZE:
            raise ProcessingSupervisorError("Input is empty or exceeds the processor size limit")
        if not isinstance(content_type, str) or content_type not in _ALLOWED_MEDIA_TYPES:
            raise ProcessingSupervisorError("Unsupported media type")

        payload = json.dumps(
            {
                "content_type": content_type,
                "data_base64": base64.b64encode(data).decode("ascii"),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        container_name = f"metaguard-processor-{uuid.uuid4().hex}"
        command = [
            "docker",
            "run",
            "--pull=never",
            "--interactive",
            "--name",
            container_name,
            "--network=none",
            "--read-only",
            "--user=65532:65532",
            f"--memory={CONTAINER_MEMORY}",
            f"--memory-swap={CONTAINER_MEMORY}",
            f"--cpus={CONTAINER_CPUS}",
            f"--pids-limit={CONTAINER_PIDS_LIMIT}",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={CONTAINER_TMPFS_BYTES}",
            "--log-driver=none",
            PROCESSOR_IMAGE,
            "python",
            "-m",
            "metaguard_api.processing_worker",
        ]

        primary_error: ProcessingSupervisorError | None = None
        processed: ProcessedFile | None = None
        cleanup_failed = False
        try:
            try:
                completed = self._runner(
                    command,
                    input=payload,
                    timeout=PROCESSOR_TIMEOUT_SECONDS,
                    max_stdout_bytes=MAX_OUTPUT_BYTES,
                )
            except subprocess.TimeoutExpired as exc:
                raise ProcessingSupervisorError("Processing timed out") from exc
            except ProcessorOutputLimitExceeded as exc:
                raise ProcessingSupervisorError("Processor output exceeds the size limit") from exc
            except OSError as exc:
                raise ProcessingSupervisorError("Processor container could not be started") from exc
            if completed.returncode != 0:
                raise ProcessingSupervisorError("Processor container failed")
            if not isinstance(completed.stdout, bytes) or len(completed.stdout) > MAX_OUTPUT_BYTES:
                raise ProcessingSupervisorError("Processor output exceeds the size limit")
            processed = _decode_response(completed.stdout, content_type)
        except ProcessingSupervisorError as exc:
            primary_error = exc
        finally:
            try:
                cleanup = self._runner(
                    ["docker", "rm", "--force", container_name],
                    input=b"",
                    timeout=10,
                    max_stdout_bytes=4096,
                )
            except (OSError, subprocess.TimeoutExpired):
                cleanup_failed = True
            else:
                cleanup_failed = cleanup.returncode != 0

        if primary_error is not None:
            if cleanup_failed:
                raise ProcessingSupervisorError(
                    f"{primary_error}; container cleanup failed"
                ) from primary_error
            raise primary_error
        if cleanup_failed:
            raise ProcessingSupervisorError("Processor cleanup failed")
        if processed is None:
            raise ProcessingSupervisorError("Processor returned no result")
        return processed


def _decode_response(raw_response: bytes, expected_media_type: str) -> ProcessedFile:
    try:
        response = json.loads(
            raw_response.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProcessingSupervisorError("Processor returned an invalid response") from exc
    if not isinstance(response, dict) or frozenset(response) != {
        "cleaned_bytes_base64",
        "media_type",
        "report",
    }:
        raise ProcessingSupervisorError("Processor returned an invalid response")

    encoded_data = response["cleaned_bytes_base64"]
    media_type = response["media_type"]
    raw_report = response["report"]
    if (
        not isinstance(encoded_data, str)
        or not isinstance(media_type, str)
        or media_type != expected_media_type
        or not isinstance(raw_report, dict)
        or frozenset(raw_report) != _REPORT_KEYS
    ):
        raise ProcessingSupervisorError("Processor returned an invalid response")
    try:
        cleaned_bytes = base64.b64decode(encoded_data.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ProcessingSupervisorError("Processor returned invalid file bytes") from exc
    if not cleaned_bytes or len(cleaned_bytes) > MAX_FILE_SIZE:
        raise ProcessingSupervisorError("Processor output exceeds the file size limit")

    report_type = raw_report["media_type"]
    categories = raw_report["metadata_categories"]
    verified = raw_report["output_verified"]
    active_content = raw_report["active_content_removed"]
    uri_count = raw_report["uri_links_removed"]
    dimensions = (raw_report["width"], raw_report["height"], raw_report["page_count"])
    if (
        report_type != media_type
        or not isinstance(categories, list)
        or len(categories) > len(_ALLOWED_METADATA_CATEGORIES)
        or any(
            not isinstance(category, str) or category not in _ALLOWED_METADATA_CATEGORIES
            for category in categories
        )
        or len(categories) != len(set(categories))
        or verified is not True
        or not isinstance(active_content, bool)
        or not isinstance(uri_count, int)
        or isinstance(uri_count, bool)
        or uri_count < 0
        or any(
            value is not None
            and (not isinstance(value, int) or isinstance(value, bool) or value < 0)
            for value in dimensions
        )
    ):
        raise ProcessingSupervisorError("Processor returned an invalid report")

    width, height, page_count = dimensions
    if media_type in {"image/jpeg", "image/png"}:
        if (
            not _is_integer(width)
            or not _is_integer(height)
            or width < 1
            or height < 1
            or width > MAX_IMAGE_SIDE
            or height > MAX_IMAGE_SIDE
            or width * height > MAX_IMAGE_PIXELS
            or page_count is not None
        ):
            raise ProcessingSupervisorError("Processor returned invalid image dimensions")
    elif (
        width is not None
        or height is not None
        or not _is_integer(page_count)
        or page_count < 1
        or page_count > MAX_PDF_PAGES
    ):
        raise ProcessingSupervisorError("Processor returned invalid PDF dimensions")

    report = ProcessingReport(
        media_type=media_type,
        metadata_categories=tuple(categories),
        output_verified=True,
        width=raw_report["width"],
        height=raw_report["height"],
        page_count=raw_report["page_count"],
        active_content_removed=active_content,
        uri_links_removed=uri_count,
    )
    return ProcessedFile(cleaned_bytes=cleaned_bytes, media_type=media_type, report=report)


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
