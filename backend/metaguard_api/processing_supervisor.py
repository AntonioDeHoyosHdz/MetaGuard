"""Fixed-schema Docker supervisor for the private file processor."""

from __future__ import annotations

import base64
import json
import posixpath
import re
import subprocess
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO

from metaguard_api.processing_errors import (
    ProcessingSupervisorCleanupError,
    ProcessingSupervisorError,
)
from metaguard_api.processing_limits import MAX_FILE_SIZE, MAX_RESPONSE_BYTES
from metaguard_api.processing_response import _decode_response
from metaguard_api.processing_types import ProcessedFile

PROCESSOR_TIMEOUT_SECONDS = 60
CONTAINER_MEMORY = "1g"
CONTAINER_CPUS = "1.0"
CONTAINER_PIDS_LIMIT = "64"
MAX_OUTPUT_BYTES = MAX_RESPONSE_BYTES
CONTAINER_TMPFS_BYTES = 64 * 1024 * 1024
_ALLOWED_MEDIA_TYPES = frozenset({"image/jpeg", "image/png", "application/pdf"})
Runner = Callable[..., subprocess.CompletedProcess[bytes]]


def _absolute_linux_path(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.isprintable()
        and value.startswith("/")
        and not value.startswith("//")
        and value != "/"
        and posixpath.normpath(value) == value
    )


@dataclass(frozen=True, slots=True)
class DockerRuntimeConfig:
    """Trusted Linux host configuration, never populated from a job request.

    Paths, socket ownership and image provenance must be verified by the host
    operator; syntax validation alone cannot establish trust.
    """

    executable: str
    daemon_socket: str
    config_dir: str
    image: str

    def __post_init__(self) -> None:
        if (
            not all(
                _absolute_linux_path(path)
                for path in (self.executable, self.daemon_socket, self.config_dir)
            )
            or not isinstance(self.image, str)
            or not re.fullmatch(r"(?:[a-z0-9][a-z0-9._:/-]*@)?sha256:[a-f0-9]{64}", self.image)
        ):
            raise ValueError("Invalid trusted Docker runtime configuration")

    def environment(self) -> dict[str, str]:
        return {"DOCKER_HOST": f"unix://{self.daemon_socket}", "DOCKER_CONFIG": self.config_dir}


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
        env: dict[str, str],
    ) -> subprocess.CompletedProcess[bytes]:
        process = self._process_factory(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            env=env,
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


class ProcessingSupervisor:
    """Run exactly one processor request with fixed, non-configurable Docker flags."""

    def __init__(self, runtime: DockerRuntimeConfig, runner: Runner | None = None) -> None:
        if not isinstance(runtime, DockerRuntimeConfig):
            raise ValueError("Trusted Docker runtime configuration is required")
        self._runtime = runtime
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
            self._runtime.executable,
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
            self._runtime.image,
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
                    env=self._runtime.environment(),
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
                    [self._runtime.executable, "rm", "--force", container_name],
                    input=b"",
                    timeout=10,
                    max_stdout_bytes=4096,
                    env=self._runtime.environment(),
                )
            except Exception:
                cleanup_failed = True
            else:
                cleanup_failed = cleanup.returncode != 0

        if primary_error is not None:
            if cleanup_failed:
                raise ProcessingSupervisorCleanupError(
                    f"{primary_error}; container cleanup failed"
                ) from primary_error
            raise primary_error
        if cleanup_failed:
            raise ProcessingSupervisorCleanupError("Processor cleanup failed")
        if processed is None:
            raise ProcessingSupervisorError("Processor returned no result")
        return processed
