"""Tests for the fixed-schema Docker processing boundary."""

from __future__ import annotations

import base64
import io
import json
import subprocess
from pathlib import Path

import pytest

from metaguard_api.file_processing import ProcessedFile, ProcessingReport
from metaguard_api.processing_supervisor import (
    MAX_OUTPUT_BYTES,
    BoundedProcessRunner,
    DockerRuntimeConfig,
    ProcessingSupervisor,
    ProcessingSupervisorError,
    ProcessorOutputLimitExceeded,
)


def _test_runtime() -> DockerRuntimeConfig:
    return DockerRuntimeConfig(
        executable="/usr/bin/docker",
        daemon_socket="/run/docker.sock",
        config_dir="/etc/metaguard/docker",
        image="metaguard-processor@sha256:" + "a" * 64,
    )


def _worker_result(data: bytes = b"clean") -> bytes:
    return json.dumps(
        {
            "cleaned_bytes_base64": base64.b64encode(data).decode("ascii"),
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


class FakeRunner:
    def __init__(self, result: subprocess.CompletedProcess[bytes] | None = None):
        self.result = result or subprocess.CompletedProcess([], 0, _worker_result(), b"")
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.side_effect: BaseException | None = None
        self.cleanup_returncode = 0

    def __call__(self, args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((args, kwargs))
        if args[1] == "rm":
            return subprocess.CompletedProcess(args, self.cleanup_returncode, b"", b"")
        if self.side_effect is not None:
            raise self.side_effect
        return self.result


def test_supervisor_uses_fixed_isolated_docker_options_and_returns_result() -> None:
    runner = FakeRunner()
    supervisor = ProcessingSupervisor(runtime=_test_runtime(), runner=runner)

    result = supervisor.process(b"source", "image/png")

    assert isinstance(result, ProcessedFile)
    assert result.cleaned_bytes == b"clean"
    command, options = runner.calls[0]
    assert command[:2] == ["/usr/bin/docker", "run"]
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--user=65532:65532" in command
    assert "--memory=1g" in command
    assert "--cpus=1.0" in command
    assert "--pids-limit=64" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--pull=never" in command
    assert not any(value in command for value in ("-v", "--volume", "--env", "-e"))
    assert command[-3:] == ["python", "-m", "metaguard_api.processing_worker"]
    payload = json.loads(options["input"])
    assert set(payload) == {"content_type", "data_base64"}
    assert payload["content_type"] == "image/png"
    assert base64.b64decode(payload["data_base64"]) == b"source"
    assert options["timeout"] == 60
    assert options["max_stdout_bytes"] == MAX_OUTPUT_BYTES
    assert "capture_output" not in options
    assert runner.calls[-1][0][:3] == ["/usr/bin/docker", "rm", "--force"]


@pytest.mark.parametrize(
    ("data", "content_type"),
    [(b"", "image/png"), (b"x" * (25 * 1024 * 1024 + 1), "image/png"), (b"x", "text/plain")],
)
def test_supervisor_rejects_invalid_input_before_starting_container(
    data: bytes, content_type: str
) -> None:
    runner = FakeRunner()
    with pytest.raises(ProcessingSupervisorError):
        ProcessingSupervisor(runtime=_test_runtime(), runner=runner).process(data, content_type)
    assert runner.calls == []


def test_supervisor_rejects_oversized_or_unverified_worker_output_and_cleans_container() -> None:
    oversized = subprocess.CompletedProcess([], 0, b"x" * (36 * 1024 * 1024), b"")
    runner = FakeRunner(oversized)
    with pytest.raises(ProcessingSupervisorError):
        ProcessingSupervisor(runtime=_test_runtime(), runner=runner).process(b"source", "image/png")
    assert runner.calls[-1][0][:3] == ["/usr/bin/docker", "rm", "--force"]


def test_supervisor_cleans_named_container_after_timeout() -> None:
    runner = FakeRunner()
    runner.side_effect = subprocess.TimeoutExpired(["docker", "run"], 60)
    with pytest.raises(ProcessingSupervisorError, match="timed out"):
        ProcessingSupervisor(runtime=_test_runtime(), runner=runner).process(b"source", "image/png")
    assert runner.calls[-1][0][:3] == ["/usr/bin/docker", "rm", "--force"]


def test_supervisor_reports_cleanup_failure_alongside_timeout() -> None:
    runner = FakeRunner()
    runner.side_effect = subprocess.TimeoutExpired(["docker", "run"], 60)
    runner.cleanup_returncode = 1

    with pytest.raises(ProcessingSupervisorError, match="timed out.*cleanup failed"):
        ProcessingSupervisor(runtime=_test_runtime(), runner=runner).process(b"source", "image/png")


def test_supervisor_requires_verified_report() -> None:
    output = json.loads(_worker_result())
    output["report"]["output_verified"] = False
    runner = FakeRunner(subprocess.CompletedProcess([], 0, json.dumps(output).encode(), b""))
    with pytest.raises(ProcessingSupervisorError):
        ProcessingSupervisor(runtime=_test_runtime(), runner=runner).process(b"source", "image/png")


@pytest.mark.parametrize(
    ("media_type", "report_changes"),
    [
        ("image/png", {"metadata_categories": ["GPS latitude: 51.5"]}),
        ("image/png", {"width": 0}),
        ("image/png", {"height": None}),
        ("image/png", {"page_count": 101}),
        ("application/pdf", {"width": 1, "height": 1, "page_count": 1}),
        ("application/pdf", {"width": None, "height": None, "page_count": 101}),
        ("application/pdf", {"width": None, "height": None, "page_count": 0}),
    ],
)
def test_supervisor_rejects_report_values_and_invalid_media_dimensions(
    media_type: str, report_changes: dict[str, object]
) -> None:
    output = json.loads(_worker_result())
    output["media_type"] = media_type
    output["report"]["media_type"] = media_type
    output["report"]["width"] = None if media_type == "application/pdf" else 1
    output["report"]["height"] = None if media_type == "application/pdf" else 1
    output["report"]["page_count"] = 1 if media_type == "application/pdf" else None
    output["report"].update(report_changes)
    runner = FakeRunner(subprocess.CompletedProcess([], 0, json.dumps(output).encode(), b""))

    with pytest.raises(ProcessingSupervisorError):
        ProcessingSupervisor(runtime=_test_runtime(), runner=runner).process(b"source", media_type)


class _ChunkStream:
    def __init__(self, data: bytes):
        self._buffer = io.BytesIO(data)
        self.read_sizes: list[int] = []

    def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        return self._buffer.read(size)

    def close(self) -> None:
        self._buffer.close()


class _FakeProcess:
    def __init__(self, stdout: bytes):
        self.stdin = io.BytesIO()
        self.stdout = _ChunkStream(stdout)
        self.returncode = 0
        self.killed = False

    def wait(self, timeout: int | None = None) -> int:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


def test_bounded_runner_stops_collecting_oversized_stdout_and_discards_stderr() -> None:
    process = _FakeProcess(b"x" * 257)
    launch_options: list[dict[str, object]] = []

    def process_factory(command: list[str], **kwargs: object) -> _FakeProcess:
        launch_options.append(kwargs)
        return process

    runner = BoundedProcessRunner(process_factory=process_factory)
    with pytest.raises(ProcessorOutputLimitExceeded):
        runner(
            ["/usr/bin/docker", "run"], input=b"request", timeout=60, max_stdout_bytes=256, env={}
        )

    assert process.killed is True
    assert process.stdout.read_sizes == [257]
    assert launch_options[0]["stdout"] == subprocess.PIPE
    assert launch_options[0]["stderr"] == subprocess.DEVNULL
    assert launch_options[0]["shell"] is False
    assert launch_options[0]["env"] == {}


def test_docker_context_excludes_secrets_and_key_material() -> None:
    dockerignore = (Path(__file__).parents[1] / ".dockerignore").read_text(encoding="utf-8")

    assert ".secrets" in dockerignore
    assert "secrets" in dockerignore
    assert "*.pem" in dockerignore
    assert "*.key" in dockerignore
    assert "*.p12" in dockerignore
    assert "*.jks" in dockerignore


def test_processor_image_requires_locked_binary_wheels() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile.processor").read_text(encoding="utf-8")
    assert "--only-binary=:all:" in dockerfile
    assert "packaging==26.3" in dockerfile


def test_processor_image_copies_only_its_runtime_modules() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile.processor").read_text(encoding="utf-8")
    instructions = dockerfile.replace("\\\n", " ").splitlines()
    copies = [line.split()[1:] for line in instructions if line.startswith("COPY ")]

    assert len(copies) == 1
    assert copies[0][-1] == "./metaguard_api/"
    assert set(copies[0][:-1]) == {
        "metaguard_api/__init__.py",
        "metaguard_api/file_processing.py",
        "metaguard_api/processing_limits.py",
        "metaguard_api/processing_types.py",
        "metaguard_api/processing_worker.py",
    }


def test_processing_report_shape_is_explicit() -> None:
    report = ProcessingReport("image/png", (), True, width=1, height=1)
    assert report.output_verified is True
