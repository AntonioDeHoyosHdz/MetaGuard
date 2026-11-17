"""Launch-boundary tests only; no Docker daemon is contacted."""

import subprocess

import pytest

from metaguard_api.processing_supervisor import (
    DockerRuntimeConfig,
    ProcessingSupervisor,
    ProcessingSupervisorError,
)

IMAGE = "metaguard-processor@sha256:" + "a" * 64


def runtime(**changes):
    values = {
        "executable": "/usr/bin/docker",
        "daemon_socket": "/run/docker.sock",
        "config_dir": "/etc/metaguard/docker",
        "image": IMAGE,
    }
    return DockerRuntimeConfig(**(values | changes))


def test_supervisor_passes_only_fixed_runtime_environment_to_run_and_cleanup(monkeypatch):
    for name in ("PATH", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "HOME"):
        monkeypatch.setenv(name, "hostile-inherited-value")
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 1 if len(calls) == 1 else 0, b"", b"")

    with pytest.raises(ProcessingSupervisorError):
        ProcessingSupervisor(runtime=runtime(), runner=runner).process(b"data", "image/png")
    assert len(calls) == 2
    expected_env = {
        "DOCKER_HOST": "unix:///run/docker.sock",
        "DOCKER_CONFIG": "/etc/metaguard/docker",
    }
    assert calls[0][0][:2] == ["/usr/bin/docker", "run"]
    assert IMAGE in calls[0][0]
    assert calls[1][0][:3] == ["/usr/bin/docker", "rm", "--force"]
    assert calls[0][1]["env"] == calls[1][1]["env"] == expected_env


@pytest.mark.parametrize(
    "changes",
    [
        {"executable": "docker"},
        {"executable": "/usr/bin/../docker"},
        {"daemon_socket": "tcp://remote.example:2375"},
        {"daemon_socket": "/run/../tmp/docker.sock"},
        {"config_dir": "relative/config"},
        {"image": "metaguard-processor:local"},
        {"image": "metaguard-processor@sha256:" + "g" * 64},
    ],
)
def test_invalid_runtime_is_rejected_before_any_job(changes):
    with pytest.raises(ValueError):
        runtime(**changes)
