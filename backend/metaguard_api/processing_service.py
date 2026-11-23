"""Private Linux CLI for the isolated processor supervisor."""

import argparse
import os
import posixpath
import signal
import socket
import stat
import sys
from collections.abc import Callable, Sequence
from pathlib import PurePosixPath

from metaguard_api.processing_ipc_handler import ProcessingRequestHandler
from metaguard_api.processing_supervisor import DockerRuntimeConfig, ProcessingSupervisor

_LINUX = sys.platform == "linux"
_ACCEPT_TIMEOUT = 0.25
_TRANSFER_TIMEOUT = 5


class ServiceError(RuntimeError):
    """The private listener could not operate safely."""


class CleanupUncertain(ServiceError):
    """The operator must reconcile orphaned containers before relaunch."""


def _valid_id(value: int) -> bool:
    return type(value) is int and 0 < value < 2**32 - 1


def _check_path(path: str, service_uid: int, api_uid: int, api_gid: int) -> None:
    if (
        not all(_valid_id(value) for value in (service_uid, api_uid, api_gid))
        or service_uid == api_uid
        or not isinstance(path, str)
        or not path.isprintable()
        or not path.startswith("/")
        or path.startswith("//")
        or posixpath.normpath(path) != path
        or len(os.fsencode(path)) > 107
    ):
        raise ServiceError("Invalid private listener configuration")

    parent = PurePosixPath(path).parent
    if parent == PurePosixPath("/"):
        raise ServiceError("Socket requires a protected parent directory")
    for ancestor in reversed(parent.parents):
        info = os.lstat(str(ancestor))
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in {0, service_uid}
            or info.st_mode & 0o022
        ):
            raise ServiceError("Socket ancestors must be protected directories")

    info = os.lstat(str(parent))
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != service_uid
        or info.st_gid != api_gid
        or stat.S_IMODE(info.st_mode) != 0o2750
    ):
        raise ServiceError("Socket parent must use the configured owner and group")
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    raise ServiceError("Socket path is already occupied")


def _socket_identity(info: os.stat_result) -> tuple[int, int, int]:
    if not stat.S_ISSOCK(info.st_mode):
        raise ServiceError("The private socket path is no longer a socket")
    return info.st_dev, info.st_ino, info.st_uid


def _serve_connections(
    listener: socket.socket, handler: ProcessingRequestHandler, stop: Callable[[], bool]
) -> None:
    listener.listen(1)
    listener.settimeout(_ACCEPT_TIMEOUT)
    while not stop() and not handler.disabled:
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            continue
        try:
            if not stop():
                handler.handle(connection)
        finally:
            connection.close()
    if handler.disabled:
        raise CleanupUncertain("Processor cleanup must be reconciled before restart")


def serve(
    path: str,
    api_uid: int,
    api_gid: int,
    handler: ProcessingRequestHandler,
    *,
    stop: Callable[[], bool],
) -> None:
    """Serve one job at a time; call only from a dedicated, single-threaded process."""
    if not _LINUX:
        raise ServiceError("Private processor service requires Linux")
    service_uid = os.geteuid()
    _check_path(path, service_uid, api_uid, api_gid)
    own_socket = None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            original_mask = os.umask(0o177)
            try:
                listener.bind(path)
            finally:
                os.umask(original_mask)

            info = os.lstat(path)
            identity = _socket_identity(info)
            if info.st_uid != service_uid:
                raise ServiceError("The socket owner does not match the service")
            own_socket = identity
            if info.st_gid != api_gid or stat.S_IMODE(info.st_mode) != 0o600:
                raise ServiceError("The socket did not inherit the protected configuration")
            os.chmod(path, 0o660)
            _serve_connections(listener, handler, stop)
    finally:
        if own_socket is not None:
            if _socket_identity(os.lstat(path)) != own_socket:
                raise ServiceError("The socket entry changed; it was not removed")
            os.unlink(path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--socket", required=True, help="Absolute protected API Unix socket path")
    parser.add_argument("--api-uid", type=int, required=True, help="Expected API process UID")
    parser.add_argument("--api-gid", type=int, required=True, help="Group allowed to reach socket")
    parser.add_argument("--docker-executable", required=True, help="Trusted absolute executable")
    parser.add_argument("--docker-socket", required=True, help="Trusted local Docker Unix socket")
    parser.add_argument(
        "--docker-config-dir", required=True, help="Trusted Docker config directory"
    )
    parser.add_argument("--worker-image", required=True, help="Local SHA-256-pinned worker image")
    args = parser.parse_args(argv)
    if not _LINUX:
        print("Private processor service requires Linux.", file=sys.stderr)
        return 1

    stopped = False

    def request_stop(_signum, _frame):
        nonlocal stopped
        stopped = True

    try:
        runtime = DockerRuntimeConfig(
            args.docker_executable, args.docker_socket, args.docker_config_dir, args.worker_image
        )
        handler = ProcessingRequestHandler(
            ProcessingSupervisor(runtime), expected_uid=args.api_uid, timeout=_TRANSFER_TIMEOUT
        )
        previous_int = signal.signal(signal.SIGINT, request_stop)
        try:
            previous_term = signal.signal(signal.SIGTERM, request_stop)
            try:
                serve(args.socket, args.api_uid, args.api_gid, handler, stop=lambda: stopped)
            finally:
                signal.signal(signal.SIGTERM, previous_term)
        finally:
            signal.signal(signal.SIGINT, previous_int)
    except CleanupUncertain:
        print("Private processor cleanup must be reconciled before restart.", file=sys.stderr)
        return 1
    except (OSError, ServiceError, ValueError):
        print("Private processor service stopped.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
