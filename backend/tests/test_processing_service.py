"""Private listener lifecycle tests without Docker or live sockets."""

import stat
from types import SimpleNamespace

import pytest

import metaguard_api.processing_service as service

SOCKET = "/run/metaguard-ipc/processor.sock"
DIRECTORY = "/run/metaguard-ipc"
CLI = [
    "--socket",
    SOCKET,
    "--api-uid",
    "2000",
    "--api-gid",
    "3000",
    "--docker-executable",
    "/usr/bin/docker",
    "--docker-socket",
    "/run/docker.sock",
    "--docker-config-dir",
    "/etc/metaguard/docker",
    "--worker-image",
    "metaguard-processor@sha256:" + "a" * 64,
]


def node(mode, *, uid=1000, gid=3000, ino=1, dev=1):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid, st_ino=ino, st_dev=dev)


class Listener:
    def __init__(self, files):
        self.files = files
        self.calls = []
        self.closed = False
        self.connection = SimpleNamespace(close=lambda: self.calls.append("close connection"))
        self.after_accept = lambda: None

    def bind(self, path):
        self.calls.append(("bind", path))
        self.files[path] = node(stat.S_IFSOCK | 0o600, ino=10)

    def listen(self, backlog):
        self.calls.append(("listen", backlog))

    def settimeout(self, timeout):
        self.calls.append(("timeout", timeout))

    def accept(self):
        self.calls.append("accept")
        self.after_accept()
        return self.connection, None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True


@pytest.fixture
def host(monkeypatch):
    files = {
        "/": node(stat.S_IFDIR | 0o755, uid=0),
        "/run": node(stat.S_IFDIR | 0o755, uid=0),
        DIRECTORY: node(stat.S_IFDIR | 0o2750),
    }
    listener = Listener(files)
    created = []
    masks = []
    changes = []

    def lstat(path):
        try:
            return files[path]
        except KeyError:
            raise FileNotFoundError from None

    def umask(mask):
        masks.append(mask)
        return 0o022

    def chmod(path, mode):
        changes.append(("chmod", path, mode))
        files[path].st_mode = stat.S_IFSOCK | mode

    def unlink(path):
        changes.append(("unlink", path))
        del files[path]

    def socket_factory(*family):
        created.append(family)
        return listener

    monkeypatch.setattr(service, "_LINUX", True)
    monkeypatch.setattr(
        service,
        "os",
        SimpleNamespace(
            fsencode=service.os.fsencode,
            geteuid=lambda: 1000,
            lstat=lstat,
            umask=umask,
            chmod=chmod,
            unlink=unlink,
        ),
    )
    monkeypatch.setattr(
        service, "socket", SimpleNamespace(socket=socket_factory, AF_UNIX=1, SOCK_STREAM=1)
    )
    return SimpleNamespace(
        files=files, listener=listener, created=created, masks=masks, changes=changes
    )


def test_cleanup_failure_stops_accepting_and_removes_only_own_socket(host):
    handled = []
    handler = SimpleNamespace(disabled=False)

    def handle(connection):
        assert host.files[SOCKET].st_mode == stat.S_IFSOCK | 0o660
        handled.append(connection)
        handler.disabled = True

    handler.handle = handle
    with pytest.raises(service.ServiceError, match="cleanup"):
        service.serve(SOCKET, 2000, 3000, handler, stop=lambda: False)

    assert handled == [host.listener.connection]
    assert host.listener.calls.count("accept") == 1
    assert ("listen", 1) in host.listener.calls
    assert host.listener.closed is True
    assert host.masks == [0o177, 0o022]
    assert host.changes == [("chmod", SOCKET, 0o660), ("unlink", SOCKET)]
    assert SOCKET not in host.files


def test_stop_during_accept_closes_pending_connection_without_dispatch(host):
    stopped = False
    handled = []

    def stop():
        nonlocal stopped
        stopped = True

    host.listener.after_accept = stop
    handler = SimpleNamespace(disabled=False, handle=handled.append)
    service.serve(SOCKET, 2000, 3000, handler, stop=lambda: stopped)

    assert host.listener.closed is True
    assert "close connection" in host.listener.calls
    assert not handled
    assert ("unlink", SOCKET) in host.changes


@pytest.mark.parametrize(
    ("path", "item"),
    [
        ("/run", node(stat.S_IFDIR | 0o777, uid=0)),
        ("/run", node(stat.S_IFDIR | 0o755, uid=9000)),
        (DIRECTORY, node(stat.S_IFLNK | 0o777)),
        (DIRECTORY, node(stat.S_IFDIR | 0o2770)),
        (DIRECTORY, node(stat.S_IFDIR | 0o2755)),
        (DIRECTORY, node(stat.S_IFDIR | 0o0750)),
        (DIRECTORY, node(stat.S_IFDIR | 0o2750, gid=9000)),
        (DIRECTORY, node(stat.S_IFDIR | 0o2750, uid=9000)),
        (SOCKET, node(stat.S_IFSOCK | 0o660)),
        (SOCKET, node(stat.S_IFLNK | 0o777)),
        (SOCKET, node(stat.S_IFREG | 0o660)),
    ],
)
def test_refuses_unprotected_paths_and_existing_entries_without_mutation(host, path, item):
    host.files[path] = item
    before = host.files.copy()
    with pytest.raises(service.ServiceError):
        service.serve(SOCKET, 2000, 3000, None, stop=lambda: False)

    assert host.files == before
    assert not host.created
    assert not host.changes


@pytest.mark.parametrize(
    ("path", "uid", "gid"),
    [
        ("relative.sock", 2000, 3000),
        ("/run/../socket", 2000, 3000),
        ("/" + "é" * 54, 2000, 3000),
        ("/root.sock", 2000, 3000),
        (SOCKET, 1000, 3000),
        (SOCKET, 2000, 0),
        (SOCKET, 0, 3000),
    ],
)
def test_rejects_invalid_path_or_identities(host, path, uid, gid):
    with pytest.raises(service.ServiceError):
        service.serve(path, uid, gid, None, stop=lambda: False)

    assert not host.created
    assert not host.changes


def test_shutdown_leaves_a_replacement_inode_untouched(host):
    replacement = node(stat.S_IFSOCK | 0o660, ino=900)

    def replace(_connection):
        host.files[SOCKET] = replacement
        handler.disabled = True

    handler = SimpleNamespace(disabled=False, handle=replace)
    with pytest.raises(service.ServiceError):
        service.serve(SOCKET, 2000, 3000, handler, stop=lambda: False)

    assert host.files[SOCKET] is replacement
    assert host.listener.closed is True
    assert ("unlink", SOCKET) not in host.changes


def test_cli_refuses_non_linux_without_calling_service(monkeypatch, capsys):
    monkeypatch.setattr(service, "_LINUX", False)

    def unexpected(*args, **kwargs):
        pytest.fail("Listener must not start on a non-Linux platform")

    monkeypatch.setattr(service, "serve", unexpected)
    assert service.main(CLI) == 1
    assert capsys.readouterr().err == "Private processor service requires Linux.\n"


def test_cli_redacts_runtime_failure(host, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise OSError("private OS detail")

    monkeypatch.setattr(service, "serve", fail)
    assert service.main(CLI) == 1
    assert capsys.readouterr().err == "Private processor service stopped.\n"


def test_cli_reports_reconciliation_required_without_internal_detail(host, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise service.CleanupUncertain("private processing detail")

    monkeypatch.setattr(service, "serve", fail)
    assert service.main(CLI) == 1
    assert capsys.readouterr().err == (
        "Private processor cleanup must be reconciled before restart.\n"
    )
