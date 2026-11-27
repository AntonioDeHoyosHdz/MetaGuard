from hashlib import sha1
from http.client import BadStatusLine, HTTPResponse, IncompleteRead
from io import BytesIO
from unittest.mock import MagicMock
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler

import pytest

from metaguard_api.password_policy import PasswordScreeningResult, screen_password
from metaguard_api.pwned_passwords import (
    InvalidRangeResponse,
    RangeServiceUnavailable,
    fetch_password_range,
    is_compromised,
)


def test_transport_sends_only_padded_prefix_and_compares_locally(monkeypatch) -> None:
    password = "synthetic-password"
    digest = sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    response = MagicMock(status=200)
    response.read.return_value = f"{digest[5:]}:4\r\n".encode()
    opener = MagicMock()
    opener.open.return_value.__enter__.return_value = response
    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", lambda *_args: opener)

    assert is_compromised(password, fetch_password_range) is True
    request = opener.open.call_args.args[0]
    assert request.full_url == f"https://api.pwnedpasswords.com/range/{digest[:5]}"
    assert request.get_header("Add-padding") == "true"
    assert request.get_header("User-agent") == "MetaGuard/0.1"
    assert opener.open.call_args.kwargs["timeout"] > 0
    assert password not in request.full_url and digest not in request.full_url


@pytest.mark.parametrize("prefix", ["1234", "ABCDE/../", "abcde", "ZZZZZ"])
def test_transport_rejects_invalid_prefix_without_network(monkeypatch, prefix) -> None:
    opener = MagicMock()
    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", lambda *_args: opener)
    with pytest.raises(ValueError):
        fetch_password_range(prefix, {"Add-Padding": "true"})
    opener.open.assert_not_called()


def test_transport_failure_is_not_treated_as_safe(monkeypatch) -> None:
    opener = MagicMock()
    opener.open.side_effect = TimeoutError("sensitive details")
    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", lambda *_args: opener)
    with pytest.raises(RangeServiceUnavailable) as error:
        is_compromised("synthetic-password", fetch_password_range)
    assert "sensitive" not in str(error.value)


def test_transport_disables_proxies_and_redirects(monkeypatch) -> None:
    opener = MagicMock()
    opener.open.return_value.__enter__.return_value.status = 200
    opener.open.return_value.__enter__.return_value.read.return_value = b"ok"
    handlers = []

    def fake_opener(*args):
        handlers.extend(args)
        return opener

    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", fake_opener)
    assert fetch_password_range("ABCDE", {"Add-Padding": "true"}) == "ok"
    assert isinstance(handlers[0], ProxyHandler) and handlers[0].proxies == {}
    assert isinstance(handlers[1], HTTPRedirectHandler)
    assert handlers[1].redirect_request(None, None, 302, "", {}, "https://other.invalid") is None


@pytest.mark.parametrize(
    "body,status,error",
    [
        (b"x" * 2_000_001, 200, InvalidRangeResponse),
        (b"ok", 503, RangeServiceUnavailable),
        (b"\xff", 200, InvalidRangeResponse),
    ],
)
def test_transport_rejects_untrustworthy_responses(monkeypatch, body, status, error) -> None:
    response = MagicMock(status=status)
    response.read.return_value = body
    opener = MagicMock()
    opener.open.return_value.__enter__.return_value = response
    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", lambda *_args: opener)
    with pytest.raises(error):
        fetch_password_range("ABCDE", {"Add-Padding": "true"})


def test_transport_sanitizes_network_exception(monkeypatch) -> None:
    opener = MagicMock()
    opener.open.side_effect = URLError("synthetic sensitive details")
    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", lambda *_args: opener)
    with pytest.raises(RangeServiceUnavailable) as error:
        fetch_password_range("ABCDE", {"Add-Padding": "true"})
    assert "sensitive" not in str(error.value)
    assert error.value.__suppress_context__


def test_truncated_http_body_is_not_a_safe_result(monkeypatch) -> None:
    class FakeSocket:
        def makefile(self, *_args, **_kwargs):
            return BytesIO(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + b"F" * 35 + b":1\r\n"
            )

    response = HTTPResponse(FakeSocket())
    response.begin()
    opener = MagicMock()
    opener.open.return_value = response
    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", lambda *_args: opener)
    with pytest.raises(InvalidRangeResponse):
        is_compromised("synthetic-password", fetch_password_range)


def test_http_protocol_errors_are_sanitized(monkeypatch) -> None:
    opener = MagicMock()
    opener.open.side_effect = BadStatusLine("synthetic sensitive status")
    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", lambda *_args: opener)
    with pytest.raises(RangeServiceUnavailable) as error:
        fetch_password_range("ABCDE", {"Add-Padding": "true"})
    assert "sensitive" not in str(error.value)
    assert error.value.__suppress_context__


@pytest.mark.parametrize(
    "kind",
    [
        "truncated",
        "unframed",
        "oversized",
        "incomplete_read",
        "body_timeout",
        "long_chunk",
        "long_trailer",
        "missing_trailer",
    ],
)
def test_unverifiable_body_cannot_trigger_reduced_acceptance(monkeypatch, kind):
    password = "synthetic password for testing"
    suffix = sha1(password.encode(), usedforsecurity=False).hexdigest().upper()[5:]
    body = f"{suffix}:1\r\n".encode()
    if kind == "truncated":
        wire = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body) + 10}\r\n\r\n".encode() + body
    elif kind == "unframed":
        wire = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body
    elif kind == "long_chunk":
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"a" * 65537 + b"\r\n"
    elif kind == "long_trailer":
        wire = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n"
            + b"a" * 65537
            + b"\r\n\r\n"
        )
    elif kind == "missing_trailer":
        safe_body = b"F" * 35 + b":0\r\n"
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        wire += f"{len(safe_body):x}\r\n".encode() + safe_body + b"\r\n0\r\n"
    else:
        wire = b""

    opener = MagicMock()
    if wire:

        class Socket:
            def makefile(self, *_args, **_kwargs):
                return BytesIO(wire)

        response = HTTPResponse(Socket())
        response.begin()
        opener.open.return_value = response
    else:
        response = MagicMock(status=200, length=2_000_001, chunked=False)
        if kind == "oversized":
            response.read.return_value = b"x" * 2_000_001
            response.length = 0
        elif kind == "incomplete_read":
            response.read.side_effect = IncompleteRead(b"sensitive partial response")
        else:
            response.read.side_effect = TimeoutError("sensitive partial response")
        opener.open.return_value.__enter__.return_value = response
    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", lambda *_args: opener)
    events = []
    assert (
        screen_password(
            password,
            common_passwords=frozenset({"other common password"}),
            lookup=fetch_password_range,
            report_outage=events.append,
        )
        is PasswordScreeningResult.REJECTED
    )
    assert events == ["password_breach_check_unavailable"]


def test_unframed_http_body_is_rejected(monkeypatch) -> None:
    class FakeSocket:
        def makefile(self, *_args, **_kwargs):
            return BytesIO(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + b"F" * 35 + b":1\r\n")

    response = HTTPResponse(FakeSocket())
    response.begin()
    opener = MagicMock()
    opener.open.return_value = response
    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", lambda *_args: opener)
    with pytest.raises(InvalidRangeResponse):
        fetch_password_range("ABCDE", {"Add-Padding": "true"})


@pytest.mark.parametrize("chunked", [False, True])
def test_complete_framed_response_is_accepted(monkeypatch, chunked) -> None:
    password = "synthetic-password"
    digest = sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    body = f"{digest[5:]}:2\r\n".encode()
    if chunked:
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        wire += f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    else:
        wire = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body

    class FakeSocket:
        def makefile(self, *_args, **_kwargs):
            return BytesIO(wire)

    response = HTTPResponse(FakeSocket())
    response.begin()
    opener = MagicMock()
    opener.open.return_value = response
    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", lambda *_args: opener)
    assert is_compromised(password, fetch_password_range) is True


def test_complete_chunk_extensions_and_trailers_are_accepted(monkeypatch) -> None:
    password = "synthetic-password"
    suffix = sha1(password.encode(), usedforsecurity=False).hexdigest().upper()[5:]
    body = f"{suffix}:2\r\n".encode()
    wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    wire += f"{len(body):x};example=value\r\n".encode() + body
    wire += b"\r\n0\r\nX-Test: accepted\r\n\r\n"

    class Socket:
        def makefile(self, *_args, **_kwargs):
            return BytesIO(wire)

    response = HTTPResponse(Socket())
    response.begin()
    opener = MagicMock()
    opener.open.return_value = response
    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", lambda *_args: opener)
    assert is_compromised(password, fetch_password_range)
