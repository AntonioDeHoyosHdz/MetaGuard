"""Privacy-preserving range lookup for compromised passwords.

The caller supplies the transport and must not interpret failures as a safe result.
This component does not implement the application password policy or fallback.
"""

import re
from collections.abc import Callable
from hashlib import sha1
from http.client import HTTPException
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

_MAX_RESPONSE_BYTES = 2_000_000
_RANGE_URL = "https://api.pwnedpasswords.com/range/"
_MAX_CHUNK_LINE_BYTES = 8192


class InvalidRangeResponse(ValueError):
    """The range service returned a response that cannot be trusted."""


class RangeServiceUnavailable(RuntimeError):
    """The external range service could not be queried safely."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read_chunked_response(response) -> bytes:
    """Read chunked framing strictly, including the terminating trailer line."""
    stream = response.fp
    if stream is None:
        raise InvalidRangeResponse("Missing chunked response stream")
    result = bytearray()
    while True:
        line = stream.readline(_MAX_CHUNK_LINE_BYTES + 1)
        if (
            len(line) > _MAX_CHUNK_LINE_BYTES
            or not line.endswith(b"\r\n")
            or not re.fullmatch(rb"[0-9A-Fa-f]{1,16}(?:;[\x20-\x7e]*)?\r\n", line)
        ):
            raise InvalidRangeResponse("Invalid password range chunk header")
        size = int(line.split(b";", 1)[0].strip(), 16)
        if size > _MAX_RESPONSE_BYTES - len(result):
            raise InvalidRangeResponse("Password range response exceeds limit")
        if size == 0:
            trailer_bytes = 0
            while True:
                trailer = stream.readline(_MAX_CHUNK_LINE_BYTES + 1)
                trailer_bytes += len(trailer)
                if trailer == b"\r\n":
                    return bytes(result)
                if (
                    len(trailer) > _MAX_CHUNK_LINE_BYTES
                    or trailer_bytes > _MAX_RESPONSE_BYTES
                    or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e]*\r\n", trailer)
                ):
                    raise InvalidRangeResponse("Invalid password range chunk trailer")
        chunk = stream.read(size + 2)
        if len(chunk) != size + 2 or chunk[-2:] != b"\r\n":
            raise InvalidRangeResponse("Incomplete password range chunk")
        result.extend(chunk[:-2])


def fetch_password_range(prefix: str, headers: dict[str, str]) -> str:
    """Fetch a padded range from the fixed HTTPS endpoint without forwarding redirects."""
    if not re.fullmatch(r"[0-9A-F]{5}", prefix) or headers != {"Add-Padding": "true"}:
        raise ValueError("A five-character uppercase prefix and padding are required")
    request = Request(
        _RANGE_URL + prefix,
        headers={"Add-Padding": "true", "User-Agent": "MetaGuard/0.1"},
        method="GET",
    )
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=3) as response:
            if response.status != 200:
                raise RangeServiceUnavailable("Password range service unavailable")
            if response.length is None and not response.chunked:
                raise InvalidRangeResponse("Unframed password range response")
            try:
                body = (
                    _read_chunked_response(response)
                    if response.chunked is True
                    else response.read(_MAX_RESPONSE_BYTES + 1)
                )
            except (HTTPException, OSError):
                raise InvalidRangeResponse("Incomplete password range response") from None
            remaining = getattr(response, "length", None)
            if isinstance(remaining, int) and remaining > 0:
                raise InvalidRangeResponse("Incomplete password range response")
        if len(body) > _MAX_RESPONSE_BYTES:
            raise InvalidRangeResponse("Password range response exceeds limit")
        try:
            return body.decode("ascii")
        except UnicodeError:
            raise InvalidRangeResponse("Password range response is not ASCII") from None
    except (OSError, URLError, HTTPException):
        raise RangeServiceUnavailable("Password range service unavailable") from None


def is_compromised(password: str, lookup: Callable[[str, dict[str, str]], str]) -> bool:
    """Request a padded hash range and compare the remaining hash locally."""
    digest = sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    response = lookup(digest[:5], {"Add-Padding": "true"})
    lines = response.splitlines()
    if not lines:
        raise InvalidRangeResponse("Empty password range response")

    found = False
    for line in lines:
        match = re.fullmatch(r"([0-9A-Fa-f]{35}):([0-9]+)", line)
        if match is None:
            raise InvalidRangeResponse("Malformed password range response")
        if match.group(1).upper() == digest[5:] and int(match.group(2)) > 0:
            found = True
    return found
