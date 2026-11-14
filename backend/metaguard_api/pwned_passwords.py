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


class InvalidRangeResponse(ValueError):
    """The range service returned a response that cannot be trusted."""


class RangeServiceUnavailable(RuntimeError):
    """The external range service could not be queried safely."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
                raise RangeServiceUnavailable("Unframed password range response")
            body = response.read(_MAX_RESPONSE_BYTES + 1)
            remaining = getattr(response, "length", None)
            if isinstance(remaining, int) and remaining > 0:
                raise RangeServiceUnavailable("Incomplete password range response")
        if len(body) > _MAX_RESPONSE_BYTES:
            raise RangeServiceUnavailable("Password range response exceeds limit")
        return body.decode("ascii")
    except (OSError, URLError, UnicodeError, HTTPException):
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
