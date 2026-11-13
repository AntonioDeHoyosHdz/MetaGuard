"""Privacy-preserving range lookup for compromised passwords.

The caller supplies the transport and must not interpret failures as a safe result.
This component does not implement the application password policy or fallback.
"""

import re
from collections.abc import Callable
from hashlib import sha1


class InvalidRangeResponse(ValueError):
    """The range service returned a response that cannot be trusted."""


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
