"""Password screening for future registration; no account or endpoint is created."""

from collections.abc import Callable
from enum import StrEnum

from metaguard_api.pwned_passwords import (
    InvalidRangeResponse,
    RangeServiceUnavailable,
    is_compromised,
)


class PasswordScreeningResult(StrEnum):
    ACCEPTED = "accepted"
    ACCEPTED_REDUCED = "accepted_reduced"
    REJECTED = "rejected"


def screen_password(
    password: str,
    *,
    common_passwords: frozenset[str],
    lookup: Callable[[str, dict[str, str]], str],
    report_outage: Callable[[str], None],
    on_compromised: Callable[[], None] | None = None,
) -> PasswordScreeningResult:
    """Check a caller-provided blocklist and HIBP range; report reduced fallback.

    The caller must provide a maintained nonempty blocklist and persist the generic
    outage event; callback failures propagate so fallback never silently succeeds.
    """
    if (
        not isinstance(common_passwords, frozenset)
        or not common_passwords
        or any(not isinstance(value, str) or not value for value in common_passwords)
    ):
        raise ValueError("A nonempty local password blocklist is required")
    if not isinstance(password, str) or not 15 <= len(password) <= 1024:
        return PasswordScreeningResult.REJECTED
    try:
        if len(password.encode("utf-8")) > 1024:
            return PasswordScreeningResult.REJECTED
    except UnicodeError:
        return PasswordScreeningResult.REJECTED
    if password in common_passwords:
        return PasswordScreeningResult.REJECTED

    def checked_lookup(prefix: str, headers: dict[str, str]) -> str:
        response = lookup(prefix, headers)
        if not isinstance(response, str):
            raise InvalidRangeResponse("Non-text password range response")
        return response

    try:
        compromised = is_compromised(password, checked_lookup)
    except (RangeServiceUnavailable, OSError):
        report_outage("password_breach_check_unavailable")
        return PasswordScreeningResult.ACCEPTED_REDUCED
    except (InvalidRangeResponse, ValueError):
        # An invalid response may include a genuine match; never accept it via fallback.
        report_outage("password_breach_check_unavailable")
        return PasswordScreeningResult.REJECTED
    if compromised:
        if on_compromised is not None:
            on_compromised()
        return PasswordScreeningResult.REJECTED
    return PasswordScreeningResult.ACCEPTED
