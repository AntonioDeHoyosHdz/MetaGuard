from hashlib import sha1

import pytest

from metaguard_api.pwned_passwords import InvalidRangeResponse, is_compromised


def test_range_lookup_sends_only_prefix_and_requests_padding() -> None:
    password = "sample-password"
    digest = sha1(password.encode("utf-8")).hexdigest().upper()
    requests = []

    def lookup(prefix: str, headers: dict[str, str]) -> str:
        requests.append((prefix, headers))
        return f"{digest[5:]}:3\r\n"

    assert is_compromised(password, lookup) is True
    assert requests == [(digest[:5], {"Add-Padding": "true"})]


def test_padding_and_other_suffixes_are_not_compromised() -> None:
    digest = sha1(b"sample-password").hexdigest().upper()
    other = "F" * 35 if digest[5:] != "F" * 35 else "E" * 35

    def lookup(_prefix: str, _headers: dict[str, str]) -> str:
        return f"{digest[5:]}:0\n{other}:4\n"

    assert is_compromised("sample-password", lookup) is False


def test_invalid_response_and_transport_failure_are_not_treated_as_safe() -> None:
    def invalid(_prefix: str, _headers: dict[str, str]) -> str:
        return "invalid"

    def unavailable(_prefix: str, _headers: dict[str, str]) -> str:
        raise TimeoutError("unavailable")

    with pytest.raises(InvalidRangeResponse):
        is_compromised("sample-password", invalid)
    with pytest.raises(TimeoutError):
        is_compromised("sample-password", unavailable)


@pytest.mark.parametrize("response", ["", "<html>error</html>", "A" * 35 + ":1\nbad"])
def test_malformed_range_is_rejected(response: str) -> None:
    with pytest.raises(InvalidRangeResponse):
        is_compromised("sample-password", lambda _prefix, _headers: response)


def test_unicode_password_and_lowercase_suffix() -> None:
    password = "synthetic-Piñata-🔒"
    digest = sha1(password.encode("utf-8")).hexdigest().upper()
    assert is_compromised(password, lambda _prefix, _headers: f"{digest[5:].lower()}:8")
