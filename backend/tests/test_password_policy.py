import pytest

from metaguard_api.password_policy import PasswordScreeningResult, screen_password
from metaguard_api.pwned_passwords import RangeServiceUnavailable


def test_online_clear_and_compromised_passwords():
    events = []

    def clear(_prefix, _headers):
        return "F" * 35 + ":0"

    assert (
        screen_password(
            "correct horse battery staple",
            common_passwords=frozenset({"common password"}),
            lookup=clear,
            report_outage=events.append,
        )
        == PasswordScreeningResult.ACCEPTED
    )
    assert events == []
    from hashlib import sha1

    password = "known leaked password"
    suffix = sha1(password.encode(), usedforsecurity=False).hexdigest().upper()[5:]
    assert (
        screen_password(
            password,
            common_passwords=frozenset({"common password"}),
            lookup=lambda *_: suffix + ":1",
            report_outage=events.append,
        )
        == PasswordScreeningResult.REJECTED
    )


@pytest.mark.parametrize("error", [RangeServiceUnavailable("down"), TimeoutError("down")])
def test_outage_fallback_reports_reduced_protection(error):
    events = []

    def fail(*_args):
        raise error

    assert (
        screen_password(
            "correct horse battery staple",
            common_passwords=frozenset({"common password"}),
            lookup=fail,
            report_outage=events.append,
        )
        == PasswordScreeningResult.ACCEPTED_REDUCED
    )
    assert events == ["password_breach_check_unavailable"]


def test_local_policy_rejects_weak_or_listed_without_lookup():
    def forbidden(*_args):
        raise AssertionError("weak password must not invoke network")

    for password in ["short", "known common password"]:
        assert (
            screen_password(
                password,
                common_passwords=frozenset({"known common password"}),
                lookup=forbidden,
                report_outage=lambda _: None,
            )
            == PasswordScreeningResult.REJECTED
        )


def test_missing_blocklist_or_failed_audit_fails_closed():
    with pytest.raises(ValueError):
        screen_password(
            "correct horse battery staple",
            common_passwords=frozenset(),
            lookup=lambda *_: "x",
            report_outage=lambda _: None,
        )

    def unavailable(*_args):
        raise RangeServiceUnavailable("down")

    def audit_failure(_event):
        raise RuntimeError("audit unavailable")

    with pytest.raises(RuntimeError):
        screen_password(
            "correct horse battery staple",
            common_passwords=frozenset({"known common password"}),
            lookup=unavailable,
            report_outage=audit_failure,
        )


def test_malformed_response_with_compromised_match_is_never_accepted():
    from hashlib import sha1

    password = "known leaked password"
    suffix = sha1(password.encode(), usedforsecurity=False).hexdigest().upper()[5:]
    events = []
    result = screen_password(
        password,
        common_passwords=frozenset({"other common password"}),
        lookup=lambda *_: suffix + ":1\ninvalid",
        report_outage=events.append,
    )
    assert result == PasswordScreeningResult.REJECTED
    assert events == ["password_breach_check_unavailable"]


def test_unreasonably_large_service_count_fails_closed():
    from hashlib import sha1

    suffix = sha1(b"correct horse battery staple", usedforsecurity=False).hexdigest().upper()[5:]
    events = []
    result = screen_password(
        "correct horse battery staple",
        common_passwords=frozenset({"other common password"}),
        lookup=lambda *_: suffix + ":" + "9" * 4301,
        report_outage=events.append,
    )
    assert result == PasswordScreeningResult.REJECTED
    assert events == ["password_breach_check_unavailable"]
