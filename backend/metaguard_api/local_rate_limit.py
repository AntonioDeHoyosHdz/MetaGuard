"""Process-local rate limits for explicitly composed API runtimes."""

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from time import monotonic
from typing import Literal

from metaguard_api.settings import Settings

_MAX_BUCKETS = 4096
_MAX_BUDGET = 600


@dataclass(frozen=True, slots=True)
class _Policy:
    group: str
    scope: Literal["ip", "account", "pair", "service"]
    limit: int
    seconds: int


class LocalRateLimiter:
    """Limit admitted attempts in rolling windows, not failed logins or lockouts."""

    def __init__(
        self,
        settings: Settings,
        *,
        clock: Callable[[], float] = monotonic,
        max_buckets: int = _MAX_BUCKETS,
        verification_mail_budget: bool = False,
    ) -> None:
        if not 1 <= max_buckets <= _MAX_BUCKETS:
            raise ValueError("Invalid local rate-limit capacity")
        ip = _Policy("requests", "ip", settings.requests_per_minute_per_ip, 60)
        account = _Policy("requests", "account", settings.requests_per_minute_per_account, 60)
        self._policies = {
            "requests_per_minute_per_ip": (ip,),
            "requests_per_minute_per_account": (account,),
            "auth_status": (ip,),
            "auth_logout": (ip,),
            "auth_logout_account": (account,),
            "auth_verify_email": (ip,),
            "auth_resend_verification": (
                ip,
                _Policy("resend", "ip", settings.registrations_per_hour_per_ip, 3600),
                _Policy("resend", "account", 1, 60),
                _Policy("resend", "account", 5, 3600),
            ),
            "auth_login": (
                ip,
                _Policy("login", "pair", settings.login_failures_before_lock, 60),
            ),
            "auth_login_mfa_ip": (ip,),
            "auth_login_mfa_account": (
                _Policy("mfa", "account", settings.login_failures_before_lock, 60),
            ),
            "auth_login_mfa_pair": (
                _Policy("mfa", "pair", settings.login_failures_before_lock, 60),
            ),
            "auth_login_email_ip": (ip,),
            "auth_login_email_pair": (
                _Policy("login-email", "pair", settings.login_failures_before_lock, 60),
            ),
            "account_password_change_ip": (
                ip,
                _Policy("password-change", "ip", settings.login_failures_before_lock, 60),
            ),
            "account_password_change_account": (
                _Policy("password-change", "account", settings.login_failures_before_lock, 900),
            ),
            "password_reset_request": (
                ip,
                _Policy("password-reset-request", "ip", 10, 900),
                _Policy("password-reset-request", "account", 1, 60),
                _Policy("password-reset-request", "account", 3, 900),
            ),
            "password_reset_confirm": (
                ip,
                _Policy("password-reset-confirm", "ip", 30, 900),
                _Policy("password-reset-confirm", "account", 5, 900),
            ),
            "mfa_enrollment_setup": (_Policy("mfa-setup", "account", 5, 3600),),
            "mfa_enrollment_confirm": (_Policy("mfa-confirm", "account", 5, 900),),
            "mfa_recovery_ip": (ip,),
            "mfa_recovery_account": (_Policy("mfa-replace", "account", 5, 900),),
            "auth_register": (
                ip,
                _Policy("registration", "ip", settings.registrations_per_hour_per_ip, 3600),
            ),
            "uploads_per_minute_per_ip": (
                ip,
                _Policy("uploads", "ip", settings.uploads_per_minute_per_ip, 60),
            ),
            "uploads_per_hour_per_account": (
                account,
                _Policy("uploads", "account", settings.uploads_per_hour_per_account, 3600),
            ),
            "reports_per_minute_per_account": (account,),
            "report_deletions_per_minute_per_account": (account,),
            "download_tokens_per_hour_per_account": (
                account,
                _Policy("download-tokens", "account", 10, 3600),
            ),
            "downloads_per_minute_per_ip": (ip,),
            "downloads_per_minute_per_account": (account,),
        }
        if verification_mail_budget:
            # All preview mail actions reserve from one budget before touching the account.
            mail = (
                _Policy("verification-mail", "account", 3, 3_600),
                _Policy("verification-mail", "service", 12, 3_600),
                _Policy("verification-mail", "service", 48, 86_400),
            )
            for action in ("auth_register", "auth_resend_verification", "password_reset_request"):
                self._policies[action] += mail
        if any(policy.limit > _MAX_BUDGET for group in self._policies.values() for policy in group):
            raise ValueError("Invalid local rate-limit budget")
        self._max_buckets = max_buckets
        self._clock = clock
        self._buckets: dict[tuple[_Policy, str, str], deque[float]] = {}
        self._sweep_at = -float("inf")
        self._lock = Lock()

    def allow(self, action: str, client_ip: str, identity: str) -> bool:
        policies = self._policies.get(action)
        if not policies or not (0 < len(client_ip) <= 128 and 0 < len(identity) <= 128):
            return False
        keys = tuple(
            (
                policy,
                client_ip if policy.scope in {"ip", "pair"} else "",
                identity if policy.scope in {"account", "pair"} else "",
            )
            for policy in policies
        )
        with self._lock:
            now = self._clock()
            if now >= self._sweep_at:
                expired = [
                    key
                    for key, events in self._buckets.items()
                    if not events or now - events[-1] >= key[0].seconds
                ]
                for key in expired:
                    del self._buckets[key]
                self._sweep_at = now + 10
            if (
                len(self._buckets) + sum(key not in self._buckets for key in keys)
                > self._max_buckets
            ):
                return False
            for key in keys:
                events = self._buckets.get(key)
                if events is None:
                    continue
                cutoff = now - key[0].seconds
                while events and events[0] <= cutoff:
                    events.popleft()
                if len(events) >= key[0].limit:
                    return False
            for key in keys:
                self._buckets.setdefault(key, deque()).append(now)
            return True
