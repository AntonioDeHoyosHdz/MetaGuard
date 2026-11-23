from concurrent.futures import ThreadPoolExecutor

from metaguard_api.local_rate_limit import LocalRateLimiter
from metaguard_api.settings import Settings


def test_registration_budget_is_by_ip_and_resets_after_window():
    now = [0.0]
    limiter = LocalRateLimiter(Settings(), clock=lambda: now[0])
    for identity in range(5):
        assert limiter.allow("auth_register", "127.0.0.1", str(identity))
    now[0] = 3_599.9
    assert not limiter.allow("auth_register", "127.0.0.1", "different")
    assert limiter.allow("auth_register", "::1", "different")
    now[0] = 3_600
    assert limiter.allow("auth_register", "127.0.0.1", "different")


def test_account_upload_budget_is_shared_across_ips():
    limiter = LocalRateLimiter(Settings(), clock=lambda: 0.0)
    for i in range(10):
        assert limiter.allow("uploads_per_hour_per_account", f"client-{i}", "same-account")
    assert not limiter.allow("uploads_per_hour_per_account", "new-client", "same-account")
    assert limiter.allow("uploads_per_hour_per_account", "new-client", "another-account")


def test_resend_budget_blocks_ip_and_identity_independently():
    now = [0.0]
    settings = Settings(registrations_per_hour_per_ip=2)
    limiter = LocalRateLimiter(settings, clock=lambda: now[0])
    action = "auth_resend_verification"
    assert limiter.allow(action, "ip-1", "identity-1")
    assert not limiter.allow(action, "ip-2", "identity-1")
    assert limiter.allow(action, "ip-1", "identity-2")
    assert not limiter.allow(action, "ip-1", "identity-3")
    assert limiter.allow(action, "ip-2", "identity-3")
    for attempt in range(2, 6):
        now[0] += 60
        assert limiter.allow(action, f"ip-{attempt}", "identity-1")
    now[0] += 60
    assert not limiter.allow(action, "ip-6", "identity-1")
    now[0] = 3600
    assert limiter.allow(action, "ip-1", "identity-1")


def test_limiter_does_not_evict_live_buckets_and_caps_admissions_atomically():
    now = [0.0]
    limiter = LocalRateLimiter(Settings(), clock=lambda: now[0], max_buckets=2)
    assert not limiter.allow("unknown-action", "ignored", "ignored")
    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = list(
            pool.map(lambda _: limiter.allow("auth_login", "same-ip", "same-account"), range(20))
        )
    assert sum(admitted) == 5
    assert not limiter.allow("auth_login", "new-ip", "new-account")
    now[0] = 60.0
    assert limiter.allow("auth_login", "new-ip", "new-account")


def test_mfa_enrollment_and_recovery_limits_are_account_scoped_and_separate():
    now = [0.0]
    limiter = LocalRateLimiter(Settings(), clock=lambda: now[0])
    actions = ("mfa_enrollment_setup", "mfa_enrollment_confirm", "mfa_recovery_account")
    for action in actions:
        for attempt in range(5):
            assert limiter.allow(action, f"ip-{attempt}", "same-account")
        assert not limiter.allow(action, "another-ip", "same-account")
        assert limiter.allow(action, "another-ip", "another-account")
    now[0] = 900.0
    assert limiter.allow("mfa_recovery_account", "new-ip", "same-account")
    assert limiter.allow("mfa_enrollment_confirm", "new-ip", "same-account")
    assert not limiter.allow("mfa_enrollment_setup", "new-ip", "same-account")
    now[0] = 3600.0
    assert limiter.allow("mfa_enrollment_setup", "new-ip", "same-account")


def test_password_change_budgets_are_independent_and_only_for_password_changes():
    now = [0.0]
    limiter = LocalRateLimiter(Settings(), clock=lambda: now[0])
    ip_action = "account_password_change_ip"
    account_action = "account_password_change_account"
    for attempt in range(5):
        assert limiter.allow(ip_action, "same-ip", f"account-{attempt}")
        assert limiter.allow(account_action, f"ip-{attempt}", "same-account")
    assert not limiter.allow(ip_action, "same-ip", "new-account")
    assert not limiter.allow(account_action, "new-ip", "same-account")
    assert limiter.allow(ip_action, "new-ip", "same-account")
    assert limiter.allow(account_action, "same-ip", "new-account")
    assert limiter.allow("auth_login", "same-ip", "same-account")
    now[0] = 60.0
    assert limiter.allow(ip_action, "same-ip", "new-account")
    assert not limiter.allow(account_action, "same-ip", "same-account")
    now[0] = 900.0
    assert limiter.allow(account_action, "same-ip", "same-account")
