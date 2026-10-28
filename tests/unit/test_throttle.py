"""Login throttles: `pirewall.core.throttle`, the admin `AdminLoginThrottle`, the portal `LoginThrottle`."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from pirewall.api.throttle import AdminLoginThrottle
from pirewall.core.throttle import FailureWindow, LockoutScope, ScopedThrottle
from pirewall.portal.sessions import LoginThrottle
from tests.helpers.config import make_config

NOW = datetime(2026, 1, 1, tzinfo=UTC)
CLIENT = IPv4Address("192.168.1.20")
OTHER = IPv4Address("192.168.1.21")


# ----------------------------------------------------------- FailureWindow


def test_the_failure_that_reaches_the_limit_reports_the_new_lockout_once() -> None:
    window: FailureWindow[str] = FailureWindow(max_failures=2, window_seconds=60)
    assert window.record_failure("a", NOW) is False
    assert window.record_failure("a", NOW) is True
    # Already locked: further failures are not a *new* lockout.
    assert window.record_failure("a", NOW) is False
    assert window.is_locked_out("a", NOW)


def test_the_window_slides() -> None:
    window: FailureWindow[str] = FailureWindow(max_failures=2, window_seconds=60)
    window.record_failure("a", NOW)
    window.record_failure("a", NOW + timedelta(seconds=30))
    assert window.is_locked_out("a", NOW + timedelta(seconds=59))
    # The first failure has left the window; one remains, below the limit.
    assert not window.is_locked_out("a", NOW + timedelta(seconds=61))


def test_retry_after_rounds_up_and_is_never_zero_while_locked() -> None:
    window: FailureWindow[str] = FailureWindow(max_failures=1, window_seconds=60)
    window.record_failure("a", NOW)
    assert window.seconds_until_unlocked("a", NOW) == 60
    assert window.seconds_until_unlocked("a", NOW + timedelta(seconds=59, milliseconds=500)) == 1
    assert window.seconds_until_unlocked("a", NOW + timedelta(seconds=60)) == 0


# ---------------------------------------------------------- ScopedThrottle


def test_global_scope_counts_every_key_together() -> None:
    throttle = ScopedThrottle({LockoutScope.SOURCE: 5, LockoutScope.GLOBAL: 3}, window_seconds=60)
    for key in ("a", "b"):
        assert throttle.record_failure({LockoutScope.SOURCE: key}, NOW) == ()
    assert throttle.record_failure({LockoutScope.SOURCE: "c"}, NOW) == (LockoutScope.GLOBAL,)
    lockout = throttle.lockout({LockoutScope.SOURCE: "fresh"}, NOW)
    assert lockout is not None
    assert lockout.scope is LockoutScope.GLOBAL


def test_clearing_a_source_never_clears_the_global_count() -> None:
    throttle = ScopedThrottle({LockoutScope.SOURCE: 5, LockoutScope.GLOBAL: 2}, window_seconds=60)
    throttle.record_failure({LockoutScope.SOURCE: "a"}, NOW)
    throttle.record_failure({LockoutScope.SOURCE: "a"}, NOW)
    throttle.clear(LockoutScope.SOURCE, "a")
    throttle.clear(LockoutScope.GLOBAL, "*")
    assert throttle.lockout({LockoutScope.SOURCE: "a"}, NOW) is not None


def test_the_longest_wait_wins_when_several_scopes_are_locked() -> None:
    throttle = ScopedThrottle({LockoutScope.SOURCE: 1, LockoutScope.GLOBAL: 2}, window_seconds=60)
    throttle.record_failure({LockoutScope.SOURCE: "a"}, NOW)
    throttle.record_failure({LockoutScope.SOURCE: "a"}, NOW + timedelta(seconds=10))
    lockout = throttle.lockout({LockoutScope.SOURCE: "a"}, NOW + timedelta(seconds=10))
    assert lockout is not None
    # SOURCE's limit is one, so its window runs from the newest failure:
    # 60 s. GLOBAL's runs from the oldest: 50 s.
    assert (lockout.scope, lockout.retry_after_seconds) == (LockoutScope.SOURCE, 60)


# ------------------------------------------------------ AdminLoginThrottle


def _admin_throttle(per_ip: int, global_limit: int) -> AdminLoginThrottle:
    config = make_config(
        authentication={
            "max_failed_logins_per_ip": per_ip,
            "max_failed_logins_global": global_limit,
            "failed_login_window_seconds": 300,
        }
    )
    return AdminLoginThrottle(config.authentication)


def test_admin_throttle_is_per_ip_below_the_global_limit() -> None:
    throttle = _admin_throttle(per_ip=2, global_limit=10)
    assert throttle.record_failure("10.0.0.1", NOW) == ()
    assert throttle.record_failure("10.0.0.1", NOW) == (LockoutScope.SOURCE,)
    assert throttle.lockout("10.0.0.1", NOW) is not None
    assert throttle.lockout("10.0.0.2", NOW) is None


def test_admin_throttle_global_limit_spans_addresses() -> None:
    throttle = _admin_throttle(per_ip=5, global_limit=3)
    for host in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        throttle.record_failure(host, NOW)
    lockout = throttle.lockout("10.0.0.99", NOW)
    assert lockout is not None
    assert lockout.scope is LockoutScope.GLOBAL
    assert throttle.lockout("10.0.0.99", NOW + timedelta(seconds=301)) is None


def test_a_missing_client_address_is_still_counted() -> None:
    throttle = _admin_throttle(per_ip=1, global_limit=10)
    throttle.record_failure(None, NOW)
    assert throttle.lockout(None, NOW) is not None


# ------------------------------------------------- portal LoginThrottle


def test_portal_per_account_limit_spans_source_addresses() -> None:
    """Guessing one account's password from many addresses is still stopped."""
    throttle = LoginThrottle(5, 300, max_failures_per_account=3, max_failures_global=100)
    for index in range(3):
        throttle.record_failure(IPv4Address(f"192.168.1.{100 + index}"), NOW, "alice")
    lockout = throttle.lockout(IPv4Address("192.168.1.200"), "alice", NOW)
    assert lockout is not None
    assert lockout.scope is LockoutScope.ACCOUNT
    # Another account from the same fresh address is unaffected.
    assert throttle.lockout(IPv4Address("192.168.1.200"), "bob", NOW) is None


def test_portal_account_key_ignores_case() -> None:
    throttle = LoginThrottle(5, 300, max_failures_per_account=2)
    throttle.record_failure(CLIENT, NOW, "Alice")
    throttle.record_failure(OTHER, NOW, "ALICE")
    assert throttle.lockout(IPv4Address("192.168.1.99"), "alice", NOW) is not None


def test_portal_global_limit_locks_everyone() -> None:
    throttle = LoginThrottle(5, 300, max_failures_per_account=5, max_failures_global=3)
    for index in range(3):
        throttle.record_failure(IPv4Address(f"192.168.1.{100 + index}"), NOW, f"user{index}")
    lockout = throttle.lockout(IPv4Address("192.168.1.250"), "someone-else", NOW)
    assert lockout is not None
    assert lockout.scope is LockoutScope.GLOBAL


def test_a_portal_success_clears_the_ip_and_the_account() -> None:
    throttle = LoginThrottle(2, 300, max_failures_per_account=2)
    throttle.record_failure(CLIENT, NOW, "alice")
    throttle.clear(CLIENT, "alice")
    throttle.record_failure(CLIENT, NOW, "alice")
    assert throttle.lockout(CLIENT, "alice", NOW) is None
