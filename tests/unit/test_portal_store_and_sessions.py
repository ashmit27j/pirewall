"""Portal user store, session registry, and login throttle (ADDENDUM_3.md C3)."""

import stat
import tempfile
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from pirewall.core.exceptions import ConfigurationError
from pirewall.portal.sessions import LoginThrottle, PortalSessionRegistry
from pirewall.portal.store import PortalUserStore

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
CLIENT = IPv4Address("192.168.100.50")
OTHER = IPv4Address("192.168.100.51")


@pytest.fixture
def store_path() -> Path:
    return Path(tempfile.mkdtemp()) / "nested" / "portal_users.json"


# --------------------------------------------------------------- user store


def test_missing_store_is_an_empty_store_not_an_error(store_path: Path) -> None:
    """A first boot has no file yet; that must not be a startup failure."""
    store = PortalUserStore(store_path)
    assert store.list_users() == []
    assert store.has_demo_accounts() is False


def test_users_round_trip_through_the_file(store_path: Path) -> None:
    store = PortalUserStore(store_path)
    store.add("alice", "correct-horse", NOW, "admin", note="laptop")
    reloaded = PortalUserStore(store_path)
    assert [user.username for user in reloaded.list_users()] == ["alice"]
    assert reloaded.verify("alice", "correct-horse") is True
    assert reloaded.list_users()[0].note == "laptop"


def test_the_store_file_is_not_readable_by_other_users(store_path: Path) -> None:
    """It holds password hashes; 0600 is the point of keeping core the only writer."""
    PortalUserStore(store_path).add("alice", "pw", NOW, "admin")
    assert stat.S_IMODE(store_path.stat().st_mode) == 0o600


def test_password_is_never_stored_in_the_clear(store_path: Path) -> None:
    store = PortalUserStore(store_path)
    store.add("alice", "super-secret-value", NOW, "admin")
    assert "super-secret-value" not in store_path.read_text(encoding="utf-8")


def test_verify_rejects_a_wrong_password_and_an_unknown_user(store_path: Path) -> None:
    store = PortalUserStore(store_path)
    store.add("alice", "pw", NOW, "admin")
    assert store.verify("alice", "wrong") is False
    assert store.verify("nobody", "pw") is False


def test_duplicate_username_is_refused(store_path: Path) -> None:
    store = PortalUserStore(store_path)
    store.add("alice", "pw", NOW, "admin")
    with pytest.raises(ConfigurationError, match="already exists"):
        store.add("alice", "other", NOW, "admin")


def test_setting_a_password_on_a_missing_user_is_refused(store_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        PortalUserStore(store_path).set_password("ghost", "pw")


def test_rotating_a_demo_password_clears_demo_status(store_path: Path) -> None:
    """The warning is about the *published* credentials, so changing one ends it."""
    store = PortalUserStore(store_path)
    store.add("demo-alice", "pirewall-demo-1", NOW, "seed", is_demo=True)
    assert store.has_demo_accounts() is True
    store.set_password("demo-alice", "something-else")
    assert store.has_demo_accounts() is False
    assert store.verify("demo-alice", "something-else") is True


def test_remove_is_reported_honestly(store_path: Path) -> None:
    store = PortalUserStore(store_path)
    store.add("alice", "pw", NOW, "admin")
    assert store.remove("alice") is True
    assert store.remove("alice") is False


def test_a_corrupt_store_fails_loudly_rather_than_silently_empty(store_path: Path) -> None:
    """An unreadable user file must not look like "nobody has an account"."""
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="could not read portal user store"):
        PortalUserStore(store_path)


def test_a_store_that_is_not_a_list_is_refused(store_path: Path) -> None:
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_text('{"alice": {}}', encoding="utf-8")
    with pytest.raises(ConfigurationError, match="must contain a JSON list"):
        PortalUserStore(store_path)


# ---------------------------------------------------------------- sessions


def test_a_token_is_bound_to_the_address_that_logged_in() -> None:
    """Replaying a token from another device must authorize nothing (ADDENDUM_3.md C1)."""
    registry = PortalSessionRegistry(token_expiry_seconds=60)
    registry.create("alice", CLIENT, "tok", NOW)
    assert registry.validate("tok", CLIENT, NOW) is not None
    assert registry.validate("tok", OTHER, NOW) is None


def test_a_session_stops_validating_once_it_expires() -> None:
    registry = PortalSessionRegistry(token_expiry_seconds=60)
    registry.create("alice", CLIENT, "tok", NOW)
    assert registry.validate("tok", CLIENT, NOW + timedelta(seconds=59)) is not None
    assert registry.validate("tok", CLIENT, NOW + timedelta(seconds=61)) is None


def test_re_login_replaces_the_previous_session_for_that_address() -> None:
    """Otherwise the old token outlives the visible session and re-authorizes the address."""
    registry = PortalSessionRegistry(token_expiry_seconds=60)
    registry.create("alice", CLIENT, "first", NOW)
    registry.create("alice", CLIENT, "second", NOW)
    assert registry.validate("first", CLIENT, NOW) is None
    assert registry.validate("second", CLIENT, NOW) is not None
    assert len(registry.list_sessions(NOW)) == 1


def test_the_session_table_is_bounded() -> None:
    """An unauthenticated LAN can drive this structure, so it carries a cap like every other."""
    registry = PortalSessionRegistry(token_expiry_seconds=60, max_sessions=4)
    for index in range(50):
        registry.create("user", IPv4Address(f"192.168.100.{index + 10}"), f"tok{index}", NOW)
    assert len(registry.list_sessions(NOW)) <= 4


def test_purge_expired_returns_what_it_retired() -> None:
    """The caller uses the return value to retire nft elements, so it has to be accurate."""
    registry = PortalSessionRegistry(token_expiry_seconds=60)
    registry.create("alice", CLIENT, "tok", NOW)
    assert registry.purge_expired(NOW) == []
    retired = registry.purge_expired(NOW + timedelta(seconds=61))
    assert [session.token for session in retired] == ["tok"]
    assert registry.list_sessions(NOW + timedelta(seconds=61)) == []


# ---------------------------------------------------------------- throttle


def test_throttle_locks_out_after_the_configured_failure_count() -> None:
    throttle = LoginThrottle(max_failures=3, window_seconds=300)
    for _ in range(2):
        throttle.record_failure(CLIENT, NOW)
    assert throttle.is_locked_out(CLIENT, NOW) is False
    throttle.record_failure(CLIENT, NOW)
    assert throttle.is_locked_out(CLIENT, NOW) is True


def test_throttle_lockout_lapses_with_the_window() -> None:
    throttle = LoginThrottle(max_failures=2, window_seconds=300)
    for _ in range(2):
        throttle.record_failure(CLIENT, NOW)
    assert throttle.is_locked_out(CLIENT, NOW + timedelta(seconds=299)) is True
    assert throttle.is_locked_out(CLIENT, NOW + timedelta(seconds=301)) is False


def test_throttle_is_per_address() -> None:
    """One device guessing passwords must not lock the rest of the network out."""
    throttle = LoginThrottle(max_failures=2, window_seconds=300)
    for _ in range(2):
        throttle.record_failure(CLIENT, NOW)
    assert throttle.is_locked_out(CLIENT, NOW) is True
    assert throttle.is_locked_out(OTHER, NOW) is False


def test_a_successful_login_clears_the_failure_record() -> None:
    throttle = LoginThrottle(max_failures=3, window_seconds=300)
    for _ in range(2):
        throttle.record_failure(CLIENT, NOW)
    throttle.clear(CLIENT)
    assert throttle.seconds_until_unlocked(CLIENT, NOW) == 0


def test_throttle_tracking_is_bounded() -> None:
    """A spoofed-source flood must not grow this table without limit.

    Asserted through behaviour rather than by reading the internal dict:
    once far more addresses than the cap have failed, the earliest ones must
    have been evicted, so they are no longer locked out.
    """
    throttle = LoginThrottle(max_failures=1, window_seconds=300, max_tracked_sources=8)
    addresses = [IPv4Address(f"10.0.{index // 256}.{index % 256}") for index in range(200)]
    for address in addresses:
        throttle.record_failure(address, NOW)
    still_locked = [address for address in addresses if throttle.is_locked_out(address, NOW)]
    assert len(still_locked) <= 8, f"throttle tracked {len(still_locked)} sources despite a cap of 8"
    # The most recent failures are the ones worth keeping.
    assert addresses[-1] in still_locked
