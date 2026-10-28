"""Demo portal accounts (KNOWN_ISSUES.md #4, PLAN_FINAL §4.9).

`portal_users remove-demo`, the startup refusal while enforcing
(`pirewall.portal.demo_policy`), and the portal's per-account throttle
through `PortalService`, which is where the demo accounts would be guessed.
"""

import tempfile
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from scripts.deployment import portal_users

from pirewall.config.models import PirewallConfig
from pirewall.core.enums import EnforcementMode, SecurityEventType
from pirewall.core.exceptions import ConfigurationError
from pirewall.core.models.event import SecurityEvent
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.portal_service import PortalLoginError, PortalService
from pirewall.portal.demo_policy import refuse_demo_accounts_when_enforcing
from pirewall.portal.store import PortalUserStore
from tests.helpers.config import make_config

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _store(tmp_path: Path) -> PortalUserStore:
    return PortalUserStore(tmp_path / "portal_users.json")


def _seed(store: PortalUserStore) -> None:
    for username, password in portal_users.DEMO_ACCOUNTS[:2]:
        store.add(username, password, NOW, created_by="seed-demo", is_demo=True)
    store.add("alice", "a-real-password", NOW, created_by="cli")


# ------------------------------------------------------------- remove-demo


def test_remove_demo_removes_every_demo_account_and_nothing_else(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    # A rotated demo-* account is no longer public, but is still a sample.
    store.add("demo-zed", "rotated", NOW, created_by="cli")

    assert store.remove_demo_accounts() == ["demo-alice", "demo-bob", "demo-zed"]
    assert [user.username for user in _store(tmp_path).list_users()] == ["alice"]


def test_remove_demo_command_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    store = _store(tmp_path)
    _seed(store)
    def _open(_path: Path) -> PortalUserStore:
        return store

    monkeypatch.setattr(portal_users, "_open_store", _open)

    assert portal_users.main(["remove-demo"]) == portal_users.EXIT_OK
    first = capsys.readouterr().out
    assert "Removed 2 demo account(s)" in first
    assert "demo-alice" in first
    assert "demo-bob" in first

    assert portal_users.main(["remove-demo"]) == portal_users.EXIT_OK
    assert "nothing to do" in capsys.readouterr().out
    assert [user.username for user in _store(tmp_path).list_users()] == ["alice"]


# --------------------------------------------------------- startup refusal


def _config(tmp_path: Path, mode: EnforcementMode, **portal: object) -> PirewallConfig:
    return make_config(
        firewall={"enforcement_mode": mode.value},
        portal={"enabled": True, "user_store_path": str(tmp_path / "portal_users.json"), **portal},
    )


@pytest.mark.parametrize("mode", [EnforcementMode.ASSISTED, EnforcementMode.ACTIVE])
def test_enforcing_with_demo_accounts_is_refused(tmp_path: Path, mode: EnforcementMode) -> None:
    _seed(_store(tmp_path))
    with pytest.raises(ConfigurationError, match="remove-demo") as excinfo:
        refuse_demo_accounts_when_enforcing(_config(tmp_path, mode))
    assert "demo-alice" in str(excinfo.value)
    assert "pirewall-demo-" not in str(excinfo.value), "the refusal must not print the passwords"


def test_shadow_with_demo_accounts_starts(tmp_path: Path) -> None:
    _seed(_store(tmp_path))
    refuse_demo_accounts_when_enforcing(_config(tmp_path, EnforcementMode.SHADOW))


def test_an_explicit_opt_in_allows_demo_accounts_while_enforcing(tmp_path: Path) -> None:
    _seed(_store(tmp_path))
    refuse_demo_accounts_when_enforcing(
        _config(tmp_path, EnforcementMode.ACTIVE, allow_demo_accounts=True)
    )


def test_enforcing_without_demo_accounts_starts(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    store.remove_demo_accounts()
    refuse_demo_accounts_when_enforcing(_config(tmp_path, EnforcementMode.ACTIVE))


def test_a_disabled_portal_never_opens_the_store(tmp_path: Path) -> None:
    (tmp_path / "portal_users.json").write_text("not json", encoding="utf-8")
    config = _config(tmp_path, EnforcementMode.ACTIVE, enabled=False)
    refuse_demo_accounts_when_enforcing(config)


def test_pirewall_core_exits_before_starting_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal is wired into `pirewall-core`'s entry point, ahead of `--check-config`."""
    pytest.importorskip("fcntl", reason="pirewall.main imports POSIX-only modules")
    from pirewall import main as core_main

    _seed(_store(tmp_path))
    configs = {
        EnforcementMode.ASSISTED: _config(tmp_path, EnforcementMode.ASSISTED),
        EnforcementMode.SHADOW: _config(tmp_path, EnforcementMode.SHADOW),
    }
    for mode, expected in (
        (EnforcementMode.ASSISTED, core_main.EXIT_FAILURE),
        (EnforcementMode.SHADOW, core_main.EXIT_OK),
    ):
        chosen = configs[mode]

        def _load(_path: Path, chosen: PirewallConfig = chosen) -> PirewallConfig:
            return chosen

        monkeypatch.setattr(core_main, "load", _load)
        assert core_main.main(["--check-config"]) == expected


# --------------------------------------------- portal per-account throttle


class _Portal:
    def __init__(self) -> None:
        config = make_config(
            portal={
                "enabled": True,
                "max_failed_logins_per_ip": 5,
                "max_failed_logins_per_account": 3,
                "max_failed_logins_global": 50,
            }
        )
        self.store = PortalUserStore(Path(tempfile.mkdtemp()) / "users.json")
        self.store.add("alice", "right", NOW, created_by="cli")
        self.events: list[SecurityEvent] = []
        self.service = PortalService(
            config,
            FirewallManager(config, FakeFirewallBackend()),
            self.store,
            on_event=self.events.append,
            now_fn=lambda: NOW,
        )


def test_portal_locks_an_account_guessed_from_many_addresses() -> None:
    portal = _Portal()
    for index in range(3):
        with pytest.raises(PortalLoginError, match="Invalid username or password"):
            portal.service.login("alice", "wrong", IPv4Address(f"192.168.1.{100 + index}"))

    with pytest.raises(PortalLoginError, match="Too many failed attempts"):
        portal.service.login("alice", "right", IPv4Address("192.168.1.200"))
    reasons = [
        event.reason or ""
        for event in portal.events
        if event.event_type is SecurityEventType.AUTHENTICATION_FAILURE
    ]
    assert any("lockout started (account)" in reason for reason in reasons)
    assert any("account lockout" in reason for reason in reasons)


def test_portal_account_lockout_leaves_other_accounts_alone() -> None:
    portal = _Portal()
    portal.store.add("bob", "bobs", NOW, created_by="cli")
    for index in range(3):
        with pytest.raises(PortalLoginError):
            portal.service.login("alice", "wrong", IPv4Address(f"192.168.1.{100 + index}"))
    session = portal.service.login("bob", "bobs", IPv4Address("192.168.1.200"))
    assert session.username == "bob"
