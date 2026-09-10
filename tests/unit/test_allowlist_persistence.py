"""`FirewallManager` + `AllowlistStore` wiring (KNOWN_ISSUES.md #10).

`POST /api/v1/allowlist` used to mutate `FirewallManager`'s in-memory list
only, so every runtime-added entry was lost on the next restart. These
tests build a fresh `FirewallManager` from the same on-disk store to
simulate exactly that restart, the way `tests/unit/test_allowlist_store.py`
does for the store alone.
"""

from datetime import UTC, datetime
from ipaddress import IPv4Network
from pathlib import Path

from pirewall.config.models import PirewallConfig
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.firewall.allowlist_store import AllowlistStore
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from tests.helpers.config import make_config

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _entry(entry_id: str, target: str) -> AllowlistEntry:
    return AllowlistEntry(
        id=entry_id,
        target=IPv4Network(target),
        reason="printer",
        created_at=NOW,
        created_by="admin",
    )


def _manager_with_store(config: PirewallConfig, store: AllowlistStore) -> FirewallManager:
    return FirewallManager(config, FakeFirewallBackend(), store)


def test_an_entry_added_at_runtime_survives_a_restart(tmp_path: Path) -> None:
    store_path = tmp_path / "allowlist.json"
    config = make_config()

    first_run = _manager_with_store(config, AllowlistStore(store_path))
    first_run.add_allowlist_entry(_entry("runtime-1", "192.168.1.50/32"))

    # A fresh manager over a fresh store instance, exactly what happens
    # across a pirewall-core restart: config is re-read (unchanged, no
    # allowlist entries of its own here) and the store is re-loaded from
    # the same file.
    second_run = _manager_with_store(config, AllowlistStore(store_path))

    assert [entry.id for entry in second_run.allowlist] == ["runtime-1"]


def test_removing_a_runtime_added_entry_removes_it_from_the_store(tmp_path: Path) -> None:
    store_path = tmp_path / "allowlist.json"
    config = make_config()
    manager = _manager_with_store(config, AllowlistStore(store_path))
    manager.add_allowlist_entry(_entry("runtime-1", "192.168.1.50/32"))

    assert manager.remove_allowlist_entry("runtime-1") is True

    after_restart = _manager_with_store(config, AllowlistStore(store_path))
    assert after_restart.allowlist == ()


def test_config_seeded_entries_are_not_removed_from_the_store(tmp_path: Path) -> None:
    """A config-declared entry was never in the store; removing it must not error trying to."""
    store_path = tmp_path / "allowlist.json"
    config = make_config(
        firewall={
            "allowlist": (
                {
                    "id": "config-1",
                    "target": "192.168.1.60/32",
                    "reason": "static seed",
                    "created_at": NOW.isoformat(),
                    "created_by": "deployment",
                },
            )
        }
    )
    manager = _manager_with_store(config, AllowlistStore(store_path))

    assert manager.remove_allowlist_entry("config-1") is True
    assert manager.allowlist == ()
    # The store itself was never touched by removing a config-seeded entry.
    assert AllowlistStore(store_path).list_entries() == []

    # Since the config is static, the same entry reappears on the next
    # "restart" (a fresh manager over the same config) — expected, and
    # distinct from the runtime-added case above. Only a runtime addition
    # is this item's persistence concern.
    after_restart = _manager_with_store(config, AllowlistStore(store_path))
    assert [entry.id for entry in after_restart.allowlist] == ["config-1"]


def test_without_a_store_behavior_is_unchanged() -> None:
    """`allowlist_store=None` (the default) keeps every existing caller working exactly as before."""
    config = make_config()
    manager = FirewallManager(config, FakeFirewallBackend())

    manager.add_allowlist_entry(_entry("runtime-1", "192.168.1.50/32"))
    assert [entry.id for entry in manager.allowlist] == ["runtime-1"]
    assert manager.remove_allowlist_entry("runtime-1") is True
    assert manager.allowlist == ()
