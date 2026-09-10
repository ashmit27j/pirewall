"""`pirewall.firewall.allowlist_store.AllowlistStore` (KNOWN_ISSUES.md #10)."""

from datetime import UTC, datetime
from ipaddress import IPv4Network
from pathlib import Path

from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.firewall.allowlist_store import AllowlistStore

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _entry(entry_id: str = "entry-1", target: str = "192.168.1.50/32") -> AllowlistEntry:
    return AllowlistEntry(
        id=entry_id,
        target=IPv4Network(target),
        reason="printer",
        created_at=NOW,
        created_by="admin",
    )


def test_missing_file_is_an_empty_store(tmp_path: Path) -> None:
    store = AllowlistStore(tmp_path / "allowlist.json")
    assert store.list_entries() == []


def test_add_persists_across_a_new_store_instance(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    AllowlistStore(path).add(_entry())

    reloaded = AllowlistStore(path)
    assert [entry.id for entry in reloaded.list_entries()] == ["entry-1"]
    assert reloaded.list_entries()[0].target == IPv4Network("192.168.1.50/32")


def test_remove_persists_across_a_new_store_instance(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    store = AllowlistStore(path)
    store.add(_entry())

    assert store.remove("entry-1") is True
    assert AllowlistStore(path).list_entries() == []


def test_remove_of_an_id_never_added_returns_false(tmp_path: Path) -> None:
    store = AllowlistStore(tmp_path / "allowlist.json")
    assert store.remove("never-existed") is False


def test_add_overwrites_an_entry_with_the_same_id(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    store = AllowlistStore(path)
    store.add(_entry(target="192.168.1.50/32"))
    store.add(_entry(target="192.168.1.99/32"))

    entries = AllowlistStore(path).list_entries()
    assert len(entries) == 1
    assert entries[0].target == IPv4Network("192.168.1.99/32")


def test_file_is_written_with_restrictive_permissions(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    AllowlistStore(path).add(_entry())

    assert (path.stat().st_mode & 0o777) == 0o600


def test_parent_directory_is_created_if_missing(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "allowlist.json"
    AllowlistStore(path).add(_entry())

    assert path.is_file()
