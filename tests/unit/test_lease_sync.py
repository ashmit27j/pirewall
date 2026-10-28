"""`pirewall.runtime.lease_sync` (ADDENDUM_4.md D2, D3; phase 14).

The startup seed (and what a failed one does to the raw guard), the polling
pass, its failure handling, and the inotify watcher.
"""

import sys
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from pirewall.config.models import PirewallConfig
from pirewall.core import nft_names
from pirewall.core.bindings import LeaseBindingTable, static_bindings
from pirewall.core.enums import EventSeverity, GuardMode, GuardName, SecurityEventType
from pirewall.core.exceptions import FirewallError
from pirewall.core.models.event import SecurityEvent
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.runtime.lease_sync import SEED_FAILURE_ACTOR, LeaseFileWatcher, LeaseSync
from tests.helpers.config import make_config

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
DEVICE = "192.168.1.20"
DEVICE_MAC = "02:00:00:00:00:20"
STATIC_IP = "192.168.1.5"
STATIC_MAC = "02:00:00:00:00:05"


class _Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


class _Rig:
    def __init__(self, lease_file: Path, *, v2: bool = True) -> None:
        self.clock = _Clock()
        self.config: PirewallConfig = make_config(
            antispoof={
                "lease_file": str(lease_file),
                "static": [{"ip": STATIC_IP, "mac": STATIC_MAC, "reason": "printer"}],
            }
        )
        self.sets = FakeSetBackend(self.clock)
        self.table = LeaseBindingTable(static_bindings(self.config.antispoof.static))
        self.manager = FirewallManager(
            self.config,
            FakeFirewallBackend(),
            set_backend=self.sets if v2 else None,
            mac_resolver=self.table.resolve_mac,
        )
        self.events: list[SecurityEvent] = []
        self.sync = LeaseSync(self.config, self.table, self.manager, self.events.append, now_fn=self.clock)

    def macbind(
        self, table: str = nft_names.STATIC_TABLE, family: str = nft_names.INET_FAMILY
    ) -> list[object]:
        return [state.key for state in self.sets.list_set(nft_names.SET_MACBIND, table=table, family=family)]


def _write(path: Path, *lines: str) -> None:
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


def _lease_line(ip: str = DEVICE, mac: str = DEVICE_MAC, seconds: int = 3600) -> str:
    return f"{int((NOW + timedelta(seconds=seconds)).timestamp())} {mac} {ip} phone *"


@pytest.fixture
def lease_file(tmp_path: Path) -> Iterator[Path]:
    yield tmp_path / "dnsmasq-wlan0.leases"


# --------------------------------------------------------------------- seed


def test_a_good_seed_binds_leases_and_static_entries_and_leaves_the_raw_guard_alone(lease_file: Path) -> None:
    _write(lease_file, _lease_line())
    rig = _Rig(lease_file)
    assert rig.sync.seed() is True
    assert set(rig.macbind()) == {(STATIC_IP, STATIC_MAC), (DEVICE, DEVICE_MAC)}
    assert rig.macbind(nft_names.STATIC_ARP_TABLE, nft_names.ARP_FAMILY) == rig.macbind()
    assert rig.sets.guard_mode(GuardName.RAW) is GuardMode.ENFORCE
    assert rig.events == []


def test_an_empty_lease_file_is_a_successful_seed(lease_file: Path) -> None:
    _write(lease_file)
    assert _Rig(lease_file).sync.seed() is True


def test_a_missing_lease_file_fails_the_seed_and_puts_the_raw_guard_in_observe(lease_file: Path) -> None:
    rig = _Rig(lease_file)
    assert rig.sync.seed() is False
    assert rig.sets.guard_mode(GuardName.RAW) is GuardMode.OBSERVE
    assert rig.sets.guard_mode(GuardName.INPUT) is GuardMode.ENFORCE, "only the raw guard depends on bindings"
    flip, warning = rig.events
    assert SEED_FAILURE_ACTOR in (flip.reason or "")
    assert warning.event_type is SecurityEventType.SYSTEM_WARNING
    assert warning.severity is EventSeverity.WARNING
    assert "lease file could not be read" in (warning.reason or "")
    assert "observe" in (warning.reason or "")
    # Static devices still resolve and are still bound.
    assert rig.macbind() == [(STATIC_IP, STATIC_MAC)]


def test_a_refused_kernel_write_fails_the_seed_too(lease_file: Path) -> None:
    _write(lease_file, _lease_line())
    rig = _Rig(lease_file)
    rig.sets.fail_next = True
    assert rig.sync.seed() is False
    assert rig.sets.guard_mode(GuardName.RAW) is GuardMode.OBSERVE
    assert "writing the binding sets failed" in (rig.events[-1].reason or "")


def test_if_even_the_downgrade_fails_the_warning_is_critical(
    lease_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = _Rig(lease_file)

    def refuse(*_args: object) -> SecurityEvent:
        raise FirewallError("kernel refused")

    monkeypatch.setattr(rig.manager, "set_guard_mode", refuse)
    assert rig.sync.seed() is False
    (warning,) = rig.events
    assert warning.severity is EventSeverity.CRITICAL


def test_on_the_v1_path_a_failed_seed_only_warns(lease_file: Path) -> None:
    rig = _Rig(lease_file, v2=False)
    assert rig.sync.seed() is False
    (warning,) = rig.events
    assert "observe" not in (warning.reason or "")


def test_a_seed_clears_pairs_left_in_the_kernel_by_a_previous_run(lease_file: Path) -> None:
    _write(lease_file, _lease_line(ip="192.168.1.30", mac="02:00:00:00:00:30"))
    rig = _Rig(lease_file)
    rig.sync.seed()
    _write(lease_file, _lease_line())
    fresh = LeaseSync(rig.config, LeaseBindingTable(), rig.manager, rig.events.append, now_fn=rig.clock)
    assert fresh.seed() is True
    assert rig.macbind() == [(DEVICE, DEVICE_MAC)]


# --------------------------------------------------------------------- poll


def test_a_poll_writes_only_what_changed(lease_file: Path) -> None:
    _write(lease_file, _lease_line())
    rig = _Rig(lease_file)
    rig.sync.seed()
    writes = len(rig.sets.ops)
    assert rig.sync.poll() == 0
    assert len(rig.sets.ops) == writes
    _write(lease_file, _lease_line(mac="02:00:00:00:00:99"))
    assert rig.sync.poll() > 0
    assert (DEVICE, "02:00:00:00:00:99") in rig.macbind()
    assert (DEVICE, DEVICE_MAC) not in rig.macbind()


def test_an_expired_lease_is_unbound_without_the_file_changing(lease_file: Path) -> None:
    _write(lease_file, _lease_line(seconds=10))
    rig = _Rig(lease_file)
    rig.sync.seed()
    rig.clock.now += timedelta(seconds=11)
    rig.sync.poll()
    assert rig.table.resolve_mac(IPv4Address(DEVICE)) is None


def test_an_unreadable_file_keeps_the_last_known_bindings_and_reports_once(lease_file: Path) -> None:
    _write(lease_file, _lease_line())
    rig = _Rig(lease_file)
    rig.sync.seed()
    lease_file.unlink()
    rig.sync.poll()
    rig.sync.poll()
    assert rig.table.resolve_mac(IPv4Address(DEVICE)) == DEVICE_MAC
    assert (DEVICE, DEVICE_MAC) in rig.macbind()
    errors = [event for event in rig.events if event.severity is EventSeverity.ERROR]
    assert len(errors) == 1
    _write(lease_file, _lease_line())
    rig.sync.poll()
    assert "readable again" in (rig.events[-1].reason or "")


def test_a_failed_write_is_retried_as_a_full_resync(lease_file: Path) -> None:
    _write(lease_file, _lease_line())
    rig = _Rig(lease_file)
    rig.sync.seed()
    _write(lease_file, _lease_line(mac="02:00:00:00:00:99"))
    rig.sets.fail_next = True
    assert rig.sync.poll() == 0
    assert (DEVICE, DEVICE_MAC) in rig.macbind(), "the refused batch changed nothing"
    rig.sync.poll()  # nothing changed in the file, but the kernel is behind
    assert (DEVICE, "02:00:00:00:00:99") in rig.macbind()
    assert (DEVICE, DEVICE_MAC) not in rig.macbind()


def test_an_oversized_file_is_refused_as_unreadable(lease_file: Path) -> None:
    lease_file.write_bytes(b"x" * (1024 * 1024 + 1))
    rig = _Rig(lease_file)
    assert rig.sync.seed() is False


def test_hostnames_never_reach_an_event_or_the_log(
    lease_file: Path, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "alices-iphone-SECRET"
    _write(lease_file, _lease_line().replace("phone", secret), f"garbage {secret}")
    rig = _Rig(lease_file)
    caplog.set_level("DEBUG")
    rig.sync.seed()
    lease_file.unlink()
    rig.sync.poll()
    assert secret not in caplog.text
    assert all(secret not in (event.reason or "") for event in rig.events)


# --------------------------------------------------------------------- run


def test_run_polls_until_stopped(lease_file: Path) -> None:
    _write(lease_file, _lease_line())
    config = make_config(antispoof={"lease_file": str(lease_file), "poll_seconds": 0.05})
    table = LeaseBindingTable()
    manager = FirewallManager(config, FakeFirewallBackend())
    sync = LeaseSync(config, table, manager, lambda _event: None)
    stop = threading.Event()
    thread = threading.Thread(target=sync.run, args=(stop,))
    thread.start()
    try:
        for _ in range(200):
            if table.resolve_mac(IPv4Address(DEVICE)) is not None:
                break
            stop.wait(0.01)
    finally:
        stop.set()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert table.resolve_mac(IPv4Address(DEVICE)) == DEVICE_MAC


@pytest.mark.skipif(sys.platform != "linux", reason="inotify is Linux-only")
def test_inotify_reports_a_change_to_the_lease_file_and_not_to_its_neighbours(lease_file: Path) -> None:
    _write(lease_file)
    watcher = LeaseFileWatcher(lease_file)
    stop = threading.Event()
    try:
        assert watcher.uses_inotify
        (lease_file.parent / "other.leases").write_text("x", encoding="utf-8")
        assert watcher.wait(0.2, stop) is False
        _write(lease_file, _lease_line())
        assert watcher.wait(1.0, stop) is True
    finally:
        watcher.close()


def test_without_inotify_the_watcher_is_a_plain_timeout(lease_file: Path) -> None:
    watcher = LeaseFileWatcher(lease_file / "missing-dir" / "x.leases")
    assert watcher.uses_inotify is False
    stop = threading.Event()
    stop.set()
    assert watcher.wait(5.0, stop) is False
