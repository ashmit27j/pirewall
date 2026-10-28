"""`CoreDaemon`'s binding wiring (ADDENDUM_4.md D2, D3; phase 14): the startup seed and lease sync.

Runs the whole daemon with fakes (capture, both firewall backends, systemd)
and a real lease file in a temp directory. The set backend is injected,
which is how core runs on the v2 path until phase 16 makes it the default.
"""

import socket
import tempfile
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from pirewall.capture.fake import FakePacketCapture
from pirewall.core import nft_names
from pirewall.core.enums import GuardMode, GuardName, SecurityEventType
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from pirewall.runtime.core import CoreDaemon
from pirewall.runtime.watchdog import SystemdNotifier
from tests.helpers.config import make_config

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="platform has no AF_UNIX support")

DEVICE = "192.168.1.20"
DEVICE_MAC = "02:00:00:00:00:20"


@pytest.fixture
def workdir() -> Iterator[Path]:
    """A short temp path: `AF_UNIX` names are capped at ~104 bytes on macOS."""
    with tempfile.TemporaryDirectory(prefix="pw") as directory:
        yield Path(directory)


def _daemon(workdir: Path, *, lease_lines: list[str] | None) -> tuple[CoreDaemon, FakeSetBackend]:
    lease_file = workdir / "dnsmasq-wlan0.leases"
    if lease_lines is not None:
        lease_file.write_text("".join(f"{line}\n" for line in lease_lines), encoding="utf-8")
    config = make_config(
        api={"rpc_socket_path": str(workdir / "c.sock"), "history_size": 50},
        firewall={"allowlist_store_path": str(workdir / "allowlist.json")},
        antispoof={"lease_file": str(lease_file), "poll_seconds": 0.05},
        ml={
            "lightgbm_model_path": str(workdir / "none.txt"),
            "isolation_forest_model_path": str(workdir / "none"),
        },
    )
    sets = FakeSetBackend(lambda: datetime.now(UTC))
    daemon = CoreDaemon(
        config,
        capture=FakePacketCapture("test0", []),
        backend=FakeFirewallBackend(),
        notifier=SystemdNotifier(notify_socket=None),
        set_backend=sets,
    )
    return daemon, sets


def _lease(ip: str = DEVICE, mac: str = DEVICE_MAC) -> str:
    return f"{int((datetime.now(UTC) + timedelta(hours=1)).timestamp())} {mac} {ip} phone *"


def _wait_for(condition: Callable[[], bool], what: str) -> None:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


def test_startup_seeds_the_kernel_binding_sets_from_the_lease_file(workdir: Path) -> None:
    daemon, sets = _daemon(workdir, lease_lines=[_lease()])
    daemon.start()
    try:
        assert daemon.bindings.resolve_mac(IPv4Address(DEVICE)) == DEVICE_MAC
        listed = sets.list_set(nft_names.SET_MACBIND, table=nft_names.STATIC_TABLE)
        assert [state.key for state in listed] == [(DEVICE, DEVICE_MAC)]
        assert sets.guard_mode(GuardName.RAW) is GuardMode.ENFORCE
    finally:
        daemon.stop()


def test_a_failed_seed_leaves_the_raw_guard_in_observe_and_says_so(workdir: Path) -> None:
    daemon, sets = _daemon(workdir, lease_lines=None)
    daemon.start()
    try:
        assert sets.guard_mode(GuardName.RAW) is GuardMode.OBSERVE
        assert sets.guard_mode(GuardName.INPUT) is GuardMode.ENFORCE
        warnings = [
            event
            for event in daemon._state.events  # pyright: ignore[reportPrivateUsage]
            if event.event_type is SecurityEventType.SYSTEM_WARNING
            and "binding seed failed" in (event.reason or "")
        ]
        assert warnings, "a failed seed is reported, not silent"
    finally:
        daemon.stop()


def test_the_lease_sync_thread_picks_up_a_new_lease(workdir: Path) -> None:
    daemon, sets = _daemon(workdir, lease_lines=[])
    daemon.start()
    try:
        assert daemon.bindings.snapshot() == ()
        (workdir / "dnsmasq-wlan0.leases").write_text(_lease() + "\n", encoding="utf-8")
        _wait_for(lambda: daemon.bindings.resolve_mac(IPv4Address(DEVICE)) == DEVICE_MAC, "the new lease")
        _wait_for(
            lambda: bool(sets.list_set(nft_names.SET_BOUND4, table=nft_names.STATIC_TABLE)),
            "the kernel binding",
        )
    finally:
        daemon.stop()


def test_a_fail_open_stop_flushes_the_adaptive_sets_and_leaves_every_guard_alone(workdir: Path) -> None:
    """Audit #17: a clean fail-open stop is not the kill switch.

    `revert_to_base` sets every guard to observe, so calling it on shutdown
    turned a crash loop into an off switch. `fail_open_shutdown` flushes
    only the adaptive sets. The leftover element stands in for one a
    previous run deployed: core never tracked it, so the flush must happen
    even with no active rule.
    """
    daemon, sets = _daemon(workdir, lease_lines=[_lease()])
    daemon.start()
    sets.set_guard_mode(GuardName.FORWARD, GuardMode.ENFORCE)
    sets.add_element(nft_names.SET_BLOCK4, "192.168.1.99", 600)
    modes_before = {guard: sets.guard_mode(guard) for guard in GuardName}
    assert not daemon._manager.active_rules()  # pyright: ignore[reportPrivateUsage]

    daemon.stop()

    assert {guard: sets.guard_mode(guard) for guard in GuardName} == modes_before
    assert sets.guard_mode(GuardName.FORWARD) is GuardMode.ENFORCE
    for set_name in nft_names.ADAPTIVE_ENFORCEMENT_SETS:
        assert sets.list_set(set_name) == [], f"{set_name} still holds elements after a fail-open stop"
