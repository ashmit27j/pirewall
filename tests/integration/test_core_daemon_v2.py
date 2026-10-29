"""`CoreDaemon` with the phase-16 wiring: set backend, v2 snapshots, replay, panic fallback.

Every test runs the whole daemon (all threads, the real RPC socket) over
`FakeSetBackend` + `FakeFirewallBackend`: no root, no nft. Skipped where
`AF_UNIX` is unavailable.
"""

import socket
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from pirewall.capture.fake import FakeFlowCapture, FakePacketCapture
from pirewall.capture.pcapio import PcapWriter
from pirewall.capture.replay import ReplayCapture, ReplayPacketCapture
from pirewall.config.models import PirewallConfig
from pirewall.core import nft_names
from pirewall.core.enums import EventSeverity, GuardMode, PipelineEngine, SecurityEventType
from pirewall.core.exceptions import ConfigurationError, NativeEngineError
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from pirewall.firewall.sets import SetOp, SetOpKind
from pirewall.flow.native import NativeFlowAggregator, native_engine_available
from pirewall.ipc.client import UnixSocketRpcClient
from pirewall.runtime.core import CoreDaemon, check_engine_implemented
from pirewall.runtime.watchdog import SystemdNotifier
from tests.helpers.config import make_config
from tests.helpers.traffic import ACK, FIN, SYN, T0_US, tcp

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="platform has no AF_UNIX support")

_DEADLINE_SECONDS = 10.0


@pytest.fixture
def workdir() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="pw-") as directory:
        yield Path(directory)


def _wait_for(condition: Callable[[], bool], what: str) -> None:
    deadline = time.monotonic() + _DEADLINE_SECONDS
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


def _config(workdir: Path, **overrides: dict[str, Any]) -> PirewallConfig:
    sections: dict[str, dict[str, Any]] = {
        "api": {"rpc_socket_path": str(workdir / "core.sock"), "history_size": 100},
        "firewall": {"allowlist_store_path": str(workdir / "allowlist.json")},
        "antispoof": {"lease_file": str(workdir / "leases")},
        "capture": {"interface": "eth1"},
    }
    for section, values in overrides.items():
        sections[section] = {**sections.get(section, {}), **values}
    return make_config(**sections)


def _daemon(config: PirewallConfig, sets: FakeSetBackend | None, **kwargs: Any) -> CoreDaemon:
    kwargs.setdefault("capture", FakePacketCapture("eth1", []))
    return CoreDaemon(
        config,
        backend=FakeFirewallBackend(),
        set_backend=sets,
        notifier=SystemdNotifier(notify_socket=None),
        **kwargs,
    )


def _event_reasons(daemon_client: UnixSocketRpcClient) -> list[str]:
    return [event.reason or "" for event in daemon_client.list_events()]


def test_guard_modes_are_published_and_served_over_the_socket(workdir: Path) -> None:
    (workdir / "leases").write_text("")
    sets = FakeSetBackend(lambda: datetime.now(UTC))
    daemon = _daemon(_config(workdir), sets)
    daemon.start()
    try:
        client = UnixSocketRpcClient(str(workdir / "core.sock"))
        modes = client.get_guard_modes()
        assert (modes.raw, modes.input, modes.forward) == (
            GuardMode.ENFORCE,
            GuardMode.ENFORCE,
            GuardMode.OBSERVE,
        )
        stats = client.get_engine_stats()
        assert stats.backend == "python"
        assert stats.panics_caught == 0
        assert client.list_bindings() == ()
    finally:
        daemon.stop()


def test_the_v2_reads_never_wait_for_the_rpc_lock(workdir: Path) -> None:
    """V2_CONTRACTS §9: served from snapshots, so a busy pipeline cannot stall them."""
    (workdir / "leases").write_text("")
    daemon = _daemon(_config(workdir), FakeSetBackend(lambda: datetime.now(UTC)))
    daemon.start()
    client = UnixSocketRpcClient(str(workdir / "core.sock"), timeout_seconds=2.0)
    release = threading.Event()
    held = threading.Event()

    def hold_the_lock() -> None:
        with daemon._lock:  # pyright: ignore[reportPrivateUsage]
            held.set()
            release.wait(5.0)

    holder = threading.Thread(target=hold_the_lock)
    holder.start()
    try:
        assert held.wait(2.0)
        started = time.monotonic()
        client.get_guard_modes()
        client.list_bindings()
        client.list_offenders()
        client.get_engine_stats()
        assert time.monotonic() - started < 1.0
    finally:
        release.set()
        holder.join()
        daemon.stop()


def test_a_missing_v2_table_raises_critical_and_is_never_recreated(workdir: Path) -> None:
    (workdir / "leases").write_text("")
    sets = FakeSetBackend(lambda: datetime.now(UTC))
    daemon = _daemon(_config(workdir), sets)
    daemon.start()
    try:
        client = UnixSocketRpcClient(str(workdir / "core.sock"))
        sets.panic()  # the tables vanish behind core's back
        _wait_for(
            lambda: any("v2 table(s) missing" in reason for reason in _event_reasons(client)),
            "the table-loss CRITICAL",
        )
        critical = [e for e in client.list_events() if "v2 table(s) missing" in (e.reason or "")]
        assert critical[0].severity is EventSeverity.CRITICAL
        assert not sets.table_exists(nft_names.INET_FAMILY, nft_names.STATIC_TABLE)
        client.get_status()  # core still serving: this raises if the socket went away
    finally:
        daemon.stop()


def test_start_reconciles_with_elements_left_by_a_previous_run(workdir: Path) -> None:
    (workdir / "leases").write_text("")
    sets = FakeSetBackend(lambda: datetime.now(UTC))
    sets.apply([SetOp(SetOpKind.ADD, nft_names.SET_BLOCK4, "192.168.1.77", 600)])
    daemon = _daemon(_config(workdir), sets)
    daemon.start()
    try:
        client = UnixSocketRpcClient(str(workdir / "core.sock"))
        active = [rule for rule in client.list_rules() if rule.id.startswith("reconciled:")]
        assert [str(rule.source) for rule in active] == ["192.168.1.77/32"]
    finally:
        daemon.stop()


def _write_session_pcap(path: Path, starts_us: list[int]) -> None:
    """One short TCP session from each start time, client 192.168.1.10 -> 203.0.113.7."""
    with PcapWriter(path) as writer:
        for index, start in enumerate(starts_us):
            port = 40000 + index
            for offset, frame in enumerate(
                [
                    tcp("192.168.1.10", "203.0.113.7", port, 80, SYN),
                    tcp("203.0.113.7", "192.168.1.10", 80, port, SYN | ACK),
                    tcp("192.168.1.10", "203.0.113.7", port, 80, ACK),
                    tcp("192.168.1.10", "203.0.113.7", port, 80, FIN | ACK),
                ]
            ):
                writer.write(frame, start + offset * 1_000)


@pytest.mark.parametrize("native", [True, False], ids=["native", "python"])
def test_capture_backend_replay_is_selected_and_swept_on_the_replay_clock(
    workdir: Path, native: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Phase 15 hand-off: core picks the replay from config, and sweeps at capture time.

    The pcap starts at `T0_US` (March 2026) and spans ~6 minutes, replayed
    at max speed. Core rebases it to "now", and a wall-clock sweep would
    land months after the capture's start, at most once; the replay-clock
    sweeps land at capture times, ~every 30 s of them, so they span the
    pcap's whole ~6 minutes even though it drains in about a second.
    """
    if native and not native_engine_available():
        pytest.skip("pirewall_native not built")
    if not native:
        monkeypatch.setattr("pirewall.capture.replay.native_engine_available", lambda: False)
    (workdir / "leases").write_text("")
    capture_file = workdir / "mock.pcap"
    _write_session_pcap(capture_file, [T0_US + seconds * 1_000_000 for seconds in (0, 120, 240, 360)])
    config = _config(workdir, capture={"backend": "replay", "replay_path": str(capture_file)})
    daemon = CoreDaemon(
        config,
        backend=FakeFirewallBackend(),
        set_backend=FakeSetBackend(lambda: datetime.now(UTC)),
        notifier=SystemdNotifier(notify_socket=None),
    )
    assert isinstance(daemon._capture, ReplayCapture | ReplayPacketCapture)  # pyright: ignore[reportPrivateUsage]
    sweeps: list[datetime] = []
    original = daemon._sweep_flows  # pyright: ignore[reportPrivateUsage]

    def record(now: datetime) -> None:
        sweeps.append(now)
        original(now)

    monkeypatch.setattr(daemon, "_sweep_flows", record)
    started = datetime.now(UTC)
    daemon.start()
    try:
        client = UnixSocketRpcClient(str(workdir / "core.sock"))
        _wait_for(lambda: any("replay finished" in r for r in _event_reasons(client)), "the replay to end")
        _wait_for(lambda: len(client.list_flows()) == 4, "every replayed session")
        assert client.get_engine_stats().backend == "replay"
    finally:
        daemon.stop()
    assert sweeps, "the replay should have been swept on its own clock"
    # Rebasing puts the capture in the present; the sweeps still land on
    # its ~6 minutes of capture time, which no wall-clock sweep could do in
    # a replay that drains in about a second. The sessions are 120 s apart,
    # so a 30 s cleanup interval sweeps at 120, 240 and 360 s.
    assert len(sweeps) >= 3
    assert max(sweeps) - min(sweeps) >= timedelta(seconds=200)
    assert all(abs((sweep - started).total_seconds()) < 400 for sweep in sweeps)


class _PanickingCapture(FakeFlowCapture):
    """A ring whose every poll hits a (caught) engine panic."""

    def poll(self, timeout_ms: int) -> int:
        del timeout_ms
        raise NativeEngineError("injected panic in poll")


@pytest.mark.skipif(not native_engine_available(), reason="pirewall_native not built")
def test_repeated_native_panics_fall_back_to_the_python_capture_path(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D6: N panics within a minute swap the live ring for AFPacketCapture, with a CRITICAL event."""
    (workdir / "leases").write_text("")
    config = _config(workdir, capture={"native_max_panics_per_minute": 3})
    aggregator = NativeFlowAggregator(config.flow, config.network.protected_network)
    replacement = FakePacketCapture("eth1", [])

    def _replacement(**_kwargs: object) -> FakePacketCapture:
        return replacement

    monkeypatch.setattr("pirewall.runtime.core.AFPacketCapture", _replacement)
    daemon = _daemon(
        config,
        FakeSetBackend(lambda: datetime.now(UTC)),
        capture=_PanickingCapture("eth1", aggregator.engine, []),
        native_aggregator=aggregator,
    )
    daemon.start()
    try:
        client = UnixSocketRpcClient(str(workdir / "core.sock"))
        _wait_for(
            lambda: any("switched to the Python capture path" in r for r in _event_reasons(client)),
            "the fallback",
        )
        events = client.list_events()
        caught = [e for e in events if "panic caught and recovered" in (e.reason or "")]
        assert len(caught) == 3
        assert all(e.event_type is SecurityEventType.CAPTURE_ERROR for e in caught)
        switched = next(e for e in events if "switched to the Python" in (e.reason or ""))
        assert switched.severity is EventSeverity.CRITICAL
        _wait_for(lambda: client.get_engine_stats().backend == "python", "the engine stats to follow")
        assert client.get_engine_stats().panics_caught == 3
        assert daemon._capture is replacement  # pyright: ignore[reportPrivateUsage]
    finally:
        daemon.stop()


def test_engine_v2_is_implemented_but_assisted_needs_the_d1_thresholds(workdir: Path) -> None:
    missing = str(workdir / "no_thresholds.toml")
    config = _config(
        workdir,
        pipeline={"engine": PipelineEngine.V2.value},
        d1={"thresholds_path": missing},
        firewall={"enforcement_mode": "assisted"},
    )

    check_engine_implemented(config)  # v2 ships in phase 17
    with pytest.raises(ConfigurationError, match="D1 thresholds"):
        _daemon(config, None)


def test_engine_v2_in_shadow_falls_back_to_the_floors(workdir: Path) -> None:
    config = _config(
        workdir, pipeline={"engine": PipelineEngine.V2.value}, d1={"thresholds_path": str(workdir / "none")}
    )

    daemon = _daemon(config, FakeSetBackend(lambda: datetime.now(UTC)))

    assert daemon.v2_pipeline is not None
    assert daemon.v2_pipeline.d1.thresholds.provenance["source"] == "floors"


def test_mock_firewall_runs_on_fakes_without_any_injection(workdir: Path) -> None:
    (workdir / "leases").write_text("")
    capture_file = workdir / "mock.pcap"
    _write_session_pcap(capture_file, [T0_US])
    config = _config(workdir, capture={"backend": "replay", "replay_path": str(capture_file)})
    daemon = CoreDaemon(config, notifier=SystemdNotifier(notify_socket=None), mock_firewall=True)
    daemon.start()
    try:
        client = UnixSocketRpcClient(str(workdir / "core.sock"))
        assert client.get_guard_modes().forward is GuardMode.OBSERVE
        _wait_for(lambda: len(client.list_flows()) == 1, "the replayed session")
    finally:
        daemon.stop()
