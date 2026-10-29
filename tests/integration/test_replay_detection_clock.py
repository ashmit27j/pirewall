"""D1 in a mock replay is evaluated on the capture clock, not the wall clock.

Phase 18 hand-over, finding 1: at `replay_speed = "max"` an accelerated
replay fed D1 windows measured with `datetime.now`, so every connection
start in the whole capture fell inside one wall-clock window and benign
devices drew decisions that a real-time replay did not produce.

This fixture is the shape of that failure: one device opens 25 ordinary
sessions to 25 different hosts on one port, spread 12 s apart in capture
time. No 10 s capture-time window contains more than one of them, so D1
must stay silent. Before the fix, a max-speed replay counted all 25 in its
10 s wall-clock window and fired `horizontal_scan` (threshold 20). A scan
at the end of the capture supplies a positive "detection drained" signal:
when its decision appears, every earlier benign flow has been processed.

`evaluation_cooldown_seconds = 0` forces one evaluation per record, which
is what makes the wall-clock bug show up in a replay that drains in well
under the production cooldown.

Skipped where `AF_UNIX` is unavailable.
"""

import socket
import tempfile
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import pytest

from pirewall.capture.pcapio import PcapWriter
from pirewall.capture.replay import build_replay_capture
from pirewall.core.enums import SecurityEventType
from pirewall.flow.native import native_engine_available
from pirewall.ipc.client import UnixSocketRpcClient
from pirewall.runtime.core import CoreDaemon
from pirewall.runtime.watchdog import SystemdNotifier
from tests.helpers.config import make_config
from tests.helpers.traffic import ACK, FIN, PSH, RST, SYN, T0_US, mac_of, tcp

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="platform has no AF_UNIX support")

_REPO: Final = Path(__file__).resolve().parents[2]
_DEADLINE_SECONDS: Final = 15.0
DEVICE: Final = "192.168.1.66"
SCANNER: Final = "192.168.1.99"
VICTIM: Final = "192.168.1.10"
PORT: Final = 445
HOSTS: Final = tuple(f"198.51.100.{octet}" for octet in range(1, 26))
# 12 s apart: every 10 s window holds at most one start, so only a
# wall-clock evaluation (which sees the whole accelerated replay at once)
# can exceed the horizontal_scan floor of 20.
_SPACING_US: Final = 12_000_000


@pytest.fixture
def workdir() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="pw-") as directory:
        yield Path(directory)


def _wait_for(condition: Callable[[], bool], what: str) -> None:
    deadline = time.monotonic() + _DEADLINE_SECONDS
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


def _write_pcap(path: Path) -> int:
    """25 benign sessions 12 s apart, then one vertical scan. Returns the frame count."""
    frames: list[tuple[bytes, int]] = []
    for index, host in enumerate(HOSTS):
        sport = 40000 + index
        base = T0_US + index * _SPACING_US
        frames.extend(
            [
                (tcp(DEVICE, host, sport, PORT, SYN), base),
                (tcp(host, DEVICE, PORT, sport, SYN | ACK), base + 1_000),
                (tcp(DEVICE, host, sport, PORT, ACK | PSH, b"x" * 40), base + 2_000),
                (tcp(DEVICE, host, sport, PORT, FIN | ACK), base + 3_000),
                (tcp(host, DEVICE, PORT, sport, FIN | ACK), base + 4_000),
            ]
        )
    scan_base = T0_US + len(HOSTS) * _SPACING_US + 1_000_000
    for port in range(1, 26):
        at = scan_base + port * 10_000
        frames.append((tcp(SCANNER, VICTIM, 50000, port, SYN), at))
        frames.append((tcp(VICTIM, SCANNER, port, 50000, RST | ACK), at + 1_000))
    with PcapWriter(path) as writer:
        for frame, timestamp in frames:
            writer.write(frame, timestamp)
    return len(frames)


def mac_of_str(address: str) -> str:
    return ":".join(f"{byte:02x}" for byte in mac_of(address))


@pytest.mark.parametrize("native", [True, False], ids=["native", "python"])
def test_a_max_speed_replay_does_not_put_the_whole_capture_in_one_d1_window(
    workdir: Path, native: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    if native and not native_engine_available():
        pytest.skip("pirewall_native not built")
    if not native:
        monkeypatch.setattr("pirewall.capture.replay.native_engine_available", lambda: False)
    capture_file = workdir / "benign.pcap"
    frame_count = _write_pcap(capture_file)
    socket_path = str(workdir / "core.sock")
    config = make_config(
        api={"rpc_socket_path": socket_path, "history_size": 500},
        firewall={
            "allowlist_store_path": str(workdir / "allowlist.json"),
            "enforcement_mode": "shadow",
        },
        capture={"interface": "eth1", "backend": "replay", "replay_path": str(capture_file)},
        antispoof={"lease_file": str(workdir / "leases")},
        pipeline={"engine": "v2"},
        d1={
            "thresholds_path": str(_REPO / "config" / "d1_thresholds.toml"),
            "evaluation_cooldown_seconds": 0.0,
        },
        lab={"env_tag": "mock"},
    )
    capture, aggregator = build_replay_capture(config, rebase_to=datetime.now(UTC))
    daemon = CoreDaemon(
        config,
        capture=capture,
        native_aggregator=aggregator,
        notifier=SystemdNotifier(notify_socket=None),
        mock_firewall=True,
    )
    daemon.start()
    try:
        client = UnixSocketRpcClient(socket_path)
        _wait_for(lambda: client.get_engine_stats().frames_seen >= frame_count, "the replay to drain")

        def scanner_decided() -> bool:
            return any(
                event.event_type is SecurityEventType.POLICY_DECISION
                and event.mac == mac_of_str(SCANNER)
                for event in client.list_events()
            )

        _wait_for(scanner_decided, "a decision on the trailing scan")
        events = client.list_events()
    finally:
        daemon.stop()

    decisions = [
        event
        for event in events
        if event.event_type is SecurityEventType.POLICY_DECISION and event.mac == mac_of_str(DEVICE)
    ]
    assert decisions == [], [event.reason for event in decisions]
