"""`pipeline.engine = "v2"` end to end on a pcap replay, env=mock (phase 17).

The whole daemon (every thread, the real RPC socket, `FirewallManager` over
the in-memory set fake) replays an inline pcap: one MAC SYN-scans a LAN
host, another browses. The phase-18 mock pcaps do not exist yet, so the
fixture is inline, as the phase prompt allows. Mocked: nothing reaches the
kernel; the "block" is an element in `FakeSetBackend`.

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
from pirewall.core.enums import EnforcementMode, FirewallAction, RuleStatus
from pirewall.flow.native import native_engine_available
from pirewall.ipc.client import UnixSocketRpcClient
from pirewall.runtime.core import CoreDaemon
from pirewall.runtime.watchdog import SystemdNotifier
from tests.helpers.config import make_config
from tests.helpers.traffic import ACK, FIN, PSH, RST, SYN, T0_US, mac_of, tcp

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="platform has no AF_UNIX support")

_REPO: Final = Path(__file__).resolve().parents[2]
_DEADLINE_SECONDS: Final = 15.0
ATTACKER: Final = "192.168.1.66"
BROWSER: Final = "192.168.1.20"
VICTIM: Final = "192.168.1.10"
WEB: Final = "203.0.113.7"


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


def _write_pcap(path: Path) -> None:
    frames: list[bytes] = []
    for port in range(1, 121):  # a SYN scan: closed ports answer RST
        frames.append(tcp(ATTACKER, VICTIM, 51000, port, SYN))
        frames.append(tcp(VICTIM, ATTACKER, port, 51000, RST | ACK))
    for session in range(3):  # three ordinary page loads
        sport = 40000 + session
        frames.extend(
            [
                tcp(BROWSER, WEB, sport, 443, SYN),
                tcp(WEB, BROWSER, 443, sport, SYN | ACK),
                tcp(BROWSER, WEB, sport, 443, ACK | PSH, b"x" * 300),
                tcp(WEB, BROWSER, 443, sport, ACK | PSH, b"y" * 1200),
                tcp(BROWSER, WEB, sport, 443, FIN | ACK),
                tcp(WEB, BROWSER, 443, sport, FIN | ACK),
            ]
        )
    with PcapWriter(path) as writer:
        for offset, frame in enumerate(frames):
            writer.write(frame, T0_US + offset * 2_000)


@pytest.mark.parametrize("native", [True, False], ids=["native", "python"])
@pytest.mark.parametrize("mode", [EnforcementMode.ACTIVE, EnforcementMode.ASSISTED, EnforcementMode.SHADOW])
def test_the_scanner_is_acted_on_and_the_browser_is_not(
    workdir: Path, native: bool, mode: EnforcementMode, monkeypatch: pytest.MonkeyPatch
) -> None:
    if native and not native_engine_available():
        pytest.skip("pirewall_native not built")
    if not native:
        monkeypatch.setattr("pirewall.capture.replay.native_engine_available", lambda: False)
    capture_file = workdir / "mock.pcap"
    _write_pcap(capture_file)
    socket_path = str(workdir / "core.sock")
    config = make_config(
        api={"rpc_socket_path": socket_path, "history_size": 500},
        firewall={"allowlist_store_path": str(workdir / "allowlist.json"), "enforcement_mode": mode.value},
        capture={"interface": "eth1", "backend": "replay", "replay_path": str(capture_file)},
        antispoof={"lease_file": str(workdir / "leases")},
        pipeline={"engine": "v2"},
        d1={"thresholds_path": str(_REPO / "config" / "d1_thresholds.toml")},
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

        def scanner_rules() -> list[object]:
            return [rule for rule in client.list_rules() if str(rule.source.network_address) == ATTACKER]

        _wait_for(lambda: bool(scanner_rules()), "a decision on the scanner")
        time.sleep(0.5)  # let the rest of the replay drain through the detectors
        rules = client.list_rules()
        events = client.list_events()
    finally:
        daemon.stop()

    scanner = [rule for rule in rules if str(rule.source.network_address) == ATTACKER]
    assert scanner and all(
        rule.target is not None and rule.target.mac == mac_of_str(ATTACKER) for rule in scanner
    )
    assert not [rule for rule in rules if str(rule.source.network_address) == BROWSER]
    statuses = {(rule.action, rule.status) for rule in scanner}
    if mode is EnforcementMode.ACTIVE:
        assert (FirewallAction.BLOCK, RuleStatus.ACTIVE) in statuses
    elif mode is EnforcementMode.ASSISTED:
        assert (FirewallAction.BLOCK, RuleStatus.PENDING_APPROVAL) in statuses
        assert (FirewallAction.RATE_LIMIT, RuleStatus.ACTIVE) in statuses
    else:
        assert {status for _, status in statuses} == {RuleStatus.SHADOWED}
    decisions = [event for event in events if event.event_type.value == "policy_decision"]
    assert decisions and all(event.engine is not None and event.engine.value == "v2" for event in decisions)
    assert all(event.mac == mac_of_str(ATTACKER) for event in decisions)


def mac_of_str(address: str) -> str:
    return ":".join(f"{byte:02x}" for byte in mac_of(address))
