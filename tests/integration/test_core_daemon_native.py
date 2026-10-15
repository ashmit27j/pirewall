"""`CoreDaemon` on the native capture path, end to end.

The same daemon as `test_core_daemon.py` — every thread, the real RPC
socket, the real pipeline and `FirewallManager` — but with the native
`FlowEngine` doing parsing and aggregation and `FakeFlowCapture` standing in
for the `TPACKET_V3` ring (CLAUDE.md's Protocol/Fake rule). Proves the
native loop's drain ordering, TLS hand-off, statistics and fast path are
wired the same way the Python loop's are.

Skipped where `pirewall_native` is not built or `AF_UNIX` is unavailable.
"""

import socket
import struct
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from pirewall.capture.fake import FakeFlowCapture
from pirewall.core.enums import FirewallAction, ThreatLevel
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.flow.native import NativeFlowAggregator, native_engine_available
from pirewall.ipc.client import UnixSocketRpcClient
from pirewall.runtime.core import CoreDaemon
from pirewall.runtime.watchdog import SystemdNotifier
from tests.helpers.config import make_config
from tests.helpers.packets import eth, ipv4_header, tcp_header

pytestmark = [
    pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="platform has no AF_UNIX support"),
    pytest.mark.skipif(not native_engine_available(), reason="pirewall_native not built"),
]

_DEADLINE_SECONDS = 10.0
_POLL_SECONDS = 0.02
_SYN, _ACK, _PSH, _FIN = 0x02, 0x10, 0x08, 0x01


@pytest.fixture
def socket_path() -> Iterator[str]:
    with tempfile.TemporaryDirectory(prefix="pw-") as directory:
        yield str(Path(directory) / "core.sock")


def _tcp(src: str, dst: str, sport: int, dport: int, flags: int, payload: bytes = b"") -> bytes:
    ip = ipv4_header(6, total_length=40 + len(payload), src=src, dst=dst)
    return eth(0x0800) + ip + tcp_header(sport, dport, flags=flags) + payload


def _wait_for(condition: Callable[[], bool], what: str) -> None:
    deadline = time.monotonic() + _DEADLINE_SECONDS
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(_POLL_SECONDS)
    raise AssertionError(f"timed out waiting for {what}")


def _daemon(socket_path: str, packets: list[bytes | None], **overrides: dict[str, object]) -> CoreDaemon:
    config = make_config(
        api={"rpc_socket_path": socket_path, "history_size": 50},
        firewall={"allowlist_store_path": str(Path(socket_path).parent / "allowlist.json")},
        **overrides,
    )
    aggregator = NativeFlowAggregator(config.flow, config.network.protected_network)
    return CoreDaemon(
        config,
        capture=FakeFlowCapture("test0", aggregator.engine, packets),
        backend=FakeFirewallBackend(),
        notifier=SystemdNotifier(notify_socket=None),
        native_aggregator=aggregator,
    )


def test_native_path_turns_frames_into_flows_and_statistics(socket_path: str) -> None:
    src, dst = "203.0.113.7", "192.168.1.10"
    packets: list[bytes | None] = [
        _tcp(src, dst, 40000, 80, _SYN),
        _tcp(dst, src, 80, 40000, _SYN | _ACK),
        _tcp(src, dst, 40000, 80, _ACK | _PSH, b"GET / HTTP/1.1\r\n\r\n"),
        _tcp(src, dst, 40000, 80, _FIN | _ACK),
        _tcp(dst, src, 80, 40000, _FIN | _ACK),
        eth(0x0806) + bytes(28),  # ARP: counted as unanalysed, never a flow
        None,  # one kernel drop
    ]
    daemon = _daemon(socket_path, packets)
    daemon.start()
    try:
        client = UnixSocketRpcClient(socket_path)
        _wait_for(lambda: len(client.list_flows()) == 1, "the completed session over RPC")
        flow = client.list_flows()[0]
        assert str(flow.source_ip) == src
        assert flow.payload_stats is not None
        assert flow.payload_stats.forward_bytes == len(b"GET / HTTP/1.1\r\n\r\n")
        _wait_for(lambda: len(client.list_threats()) == 1, "the flow's assessment")

        daemon._tick()  # pyright: ignore[reportPrivateUsage]
        stats = client.get_capture_stats()
        assert stats is not None
        assert (stats.packets_seen, stats.packets_malformed, stats.packets_dropped) == (6, 1, 1)
    finally:
        daemon.stop()


def test_native_path_carries_tls_evidence_to_the_flow_it_belongs_to(socket_path: str) -> None:
    src, dst = "203.0.113.100", "192.168.1.30"
    fragment = b"\x01" + struct.pack("!H", 16384)  # CVE-2014-0160 shape
    heartbeat = bytes([24]) + b"\x03\x03" + struct.pack("!H", len(fragment)) + fragment
    packets: list[bytes | None] = [
        _tcp(src, dst, 51234, 443, _SYN),
        _tcp(dst, src, 443, 51234, _SYN | _ACK),
        _tcp(src, dst, 51234, 443, _ACK | _PSH, heartbeat),
        _tcp(src, dst, 51234, 443, _FIN | _ACK),
        _tcp(dst, src, 443, 51234, _FIN | _ACK),
    ]
    daemon = _daemon(socket_path, packets)
    daemon.start()
    try:
        client = UnixSocketRpcClient(socket_path)
        _wait_for(lambda: len(client.list_threats()) == 1, "the flow's assessment")
        assessment = client.list_threats()[0]
        assert assessment.protocol_signature_evidence is not None
        assert assessment.protocol_signature_evidence.signature == "heartbleed"
    finally:
        daemon.stop()


def test_native_path_rate_limits_a_scan_before_any_flow_completes(socket_path: str) -> None:
    src, dst = "203.0.113.70", "192.168.1.10"
    packets: list[bytes | None] = [_tcp(src, dst, 40000 + port, port, _SYN) for port in range(7000, 7030)]
    daemon = _daemon(
        socket_path, packets, flow={"active_timeout_seconds": 3600, "inactive_timeout_seconds": 3600}
    )
    daemon.start()
    try:
        client = UnixSocketRpcClient(socket_path)
        _wait_for(
            lambda: any(d.action is FirewallAction.RATE_LIMIT for d in client.list_decisions()),
            "a RATE_LIMIT decision from the source-level fast path",
        )
        assert daemon._counters.flows_completed == 0  # pyright: ignore[reportPrivateUsage]
        threats = [t for t in client.list_threats() if str(t.source_ip) == src]
        assert threats and threats[0].threat_level is ThreatLevel.HIGH
    finally:
        daemon.stop()
