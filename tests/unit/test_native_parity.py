"""The native engine must produce exactly what the Python capture path produces.

`pirewall_native.FlowEngine` (native/src/) replaces `parse_packet` +
`FlowAggregator` on the packet hot path. Feature schema 2.0.0 exists because
training and runtime once disagreed about what a flow statistic meant; two
runtime implementations disagreeing would reopen that gap. So this feeds one
deterministic, deliberately nasty frame stream through both and requires
identical output — every completed flow field-for-field (floats compared
exactly, not approximately), every new-flow signal, every TLS candidate, the
malformed count, sweeps, slow-connection clusters, snapshots and the final
flush.

Skipped where the extension is not built (`uv sync --extra native`).
"""

import random
import struct
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network

import pytest

from pirewall.capture.parser import extract_tcp_payload, parse_packet
from pirewall.config.models import FlowConfig
from pirewall.core.enums import Protocol
from pirewall.core.exceptions import PacketParseError
from pirewall.core.models.flow import Flow
from pirewall.flow.aggregator import FlowAggregator, NewFlowSignal
from pirewall.flow.native import NativeFlowAggregator, native_engine_available
from tests.helpers.packets import eth, ipv4_header, ipv6_header, mac_bytes, tcp_header, udp_header

pytestmark = pytest.mark.skipif(not native_engine_available(), reason="pirewall_native not built")

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
PROTECTED = IPv4Network("192.168.100.0/24")
CONFIG = FlowConfig(active_timeout_seconds=120, inactive_timeout_seconds=60, max_flows=64)

_FIN, _SYN, _RST, _PSH, _ACK = 0x01, 0x02, 0x04, 0x08, 0x10
ATTACKER_MAC = "02:00:00:00:00:ee"


def _mac_of(address: str) -> bytes:
    """A distinct, locally administered MAC per address, so a mixed-up MAC shows up in the comparison."""
    return b"\x02\x00" + bytes(int(part) for part in address.split("."))


def _frame(src: str, dst: str, src_mac: bytes | None) -> bytes:
    return eth(0x0800, src_mac=src_mac or _mac_of(src), dst_mac=_mac_of(dst))


def _tcp(
    src: str, dst: str, sport: int, dport: int, flags: int, payload: bytes = b"", src_mac: bytes | None = None
) -> bytes:
    ip = ipv4_header(6, total_length=40 + len(payload), src=src, dst=dst)
    return _frame(src, dst, src_mac) + ip + tcp_header(sport, dport, flags=flags) + payload


def _udp(src: str, dst: str, sport: int, dport: int, payload: bytes = b"") -> bytes:
    ip = ipv4_header(17, total_length=28 + len(payload), src=src, dst=dst)
    return _frame(src, dst, None) + ip + udp_header(sport, dport, 8 + len(payload)) + payload


def _icmp(src: str, dst: str) -> bytes:
    header = _frame(src, dst, None) + ipv4_header(1, total_length=28, src=src, dst=dst)
    return header + b"\x08\x00\x00\x00" + b"\x00" * 4


def _client_hello() -> bytes:
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + b"\x00\x00"
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _frames(seed: int) -> list[tuple[bytes, datetime]]:
    """A long, deterministic, mixed frame stream with a monotone-ish clock."""
    rng = random.Random(seed)
    lan = [f"192.168.100.{i}" for i in range(2, 30)]
    wan = [f"203.0.113.{i}" for i in range(1, 40)]
    clock = T0
    out: list[tuple[bytes, datetime]] = []

    def emit(frame: bytes, jitter_back: bool = False) -> None:
        nonlocal clock
        clock += timedelta(microseconds=rng.randint(0, 400_000))
        moment = clock - timedelta(microseconds=rng.randint(1, 5_000)) if jitter_back else clock
        out.append((frame, moment))

    for _ in range(1_500):
        kind = rng.random()
        client, server = rng.choice(lan), rng.choice(wan)
        sport, dport = rng.randint(1024, 65535), rng.choice([80, 443, 22, 53, 8080, rng.randint(1, 1024)])
        if kind < 0.35:  # a full TCP session, sometimes with data, sometimes half-closed
            emit(_tcp(client, server, sport, dport, _SYN))
            emit(_tcp(server, client, dport, sport, _SYN | _ACK))
            for _ in range(rng.randint(0, 6)):
                size = rng.choice([0, 1, 6, 100, 517, 1448])
                body = _client_hello() if (dport == 443 and size == 517) else bytes(size)
                if rng.random() < 0.5:
                    late = rng.random() < 0.1  # occasionally out of order
                    emit(_tcp(client, server, sport, dport, _ACK | _PSH, body), jitter_back=late)
                else:
                    emit(_tcp(server, client, dport, sport, _ACK | _PSH, body))
            if rng.random() < 0.8:
                emit(_tcp(client, server, sport, dport, _FIN | _ACK))
                emit(_tcp(server, client, dport, sport, _FIN | _ACK))
        elif kind < 0.45:  # scan / flood shapes: unanswered SYNs, RSTs, heartbeat records
            # Sometimes from a spoofed source: another client's IP in the attacker's frame.
            spoofer = mac_bytes(ATTACKER_MAC) if rng.random() < 0.3 else None
            for port in range(rng.randint(2, 20)):
                emit(_tcp(client, server, sport, 1 + port, _SYN, src_mac=spoofer))
            emit(_tcp(server, client, 443, sport, _RST))
            emit(_tcp(client, server, sport, 443, _ACK | _PSH, b"\x18\x03\x02\x00\x03\x01\x40\x00"))
        elif kind < 0.65:
            emit(_udp(client, server, sport, 53, bytes(rng.randint(0, 120))))
            emit(_udp(server, client, 53, sport, bytes(rng.randint(0, 300))))
        elif kind < 0.72:
            emit(_icmp(client, server))
        elif kind < 0.78:  # non-unicast / protected-broadcast: parsed, never aggregated
            emit(_udp("0.0.0.0", "255.255.255.255", 68, 67))
            emit(_udp(client, "192.168.100.255", 137, 137))
            emit(_udp(client, "224.0.0.251", 5353, 5353))
        elif kind < 0.84:  # IPv6: parsed (and validated), never aggregated
            emit(eth(0x86DD) + ipv6_header(17, 8) + udp_header(1, 2, 8))
        elif kind < 0.90:  # unsupported ethertype (ARP)
            emit(eth(0x0806) + bytes(28))
        elif kind < 0.95:  # malformed: truncated in every interesting place
            frame = _tcp(client, server, sport, dport, _ACK, bytes(20))
            emit(frame[: rng.randint(0, len(frame) - 1)])
        else:  # a long quiet gap, so inactive/active timeouts fire mid-stream
            clock += timedelta(seconds=rng.choice([61, 125]))
    return out


def _python_path(
    frames: list[tuple[bytes, datetime]],
) -> tuple[FlowAggregator, list[Flow], list[NewFlowSignal], list[tuple[object, ...]], int]:
    signals: list[NewFlowSignal] = []
    aggregator = FlowAggregator(CONFIG, on_new_flow=signals.append, protected_network=PROTECTED)
    completed: list[Flow] = []
    tls: list[tuple[object, ...]] = []
    malformed = 0
    for raw, moment in frames:
        try:
            packet = parse_packet(raw, moment)
        except PacketParseError:
            malformed += 1
            continue
        if (
            packet.protocol is Protocol.TCP
            and 443 in (packet.source_port, packet.destination_port)
            and isinstance(packet.source_ip, IPv4Address)
        ):
            payload = extract_tcp_payload(raw)
            # The native prefilter: only what check_heartbleed/compute_ja3 can act on.
            if payload and (payload[0] == 24 or (payload[0] == 22 and len(payload) >= 6 and payload[5] == 1)):
                tls.append((packet.source_ip, packet.destination_ip, packet.source_port,
                            packet.destination_port, packet.timestamp, payload))
        completed.extend(aggregator.process_packet(packet))
    return aggregator, completed, signals, tls, malformed


def _comparable(flow: Flow) -> dict[str, object]:
    return flow.model_dump(exclude={"flow_id"})


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_native_engine_matches_the_python_path_exactly(seed: int) -> None:
    frames = _frames(seed)
    python_aggregator, py_completed, py_signals, py_tls, py_malformed = _python_path(frames)

    native = NativeFlowAggregator(CONFIG, PROTECTED)
    for raw, moment in frames:
        native.feed(raw, moment)
    batch = native.drain()

    assert len(py_completed) > 100, "the stream should exercise plenty of completions"
    assert [_comparable(f) for f in batch.completed] == [_comparable(f) for f in py_completed]
    assert batch.new_flows == py_signals
    assert [
        (t.source_ip, t.destination_ip, t.source_port, t.destination_port, t.timestamp, t.payload)
        for t in batch.tls_payloads
    ] == py_tls
    seen, malformed = native.counters()
    assert seen == len(frames)
    assert malformed == py_malformed
    assert len(native) == len(python_aggregator)

    end = frames[-1][1]
    for source in {f.source_ip for f in py_completed[:20]}:
        py_snapshot = python_aggregator.snapshot_open_flow_from(source)
        native_snapshot = native.snapshot_open_flow_from(source)
        assert (py_snapshot is None) == (native_snapshot is None)
        if py_snapshot is not None and native_snapshot is not None:
            assert _comparable(native_snapshot) == _comparable(py_snapshot)

    # (now, min_duration_s, max_bytes_per_s, concurrent_threshold, max_idle_s).
    # The last tuple's wide idle bound keeps the pre-`max_idle_seconds`
    # coverage of a table snapshotted well after its traffic stopped.
    slow_args: list[tuple[datetime, float, float, int, float]] = [
        (end, 0.5, 1e9, 1, 15.0),
        (end, 5.0, 50.0, 2, 15.0),
        (end + timedelta(seconds=30), 15.0, 5.0, 3, 1e9),
    ]
    for args in slow_args:
        py_clusters = python_aggregator.snapshot_slow_connection_clusters(*args)
        native_clusters = native.snapshot_slow_connection_clusters(*args)
        assert [(c.source_ip, c.destination_ip, c.concurrent_count, _comparable(c.representative_flow))
                for c in native_clusters] == [
            (c.source_ip, c.destination_ip, c.concurrent_count, _comparable(c.representative_flow))
            for c in py_clusters
        ]

    sweep_at = end + timedelta(seconds=30)
    assert [_comparable(f) for f in native.sweep_timeouts(sweep_at)] == [
        _comparable(f) for f in python_aggregator.sweep_timeouts(sweep_at)
    ]
    assert [_comparable(f) for f in native.flush()] == [_comparable(f) for f in python_aggregator.flush()]
    assert len(native) == 0


def test_native_flows_feed_the_canonical_extractor() -> None:
    """End of the chain: a native Flow is a valid schema-2.0.0 feature source."""
    from pirewall.features.extractor import extract_features

    native = NativeFlowAggregator(CONFIG, PROTECTED)
    for raw, moment in _frames(9):
        native.feed(raw, moment)
    flows = native.drain().completed
    assert flows
    for flow in flows:
        assert flow.payload_stats is not None
        extract_features(flow)


def test_per_drain_caps_shed_and_count_the_excess() -> None:
    """Load shedding happens in the engine and is always accounted for, never silent."""
    frames = _frames(4)
    _, py_completed, py_signals, _, _ = _python_path(frames)
    native = NativeFlowAggregator(CONFIG, PROTECTED, max_pending_completed=50, max_pending_new_flows=70)
    for raw, moment in frames:
        native.feed(raw, moment)
    batch = native.drain()
    shed_flows, shed_signals = native.shed()
    assert len(batch.completed) == 50
    assert len(batch.new_flows) == 70
    assert shed_flows == len(py_completed) - 50
    assert shed_signals == len(py_signals) - 70
    # What was kept is the head of the same stream, unchanged.
    assert [_comparable(f) for f in batch.completed] == [_comparable(f) for f in py_completed[:50]]


def test_flows_and_signals_carry_the_opening_frames_macs_on_both_paths() -> None:
    """D3: both paths agree on every MAC, and a spoofed source carries the attacker's MAC."""
    victim, server = "192.168.100.10", "203.0.113.9"
    frames = [
        (_tcp(victim, server, 40000, 80, _SYN, src_mac=mac_bytes(ATTACKER_MAC)), T0),
        (_tcp(server, victim, 80, 40000, _RST | _ACK), T0 + timedelta(milliseconds=1)),
        (_tcp(victim, server, 40001, 80, _SYN), T0 + timedelta(milliseconds=2)),
        (_tcp(server, victim, 80, 40001, _RST | _ACK), T0 + timedelta(milliseconds=3)),
    ]
    _, py_completed, py_signals, _, _ = _python_path(frames)
    native = NativeFlowAggregator(CONFIG, PROTECTED)
    for raw, moment in frames:
        native.feed(raw, moment)
    batch = native.drain()

    expected = [ATTACKER_MAC, "02:00:c0:a8:64:0a"]
    assert [flow.source_mac for flow in py_completed] == expected
    assert [flow.source_mac for flow in batch.completed] == expected
    assert [flow.destination_mac for flow in batch.completed] == ["02:00:cb:00:71:09"] * 2
    assert [signal.source_mac for signal in py_signals] == expected
    assert [signal.source_mac for signal in batch.new_flows] == expected
    assert all(str(flow.source_ip) == victim for flow in batch.completed), "the IP header names the victim"
