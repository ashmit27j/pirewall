"""`CoreDaemon`'s TLS structural-evidence wiring, end to end (ADDENDUM_2.md B4/B5).

Unlike `tests/integration/test_core_daemon.py`, this deliberately never
calls `daemon.start()`/`.stop()` — those bind the real `AF_UNIX` RPC socket,
which this Windows dev machine cannot do (see that file's
`skipif(not hasattr(socket, "AF_UNIX"))`). Everything this file exercises —
`_handle_tcp_payload`, the `_tls_evidence` cache, `_pop_tls_evidence`, and
feeding the result through the real `FlowPipeline` — lives entirely below
that socket, in `CoreDaemon.__init__`'s already-constructed subsystems, so
it runs (and is actually verified) on every platform.
"""

import struct
from datetime import UTC, datetime

from pirewall.capture.fake import FakePacketCapture
from pirewall.capture.parser import parse_packet
from pirewall.core.enums import ThreatLevel
from pirewall.detection.tls_fingerprint import compute_ja3
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.runtime.core import CoreDaemon
from pirewall.runtime.watchdog import SystemdNotifier
from tests.helpers.config import make_config
from tests.helpers.flows import make_flow
from tests.helpers.packets import eth, ipv4_header, tcp_header

NOW = datetime(2026, 1, 1, tzinfo=UTC)

_SRC, _DST = "203.0.113.100", "192.168.1.30"
_SRC_PORT, _DST_PORT = 51234, 443


def _daemon() -> CoreDaemon:
    missing: dict[str, object] = {
        "lightgbm_model_path": "/nonexistent/pirewall-test/lightgbm_model.txt",
        "isolation_forest_model_path": "/nonexistent/pirewall-test/isolation_forest.joblib",
    }
    config = make_config(ml=missing)
    return CoreDaemon(
        config,
        capture=FakePacketCapture("test0", []),
        backend=FakeFirewallBackend(),
        notifier=SystemdNotifier(notify_socket=None),
    )


def _heartbleed_packet() -> bytes:
    fragment = b"\x01" + struct.pack("!H", 16384)  # the CVE-2014-0160 shape (see test_tls_heartbeat.py)
    tls_record = bytes([24]) + b"\x03\x03" + struct.pack("!H", len(fragment)) + fragment
    tcp = tcp_header(_SRC_PORT, _DST_PORT, flags=0x18)  # PSH|ACK
    ip = ipv4_header(protocol=6, total_length=20 + len(tcp) + len(tls_record), src=_SRC, dst=_DST)
    return eth(0x0800) + ip + tcp + tls_record


def test_heartbleed_match_is_cached_by_flow_key() -> None:
    daemon = _daemon()
    raw = _heartbleed_packet()
    metadata = parse_packet(raw, NOW)

    assert len(daemon._tls_evidence) == 0  # pyright: ignore[reportPrivateUsage]
    daemon._handle_tcp_payload(metadata, raw)  # pyright: ignore[reportPrivateUsage]

    assert len(daemon._tls_evidence) == 1  # pyright: ignore[reportPrivateUsage]


def test_ordinary_tls_traffic_caches_nothing() -> None:
    daemon = _daemon()
    tls_record = bytes([23]) + b"\x03\x03" + struct.pack("!H", 5) + b"hello"  # application_data
    tcp = tcp_header(_SRC_PORT, _DST_PORT, flags=0x18)
    ip = ipv4_header(protocol=6, total_length=20 + len(tcp) + len(tls_record), src=_SRC, dst=_DST)
    raw = eth(0x0800) + ip + tcp + tls_record
    metadata = parse_packet(raw, NOW)

    daemon._handle_tcp_payload(metadata, raw)  # pyright: ignore[reportPrivateUsage]

    assert len(daemon._tls_evidence) == 0  # pyright: ignore[reportPrivateUsage]


def test_pop_tls_evidence_matches_the_completing_flow_by_key() -> None:
    daemon = _daemon()
    raw = _heartbleed_packet()
    metadata = parse_packet(raw, NOW)
    daemon._handle_tcp_payload(metadata, raw)  # pyright: ignore[reportPrivateUsage]

    flow = make_flow(
        source_ip=_SRC,
        destination_ip=_DST,
        source_port=_SRC_PORT,
        destination_port=_DST_PORT,
        first_seen=NOW,
    )
    evidence = daemon._pop_tls_evidence(flow)  # pyright: ignore[reportPrivateUsage]

    assert evidence is not None
    assert evidence.signature == "heartbleed"
    assert evidence.flow_id == flow.flow_id
    assert evidence.confidence == 1.0

    # Consumed, not left behind — a second lookup for the same flow finds nothing.
    assert daemon._pop_tls_evidence(flow) is None  # pyright: ignore[reportPrivateUsage]


def test_pop_tls_evidence_none_for_a_flow_with_no_cached_match() -> None:
    daemon = _daemon()
    flow = make_flow(source_ip="203.0.113.101", destination_ip="192.168.1.31", first_seen=NOW)
    assert daemon._pop_tls_evidence(flow) is None  # pyright: ignore[reportPrivateUsage]


def test_heartbleed_evidence_reaches_a_real_threat_assessment_through_the_pipeline() -> None:
    """The full chain: cached match -> popped at completion -> assess_threat -> ThreatAssessment."""
    daemon = _daemon()
    raw = _heartbleed_packet()
    metadata = parse_packet(raw, NOW)
    daemon._handle_tcp_payload(metadata, raw)  # pyright: ignore[reportPrivateUsage]

    flow = make_flow(
        source_ip=_SRC,
        destination_ip=_DST,
        source_port=_SRC_PORT,
        destination_port=_DST_PORT,
        first_seen=NOW,
    )
    protocol_signature = daemon._pop_tls_evidence(flow)  # pyright: ignore[reportPrivateUsage]
    daemon._pipeline.process(flow, NOW, protocol_signature)  # pyright: ignore[reportPrivateUsage]

    assert len(daemon._state.threats) == 1  # pyright: ignore[reportPrivateUsage]
    assessment = daemon._state.threats[0]  # pyright: ignore[reportPrivateUsage]
    assert assessment.protocol_signature_evidence is not None
    assert assessment.protocol_signature_evidence.signature == "heartbleed"
    # protocol_signature_weight (75) * confidence (1.0) = 75 -> HIGH, and it
    # satisfies the B3 evidence-maturity gate's path (a) on its own.
    assert assessment.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)
    assert len(daemon._state.decisions) == 1  # pyright: ignore[reportPrivateUsage]
    decision = daemon._state.decisions[0]  # pyright: ignore[reportPrivateUsage]
    assert decision.action.value in ("rate_limit", "block")


# --- B5: JA3 fingerprint match ---


def _client_hello_packet() -> bytes:
    cipher_suites = (47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4)
    extensions = (
        struct.pack("!HH", 0, 0)
        + struct.pack("!HH", 10, 6)
        + struct.pack("!H", 6)
        + struct.pack("!3H", 23, 24, 25)
        + struct.pack("!HH", 11, 2)
        + bytes([1, 0])
    )
    body = (
        struct.pack("!H", 0x0301)
        + b"\x00" * 32
        + b"\x00"  # empty session_id
        + struct.pack("!H", len(cipher_suites) * 2)
        + struct.pack(f"!{len(cipher_suites)}H", *cipher_suites)
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    fragment = bytes([1]) + len(body).to_bytes(3, "big") + body
    tls_record = bytes([22]) + b"\x03\x01" + struct.pack("!H", len(fragment)) + fragment
    tcp = tcp_header(_SRC_PORT, _DST_PORT, flags=0x18)
    ip = ipv4_header(protocol=6, total_length=20 + len(tcp) + len(tls_record), src=_SRC, dst=_DST)
    return eth(0x0800) + ip + tcp + tls_record


def test_ja3_match_against_a_seeded_fingerprint_is_cached() -> None:
    """A ClientHello whose JA3 hash is in the (test-seeded) known-tool table gets cached."""
    daemon = _daemon()
    raw = _client_hello_packet()
    metadata = parse_packet(raw, NOW)
    fingerprint = compute_ja3(raw[54:])  # skip eth+ip+tcp to get at the TLS record for the hash
    assert fingerprint is not None
    daemon._known_tool_fingerprints[fingerprint.ja3_hash] = "test-attack-tool"  # pyright: ignore[reportPrivateUsage]

    assert len(daemon._tls_evidence) == 0  # pyright: ignore[reportPrivateUsage]
    daemon._handle_tcp_payload(metadata, raw)  # pyright: ignore[reportPrivateUsage]

    assert len(daemon._tls_evidence) == 1  # pyright: ignore[reportPrivateUsage]


def test_ja3_evidence_reaches_a_real_threat_assessment_through_the_pipeline() -> None:
    daemon = _daemon()
    raw = _client_hello_packet()
    metadata = parse_packet(raw, NOW)
    fingerprint = compute_ja3(raw[54:])
    assert fingerprint is not None
    daemon._known_tool_fingerprints[fingerprint.ja3_hash] = "test-attack-tool"  # pyright: ignore[reportPrivateUsage]
    daemon._handle_tcp_payload(metadata, raw)  # pyright: ignore[reportPrivateUsage]

    flow = make_flow(
        source_ip=_SRC,
        destination_ip=_DST,
        source_port=_SRC_PORT,
        destination_port=_DST_PORT,
        first_seen=NOW,
    )
    protocol_signature = daemon._pop_tls_evidence(flow)  # pyright: ignore[reportPrivateUsage]
    assert protocol_signature is not None
    assert protocol_signature.signature == f"ja3:{fingerprint.ja3_hash}"
    assert protocol_signature.confidence == 0.6  # honestly weaker than Heartbleed's 1.0

    daemon._pipeline.process(flow, NOW, protocol_signature)  # pyright: ignore[reportPrivateUsage]

    assert len(daemon._state.threats) == 1  # pyright: ignore[reportPrivateUsage]
    assessment = daemon._state.threats[0]  # pyright: ignore[reportPrivateUsage]
    assert assessment.protocol_signature_evidence is not None
    assert "test-attack-tool" in assessment.explanation


def test_ja3_no_match_against_an_unseeded_fingerprint_caches_nothing() -> None:
    """Without seeding, an ordinary ClientHello must not produce any cached evidence."""
    daemon = _daemon()
    raw = _client_hello_packet()
    metadata = parse_packet(raw, NOW)

    daemon._handle_tcp_payload(metadata, raw)  # pyright: ignore[reportPrivateUsage]

    assert len(daemon._tls_evidence) == 0  # pyright: ignore[reportPrivateUsage]
