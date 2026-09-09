"""Regressions from the first real client session on the Pi (2026-09-10).

A phone browsing a shopping site was BLOCKed as "malicious activity" within
minutes. The live evidence, pulled from the running daemon, named four
independent faults — each one alone enough to produce the outcome, and none
of them caught by any existing test because every one is a property of how
evidence is *interpreted*, not of whether the code runs.

Recorded here as concrete scenarios rather than tuning notes, so the same
misreadings cannot come back quietly.
"""

import os
import struct
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network

import pytest

from pirewall.core.enums import BehaviorPatternType, FirewallAction, RuleStatus, ThreatLevel
from pirewall.core.models.evidence import AnomalyEvidence, KnownEvidence
from pirewall.core.models.rule import FirewallRule
from pirewall.core.models.threat import ThreatAssessment
from pirewall.detection.tls_heartbeat import check_heartbleed
from pirewall.engine.decision import decide
from pirewall.firewall.manager import blocking_rules_targeting, rules_targeting
from tests.helpers.rules import make_firewall_rule

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
PROTECTED = IPv4Network("192.168.100.0/24")
CLIENT = IPv4Address("192.168.100.78")


# --------------------------------------------------------------- Heartbleed
#
# The detector was handed raw TCP payload from anywhere in a stream. A
# mid-stream segment of an established TLS connection is ciphertext and does
# not begin at a record boundary, so checking only `payload[0] == 24` fired
# on ~1 segment in 262 by chance — and ciphertext then supplied a large
# random "claimed payload length" that passed the mismatch test too. At
# weight 75 that single signature reached CRITICAL on its own.


def test_ciphertext_does_not_look_like_heartbleed() -> None:
    """The fault, reproduced at the rate that caused it: ~761 hits per 200k before."""
    hits = sum(1 for _ in range(50_000) if check_heartbleed(os.urandom(1400)) is not None)
    assert hits == 0, f"{hits} false Heartbleed matches on random ciphertext"


def test_a_real_heartbleed_request_is_still_detected() -> None:
    """The hardening must not cost the detection it exists for."""
    fragment = bytes([1]) + struct.pack("!H", 0xFFFF) + b"\x00" * 16
    record = bytes([24]) + struct.pack("!H", 0x0303) + struct.pack("!H", len(fragment)) + fragment
    match = check_heartbleed(record)
    assert match is not None
    assert match.claimed_payload_length == 0xFFFF
    assert match.available_bytes == 16


@pytest.mark.parametrize(
    "version,label",
    [(0x0000, "null"), (0x1234, "arbitrary"), (0xFFFF, "all-ones"), (0x0305, "future")],
)
def test_an_implausible_tls_version_is_rejected(version: int, label: str) -> None:
    """The single cheapest filter: ~5 legal values out of 65536."""
    fragment = bytes([1]) + struct.pack("!H", 0xFFFF) + b"\x00" * 16
    record = bytes([24]) + struct.pack("!H", version) + struct.pack("!H", len(fragment)) + fragment
    assert check_heartbleed(record) is None, f"{label} version accepted"


@pytest.mark.parametrize("message_type", [0, 3, 24, 255])
def test_an_illegal_heartbeat_message_type_is_rejected(message_type: int) -> None:
    """RFC 6520 defines exactly two: 1 (request) and 2 (response)."""
    fragment = bytes([message_type]) + struct.pack("!H", 0xFFFF) + b"\x00" * 16
    record = bytes([24]) + struct.pack("!H", 0x0303) + struct.pack("!H", len(fragment)) + fragment
    assert check_heartbleed(record) is None


def test_a_record_longer_than_tls_permits_is_rejected() -> None:
    """A TLS record cannot exceed 2^14 + expansion; a larger one is not a TLS record."""
    record = bytes([24]) + struct.pack("!H", 0x0303) + struct.pack("!H", 0xFFFF) + b"\x01\xff\xff"
    assert check_heartbleed(record) is None


# ---------------------------------------------------- evidence-maturity gate
#
# B3 exists so no single weak observation can produce BLOCK/RATE_LIMIT. It
# accepted `known_evidence is not None` as "mature", which is true of a
# confident BENIGN verdict — so the gate passed for every flow the model had
# scored, which is every flow. It never gated anything.


def _assessment(
    level: ThreatLevel,
    score: float,
    known: KnownEvidence | None = None,
    anomaly: AnomalyEvidence | None = None,
) -> ThreatAssessment:
    return ThreatAssessment(
        id="assessment-1",
        flow_id="flow-1",
        source_ip=CLIENT,
        destination_ip=IPv4Address("104.26.12.204"),
        threat_score=score,
        threat_level=level,
        confidence=1.0,
        known_evidence=known,
        anomaly_evidence=anomaly,
        explanation="test",
        assessed_at=NOW,
    )


def _known(predicted_class: str, confidence: float = 0.9999) -> KnownEvidence:
    return KnownEvidence(
        flow_id="flow-1",
        predicted_class=predicted_class,
        confidence=confidence,
        class_probabilities={predicted_class: confidence},
        model_version="0.4.0",
        feature_schema_version="1.0.0",
        generated_at=NOW,
    )


def test_a_benign_classification_is_not_mature_evidence_of_a_threat() -> None:
    """The fault: a 99.99%-confident BENIGN verdict satisfied the gate.

    `pirewall.engine.scoring` already contributes 0 for BENIGN via
    `is_attack_label`. The gate disagreeing with it meant the two layers held
    different beliefs about the same evidence.
    """
    decision = decide(_assessment(ThreatLevel.CRITICAL, 100.0, known=_known("BENIGN")), NOW)
    assert decision.action is FirewallAction.MONITOR


def test_an_attack_classification_is_mature_evidence() -> None:
    """The gate must still let genuine detections through."""
    decision = decide(_assessment(ThreatLevel.CRITICAL, 100.0, known=_known("DDoS")), NOW)
    assert decision.action is FirewallAction.BLOCK


def test_a_low_confidence_attack_classification_is_not_mature() -> None:
    """Below the known-attack confidence threshold it is a guess, not evidence."""
    decision = decide(
        _assessment(ThreatLevel.CRITICAL, 100.0, known=_known("DDoS", confidence=0.4)), NOW
    )
    assert decision.action is FirewallAction.MONITOR


def test_anomaly_evidence_alone_never_reaches_an_enforcing_action() -> None:
    """Path (c) with no tracker: the conservative default, not the permissive one."""
    anomaly = AnomalyEvidence(
        flow_id="flow-1",
        anomaly_score=-0.9,
        threshold=0.0,
        is_anomaly=True,
        model_version="0.2.0",
        feature_schema_version="1.0.0",
        generated_at=NOW,
    )
    decision = decide(_assessment(ThreatLevel.CRITICAL, 100.0, anomaly=anomaly), NOW)
    assert decision.action is FirewallAction.MONITOR


# ------------------------------------------------------ throttled != blocked
#
# The portal revoked a session and showed "malicious activity detected" for
# any restrictive rule, RATE_LIMIT included. A throttle on one flow threw the
# user off the network entirely.


def _rule(action: FirewallAction) -> FirewallRule:
    return make_firewall_rule(
        id=f"rule-{action.value}",
        status=RuleStatus.ACTIVE,
        action=action,
        source=f"{CLIENT}/32",
        destination="203.0.113.9/32",
        created_at=NOW,
    )


def test_a_rate_limit_does_not_count_as_blocking_the_client() -> None:
    rules = [_rule(FirewallAction.RATE_LIMIT)]
    assert rules_targeting(rules, CLIENT, PROTECTED), "still visible to the control panel"
    assert blocking_rules_targeting(rules, CLIENT, PROTECTED) == [], (
        "a throttle must not read as a disconnection"
    )


def test_a_block_does_count_as_blocking_the_client() -> None:
    rules = [_rule(FirewallAction.BLOCK)]
    assert len(blocking_rules_targeting(rules, CLIENT, PROTECTED)) == 1


def test_a_block_alongside_a_rate_limit_still_blocks() -> None:
    rules = [_rule(FirewallAction.RATE_LIMIT), _rule(FirewallAction.BLOCK)]
    found = blocking_rules_targeting(rules, CLIENT, PROTECTED)
    assert [r.action for r in found] == [FirewallAction.BLOCK]


# ---------------------------------------------------------- behavior signals
#
# Every behavioural pattern fired at once on a phone loading one page: 91
# distinct destinations, 71 "scanned ports" (mostly ephemeral ports belonging
# to reply-direction flows), and 189 of 500 flows counted as "failures"
# because they simply ended with no packet back.


def test_ordinary_browsing_is_not_a_port_scan() -> None:
    """Many hosts on one port is a browser; many ports on one host is a scan."""
    from pirewall.detection.behavior import BehaviorAnalyzer
    from tests.helpers.config import make_config

    config = make_config().detection.model_copy(update={"scanning_port_threshold": 10})
    analyzer = BehaviorAnalyzer(config)
    for octet in range(60):  # 60 different CDN hosts, all on 443
        analyzer.observe_new_connection(CLIENT, IPv4Address(f"203.0.113.{octet + 1}"), 443, NOW)
    assessment = analyzer.assess(CLIENT)
    assert assessment is not None
    assert BehaviorPatternType.SCANNING not in assessment.detected_patterns


def test_a_real_port_scan_is_still_detected() -> None:
    """Many ports on one host is exactly what the pattern is for."""
    from pirewall.detection.behavior import BehaviorAnalyzer
    from tests.helpers.config import make_config

    config = make_config().detection.model_copy(update={"scanning_port_threshold": 10})
    analyzer = BehaviorAnalyzer(config)
    for port in range(20, 60):  # 40 ports on a single host
        analyzer.observe_new_connection(CLIENT, IPv4Address("203.0.113.9"), port, NOW)
    assessment = analyzer.assess(CLIENT)
    assert assessment is not None
    assert BehaviorPatternType.SCANNING in assessment.detected_patterns


def test_a_flow_that_merely_ended_without_a_reply_is_not_a_failure() -> None:
    """UDP, ICMP and one-packet flow fragments are bookkeeping, not refused connections."""
    from pirewall.core.enums import Protocol
    from pirewall.detection.behavior import is_failed_connection_attempt
    from tests.helpers.flows import make_flow

    for protocol in (Protocol.UDP, Protocol.ICMP):
        flow = make_flow(
            protocol=protocol, backward_packet_count=0, forward_packet_count=1, packet_count=1
        )
        assert not is_failed_connection_attempt(flow), f"{protocol.value} counted as a failure"

    # TCP, no reply, but no SYN either — a fragment of a flow, not an attempt.
    flow = make_flow(
        protocol=Protocol.TCP, backward_packet_count=0, forward_packet_count=1, packet_count=1
    )
    assert not is_failed_connection_attempt(flow)


def test_an_unanswered_tcp_connection_attempt_is_a_failure() -> None:
    """A SYN with nothing back is the shape a scan and a SYN flood produce."""
    from pirewall.core.enums import Protocol
    from pirewall.detection.behavior import is_failed_connection_attempt
    from tests.helpers.flows import make_flow

    flow = make_flow(
        protocol=Protocol.TCP,
        backward_packet_count=0,
        forward_packet_count=2,
        packet_count=2,
        tcp_flags={"syn": 1},
    )
    assert is_failed_connection_attempt(flow)


def test_an_answered_connection_is_never_a_failure() -> None:
    from pirewall.core.enums import Protocol
    from pirewall.detection.behavior import is_failed_connection_attempt
    from tests.helpers.flows import make_flow

    flow = make_flow(
        protocol=Protocol.TCP,
        forward_packet_count=6,
        backward_packet_count=4,
        packet_count=10,
        tcp_flags={"syn": 1},
    )
    assert not is_failed_connection_attempt(flow)


# ------------------------------------------------ unanalysed != malformed
#
# ARP, EAPOL and VLAN frames are valid traffic pirewall simply does not
# analyse, and on a Wi-Fi AP they arrive constantly. Reporting each as a
# CAPTURE_ERROR filled the bounded event history with noise and evicted real
# detections within minutes of a client associating.


def test_an_arp_frame_is_not_reported_as_a_capture_error() -> None:
    from pirewall.capture.fake import FakePacketCapture
    from pirewall.capture.pipeline import capture_packets
    from pirewall.core.models.event import SecurityEvent

    # A minimal, well-formed ARP frame: dst/src MAC then ethertype 0x0806.
    arp = b"\xff" * 6 + b"\x11" * 6 + b"\x08\x06" + b"\x00" * 28
    capture = FakePacketCapture("wlan0", [arp])
    capture.start()

    events: list[SecurityEvent] = []
    list(capture_packets(capture, on_event=events.append))

    assert events == [], f"ARP produced {len(events)} security event(s)"


def test_a_genuinely_malformed_packet_is_still_reported() -> None:
    """The quieting must not hide real capture problems."""
    from pirewall.capture.fake import FakePacketCapture
    from pirewall.capture.pipeline import capture_packets
    from pirewall.core.models.event import SecurityEvent

    # IPv4 ethertype, but truncated well inside the IP header.
    truncated = b"\xff" * 6 + b"\x11" * 6 + b"\x08\x00" + b"\x45\x00\x00"
    capture = FakePacketCapture("wlan0", [truncated])
    capture.start()

    events: list[SecurityEvent] = []
    list(capture_packets(capture, on_event=events.append))

    assert len(events) == 1
    assert events[0].event_type.value == "capture_error"
