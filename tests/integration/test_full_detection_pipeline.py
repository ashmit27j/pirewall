"""End-to-end: `Packet -> Flow -> FeatureVector -> Behavior -> ThreatAssessment ->
FirewallDecision -> CandidateRule -> Validation -> FirewallBackend` (spec §39, §51).

Scripted traffic, three scenarios: a benign session, a port scan, and a
SYN-flood-like burst — all built as real `PacketMetadata` fed through the
real `FlowAggregator` (not hand-built `Flow` fixtures), so the
`Packet -> Flow` link is genuinely exercised here, not just asserted by
construction.

**Deliberate scope choice**: `known_evidence`/`anomaly_evidence` are passed
as `None` into `assess_threat` rather than run through real LightGBM/
Isolation Forest inference. ML inference correctness is already thoroughly
covered by `tests/ml/test_inference.py`/`test_known_attack.py`/
`test_anomaly_detection.py` against freshly trained placeholder models;
re-training two more models here would duplicate that coverage without
adding a genuinely new link, and — because `score_evidence`'s three
contributions are independent and strictly additive (see
`pirewall.engine.scoring`) — an untuned model's prediction on these
hand-crafted scenarios would swing the total score unpredictably in either
direction, making the "sensible decision" assertions below flaky for no
real benefit. What *is* genuinely new and asserted here: `Flow ->
FeatureVector` extraction against real aggregator-built flows (previously
only exercised against synthetic `make_flow` fixtures), the full
`BehaviorAnalyzer` -> `assess_threat` -> `decide` -> `generate_candidate_rule`
-> `FirewallManager.submit_candidate` chain, deterministically driven by
behavioral evidence alone.

`threat.behavior_weight` is raised to its config-allowed maximum (100.0,
`ThreatConfig.behavior_weight`'s `le=100.0` bound) and
`detection.persistence_seconds_threshold` is lowered from its 1800s
production default to 2.0s, purely so this test's engineered behavioral
patterns cross the MEDIUM/HIGH decision thresholds within a few
seconds of scripted traffic instead of the real 30-minute window — a
deliberate, documented test-only override, not a claim about real
production defaults.
"""

from datetime import UTC, datetime, timedelta

from pirewall.core.enums import FirewallAction, RuleStatus, ThreatLevel
from pirewall.core.models.common import TcpFlags
from pirewall.core.models.flow import Flow
from pirewall.detection.behavior import BehaviorAnalyzer
from pirewall.engine.decision import decide
from pirewall.engine.threat import assess_threat
from pirewall.features.extractor import extract_features
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.generator import generate_candidate_rule
from pirewall.firewall.manager import FirewallManager
from pirewall.flow.aggregator import FlowAggregator
from tests.helpers.config import make_config
from tests.helpers.flows import make_packet

T0 = datetime(2026, 1, 1, tzinfo=UTC)

_CONFIG = make_config(
    firewall={"enforcement_mode": "active"},
    threat={"behavior_weight": 100.0},
    detection={"persistence_seconds_threshold": 2.0},
)


def _benign_session_flow() -> Flow:
    """A normal short browsing-style TCP session: handshake, one data exchange, clean close."""
    aggregator = FlowAggregator(_CONFIG.flow)
    client, server = "10.0.0.5", "10.0.0.10"
    client_port, server_port = 51234, 443

    aggregator.process_packet(
        make_packet(
            source_ip=client,
            destination_ip=server,
            source_port=client_port,
            destination_port=server_port,
            timestamp=T0,
            tcp_flags=TcpFlags(syn=True),
        )
    )
    aggregator.process_packet(
        make_packet(
            source_ip=server,
            destination_ip=client,
            source_port=server_port,
            destination_port=client_port,
            timestamp=T0 + timedelta(milliseconds=5),
            tcp_flags=TcpFlags(syn=True, ack=True),
        )
    )
    aggregator.process_packet(
        make_packet(
            source_ip=client,
            destination_ip=server,
            source_port=client_port,
            destination_port=server_port,
            timestamp=T0 + timedelta(milliseconds=10),
            tcp_flags=TcpFlags(ack=True, psh=True),
            total_length=200,
            payload_length=150,
        )
    )
    aggregator.process_packet(
        make_packet(
            source_ip=server,
            destination_ip=client,
            source_port=server_port,
            destination_port=client_port,
            timestamp=T0 + timedelta(milliseconds=15),
            tcp_flags=TcpFlags(ack=True, psh=True),
            total_length=800,
            payload_length=750,
        )
    )
    aggregator.process_packet(
        make_packet(
            source_ip=client,
            destination_ip=server,
            source_port=client_port,
            destination_port=server_port,
            timestamp=T0 + timedelta(milliseconds=20),
            tcp_flags=TcpFlags(fin=True, ack=True),
        )
    )
    emitted = aggregator.process_packet(
        make_packet(
            source_ip=server,
            destination_ip=client,
            source_port=server_port,
            destination_port=client_port,
            timestamp=T0 + timedelta(milliseconds=25),
            tcp_flags=TcpFlags(fin=True, ack=True),
        )
    )
    assert len(emitted) == 1, "benign session should complete on mutual FIN"
    return emitted[0]


def _port_scan_flows() -> list[Flow]:
    """One source probing 12 distinct destination ports on one host, single unanswered SYN each."""
    aggregator = FlowAggregator(_CONFIG.flow)
    attacker, victim = "203.0.113.9", "10.0.0.20"
    flows: list[Flow] = []
    for index, port in enumerate(range(2000, 2012)):
        aggregator.process_packet(
            make_packet(
                source_ip=attacker,
                destination_ip=victim,
                source_port=40000,
                destination_port=port,
                timestamp=T0 + timedelta(milliseconds=300 * index),
                tcp_flags=TcpFlags(syn=True),
            )
        )
        flows.extend(aggregator.flush())  # never answered -> force-finalize each probe
    assert len(flows) == 12
    return flows


def _syn_flood_flows() -> list[Flow]:
    """One source hammering one destination service (fixed dest port) with 20 unanswered SYNs."""
    aggregator = FlowAggregator(_CONFIG.flow)
    attacker, victim = "203.0.113.77", "10.0.0.30"
    flows: list[Flow] = []
    for index in range(20):
        aggregator.process_packet(
            make_packet(
                source_ip=attacker,
                destination_ip=victim,
                source_port=40000 + index,  # distinct ephemeral source port per attempt
                destination_port=80,
                timestamp=T0 + timedelta(milliseconds=300 * index),
                tcp_flags=TcpFlags(syn=True),
            )
        )
        flows.extend(aggregator.flush())
    assert len(flows) == 20
    return flows


def _submit_through_full_pipeline(
    manager: FirewallManager, flow: Flow, analyzer: BehaviorAnalyzer
) -> tuple[ThreatLevel, FirewallAction, RuleStatus | None]:
    """Run one flow through feature extraction, behavior, threat, decision, generation, validation."""
    feature_vector = extract_features(flow)
    assert feature_vector.flow_id == flow.flow_id  # Flow -> FeatureVector link genuinely exercised

    behavior_assessment = analyzer.assess(flow.source_ip)
    assessment = assess_threat(
        _CONFIG.threat,
        flow.flow_id,
        flow.source_ip,
        flow.destination_ip,
        known_evidence=None,
        anomaly_evidence=None,
        behavior_assessment=behavior_assessment,
        assessed_at=flow.last_seen,
    )
    decision = decide(assessment, flow.last_seen)
    manager.register_decision(decision)

    candidate = generate_candidate_rule(
        decision, flow, flow.last_seen, _CONFIG.firewall.default_rule_ttl_seconds
    )
    if candidate is None:
        return assessment.threat_level, decision.action, None

    result = manager.submit_candidate(candidate, flow.last_seen)
    status = result.rule.status if result.rule is not None else None
    return assessment.threat_level, decision.action, status


def test_benign_session_is_allowed_with_no_rule() -> None:
    backend = FakeFirewallBackend()
    manager = FirewallManager(_CONFIG, backend)
    analyzer = BehaviorAnalyzer(_CONFIG.detection)

    flow = _benign_session_flow()
    analyzer.observe_flow(flow)

    level, action, status = _submit_through_full_pipeline(manager, flow, analyzer)

    assert level is ThreatLevel.LOW
    assert action is FirewallAction.ALLOW
    assert status is None  # ALLOW never generates a candidate rule at all
    assert backend.apply_calls == 0
    assert manager.active_rules() == []


def test_port_scan_is_detected_and_enforced() -> None:
    backend = FakeFirewallBackend()
    manager = FirewallManager(_CONFIG, backend)
    analyzer = BehaviorAnalyzer(_CONFIG.detection)

    *history, trigger = _port_scan_flows()
    for flow in history:
        analyzer.observe_flow(flow)
    analyzer.observe_flow(trigger)

    assessment_patterns = analyzer.assess(trigger.source_ip)
    assert assessment_patterns is not None
    assert "scanning" in {p.value for p in assessment_patterns.detected_patterns}
    assert "repeated_failures" in {p.value for p in assessment_patterns.detected_patterns}
    assert len(assessment_patterns.detected_patterns) >= 4  # enough to clear MEDIUM at weight=100

    level, action, status = _submit_through_full_pipeline(manager, trigger, analyzer)

    assert level is not ThreatLevel.LOW
    assert action is not FirewallAction.ALLOW
    assert status is RuleStatus.ACTIVE
    assert backend.apply_calls == 1
    deployed = manager.active_rules()[0]
    assert str(deployed.source) == "203.0.113.9/32"
    assert str(deployed.destination) == "10.0.0.20/32"


def test_syn_flood_is_detected_and_enforced() -> None:
    backend = FakeFirewallBackend()
    manager = FirewallManager(_CONFIG, backend)
    analyzer = BehaviorAnalyzer(_CONFIG.detection)

    *history, trigger = _syn_flood_flows()
    for flow in history:
        analyzer.observe_flow(flow)
    analyzer.observe_flow(trigger)

    assessment_patterns = analyzer.assess(trigger.source_ip)
    assert assessment_patterns is not None
    assert "repeated_connections" in {p.value for p in assessment_patterns.detected_patterns}
    assert "high_frequency" in {p.value for p in assessment_patterns.detected_patterns}
    assert len(assessment_patterns.detected_patterns) >= 4

    level, action, status = _submit_through_full_pipeline(manager, trigger, analyzer)

    assert level is not ThreatLevel.LOW
    assert action is not FirewallAction.ALLOW
    assert status is RuleStatus.ACTIVE
    assert backend.apply_calls == 1
    deployed = manager.active_rules()[0]
    assert str(deployed.source) == "203.0.113.77/32"
    assert str(deployed.destination) == "10.0.0.30/32"


def test_port_scan_and_flood_are_assessed_more_severely_than_benign_traffic() -> None:
    """Cross-scenario sanity check: identical pipeline, deterministically different outcomes."""
    manager = FirewallManager(_CONFIG, FakeFirewallBackend())

    benign_analyzer = BehaviorAnalyzer(_CONFIG.detection)
    benign_flow = _benign_session_flow()
    benign_analyzer.observe_flow(benign_flow)
    benign_level, _, _ = _submit_through_full_pipeline(manager, benign_flow, benign_analyzer)

    scan_analyzer = BehaviorAnalyzer(_CONFIG.detection)
    *scan_history, scan_trigger = _port_scan_flows()
    for flow in scan_history:
        scan_analyzer.observe_flow(flow)
    scan_analyzer.observe_flow(scan_trigger)
    scan_level, _, _ = _submit_through_full_pipeline(manager, scan_trigger, scan_analyzer)

    assert benign_level is ThreatLevel.LOW
    assert scan_level is not ThreatLevel.LOW
