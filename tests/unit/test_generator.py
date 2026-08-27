"""`generate_candidate_rule`: FirewallDecision -> CandidateRule (spec §22, §23)."""

from datetime import UTC, datetime, timedelta

from pirewall.core.enums import FirewallAction, Protocol, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.firewall.generator import generate_candidate_rule
from tests.helpers.flows import make_flow

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _decision(action: FirewallAction, **overrides: object) -> FirewallDecision:
    defaults: dict[str, object] = {
        "id": "decision-1",
        "threat_assessment_id": "assessment-1",
        "flow_id": "flow-1",
        "action": action,
        "threat_score": 90.0,
        "threat_level": ThreatLevel.CRITICAL,
        "reason": "test",
        "evidence": ("evidence-1",),
        "decided_at": NOW,
    }
    defaults.update(overrides)
    return FirewallDecision.model_validate(defaults)


def test_allow_produces_no_candidate() -> None:
    flow = make_flow()
    candidate = generate_candidate_rule(_decision(FirewallAction.ALLOW), flow, NOW, 3600)
    assert candidate is None


def test_block_produces_narrow_candidate() -> None:
    flow = make_flow(
        source_ip="203.0.113.5", destination_ip="192.168.1.10", destination_port=22, protocol=Protocol.TCP
    )
    candidate = generate_candidate_rule(_decision(FirewallAction.BLOCK), flow, NOW, 3600)

    assert candidate is not None
    assert candidate.action is FirewallAction.BLOCK
    assert str(candidate.source) == "203.0.113.5/32"
    assert str(candidate.destination) == "192.168.1.10/32"
    assert candidate.protocol is Protocol.TCP
    assert candidate.destination_port == 22
    assert candidate.source_port is None  # ephemeral, never narrowed
    assert candidate.decision_id == "decision-1"
    assert candidate.expires_at is not None


def test_expires_at_uses_default_ttl() -> None:
    flow = make_flow()
    candidate = generate_candidate_rule(_decision(FirewallAction.BLOCK), flow, NOW, 1800)
    assert candidate is not None
    assert candidate.expires_at == NOW + timedelta(seconds=1800)


def test_monitor_and_rate_limit_also_produce_candidates() -> None:
    flow = make_flow()
    for action in (FirewallAction.MONITOR, FirewallAction.RATE_LIMIT):
        candidate = generate_candidate_rule(_decision(action), flow, NOW, 3600)
        assert candidate is not None
        assert candidate.action is action
