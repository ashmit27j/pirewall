"""`pirewall.engine.decision.decide`: ThreatAssessment -> FirewallDecision (spec §19).

ADDENDUM_2.md B3's evidence-maturity gate means a `HIGH`/`CRITICAL`
assessment only actually reaches `RATE_LIMIT`/`BLOCK` if it also carries
"mature" evidence (a completed-flow classification, a behavioral pattern,
or a consistent multi-window reading) — so most of the scenarios below
deliberately construct a *realistic* high/critical assessment (one that
also carries `known_evidence` or a behavioral pattern), the same way real
detection actually produces one, rather than a bare threat_level with no
evidence behind it. The bare-level, no-evidence cases are exactly what
`test_high_without_mature_evidence_downgrades_to_monitor`/
`test_critical_without_mature_evidence_downgrades_to_monitor` test for.
"""

from datetime import UTC, datetime
from ipaddress import IPv4Address

from pirewall.core.enums import BehaviorPatternType, FirewallAction, ThreatLevel
from pirewall.core.models.behavior import BehaviorAssessment
from pirewall.core.models.evidence import KnownEvidence
from pirewall.core.models.threat import ThreatAssessment
from pirewall.engine.decision import EvidenceMaturityTracker, decide

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _known_evidence() -> KnownEvidence:
    return KnownEvidence(
        flow_id="flow-1",
        predicted_class="DDoS",
        confidence=0.95,
        model_version="1.0.0",
        feature_schema_version="1.0.0",
        generated_at=NOW,
    )


def _behavior_assessment() -> BehaviorAssessment:
    return BehaviorAssessment(
        source_ip=IPv4Address("203.0.113.5"),
        detected_patterns=(BehaviorPatternType.SCANNING,),
        confidence=0.8,
        description="test",
        window_start=NOW,
        window_end=NOW,
    )


def _assessment(
    level: ThreatLevel,
    score: float,
    *,
    known_evidence: KnownEvidence | None = None,
    behavior_assessment: BehaviorAssessment | None = None,
) -> ThreatAssessment:
    return ThreatAssessment.model_validate(
        {
            "id": "assessment-1",
            "flow_id": "flow-1",
            "source_ip": "203.0.113.5",
            "destination_ip": "192.168.1.10",
            "threat_score": score,
            "threat_level": level,
            "confidence": 0.9,
            "known_evidence": known_evidence,
            "behavior_assessment": behavior_assessment,
            "explanation": "test",
            "contributing_evidence": ("evidence-1",),
            "assessed_at": NOW,
        }
    )


def test_low_maps_to_allow() -> None:
    decision = decide(_assessment(ThreatLevel.LOW, 5.0), NOW)
    assert decision.action is FirewallAction.ALLOW


def test_medium_maps_to_monitor() -> None:
    decision = decide(_assessment(ThreatLevel.MEDIUM, 55.0), NOW)
    assert decision.action is FirewallAction.MONITOR


def test_high_maps_to_rate_limit_with_mature_evidence() -> None:
    assessment = _assessment(ThreatLevel.HIGH, 80.0, known_evidence=_known_evidence())
    decision = decide(assessment, NOW)
    assert decision.action is FirewallAction.RATE_LIMIT


def test_critical_maps_to_block_with_mature_evidence() -> None:
    assessment = _assessment(ThreatLevel.CRITICAL, 95.0, known_evidence=_known_evidence())
    decision = decide(assessment, NOW)
    assert decision.action is FirewallAction.BLOCK


def test_behavior_pattern_alone_is_sufficient_for_block() -> None:
    """Path (b) of the gate: a multi-observation behavioral pattern needs no known_evidence."""
    assessment = _assessment(ThreatLevel.CRITICAL, 95.0, behavior_assessment=_behavior_assessment())
    decision = decide(assessment, NOW)
    assert decision.action is FirewallAction.BLOCK


def test_high_without_mature_evidence_downgrades_to_monitor() -> None:
    """ADDENDUM_2.md B3: a bare threat_level with no completed-flow or behavioral evidence caps at MONITOR."""
    decision = decide(_assessment(ThreatLevel.HIGH, 80.0), NOW)
    assert decision.action is FirewallAction.MONITOR


def test_critical_without_mature_evidence_downgrades_to_monitor() -> None:
    """Regardless of the raw confidence/score value — this is the invariant's whole point."""
    decision = decide(_assessment(ThreatLevel.CRITICAL, 99.9), NOW)
    assert decision.action is FirewallAction.MONITOR


def test_consistency_tracker_grants_maturity_after_enough_windows() -> None:
    """Path (c): the same source's weak-but-elevated reading, consistent across enough windows."""
    tracker = EvidenceMaturityTracker(consistency_windows=3, max_tracked_sources=100)
    assessment = _assessment(ThreatLevel.CRITICAL, 95.0)

    first = decide(assessment, NOW, tracker)
    second = decide(assessment, NOW, tracker)
    third = decide(assessment, NOW, tracker)

    assert first.action is FirewallAction.MONITOR
    assert second.action is FirewallAction.MONITOR
    assert third.action is FirewallAction.BLOCK


def test_consistency_tracker_is_per_source() -> None:
    tracker = EvidenceMaturityTracker(consistency_windows=2, max_tracked_sources=100)
    attacker = _assessment(ThreatLevel.CRITICAL, 95.0)
    other = ThreatAssessment.model_validate(
        {**attacker.model_dump(mode="json"), "source_ip": "203.0.113.6"}
    )

    decide(attacker, NOW, tracker)
    decision = decide(other, NOW, tracker)

    assert decision.action is FirewallAction.MONITOR


def test_decision_carries_assessment_fields_through() -> None:
    assessment = _assessment(ThreatLevel.CRITICAL, 95.0, known_evidence=_known_evidence())
    decision = decide(assessment, NOW)

    assert decision.threat_assessment_id == assessment.id
    assert decision.flow_id == assessment.flow_id
    assert decision.threat_score == assessment.threat_score
    assert decision.threat_level == assessment.threat_level
    assert decision.reason == assessment.explanation
    assert decision.evidence == assessment.contributing_evidence
    assert decision.decided_at == NOW
