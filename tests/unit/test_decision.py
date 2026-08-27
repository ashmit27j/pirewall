"""`pirewall.engine.decision.decide`: ThreatAssessment -> FirewallDecision (spec §19)."""

from datetime import UTC, datetime

from pirewall.core.enums import FirewallAction, ThreatLevel
from pirewall.core.models.threat import ThreatAssessment
from pirewall.engine.decision import decide

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _assessment(level: ThreatLevel, score: float) -> ThreatAssessment:
    return ThreatAssessment.model_validate(
        {
            "id": "assessment-1",
            "flow_id": "flow-1",
            "source_ip": "203.0.113.5",
            "destination_ip": "192.168.1.10",
            "threat_score": score,
            "threat_level": level,
            "confidence": 0.9,
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


def test_high_maps_to_rate_limit() -> None:
    decision = decide(_assessment(ThreatLevel.HIGH, 80.0), NOW)
    assert decision.action is FirewallAction.RATE_LIMIT


def test_critical_maps_to_block() -> None:
    decision = decide(_assessment(ThreatLevel.CRITICAL, 95.0), NOW)
    assert decision.action is FirewallAction.BLOCK


def test_decision_carries_assessment_fields_through() -> None:
    assessment = _assessment(ThreatLevel.CRITICAL, 95.0)
    decision = decide(assessment, NOW)

    assert decision.threat_assessment_id == assessment.id
    assert decision.flow_id == assessment.flow_id
    assert decision.threat_score == assessment.threat_score
    assert decision.threat_level == assessment.threat_level
    assert decision.reason == assessment.explanation
    assert decision.evidence == assessment.contributing_evidence
    assert decision.decided_at == NOW
