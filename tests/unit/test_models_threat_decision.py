"""`ThreatAssessment` and `FirewallDecision` domain models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from pirewall.core.enums import FirewallAction, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.threat import ThreatAssessment

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _make_threat_assessment(**overrides: object) -> ThreatAssessment:
    defaults: dict[str, object] = {
        "id": "assessment-1",
        "flow_id": "flow-1",
        "source_ip": "10.0.0.5",
        "destination_ip": "93.184.216.34",
        "threat_score": 82.5,
        "threat_level": ThreatLevel.HIGH,
        "confidence": 0.9,
        "explanation": "repeated SYN attempts across many ports",
        "contributing_evidence": ("known_evidence:port_scan",),
        "assessed_at": NOW,
    }
    defaults.update(overrides)
    return ThreatAssessment.model_validate(defaults)


def test_valid_threat_assessment_constructs() -> None:
    assessment = _make_threat_assessment()
    assert assessment.threat_level is ThreatLevel.HIGH


def test_threat_score_out_of_range_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_threat_assessment(threat_score=150.0)


def test_threat_assessment_ipv6_destination_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_threat_assessment(destination_ip="2001:db8::1")


def test_valid_firewall_decision_constructs() -> None:
    decision = FirewallDecision(
        id="decision-1",
        threat_assessment_id="assessment-1",
        flow_id="flow-1",
        action=FirewallAction.BLOCK,
        threat_score=82.5,
        threat_level=ThreatLevel.HIGH,
        reason="repeated SYN attempts across many ports",
        evidence=("known_evidence:port_scan",),
        decided_at=NOW,
    )
    assert decision.action is FirewallAction.BLOCK


def test_firewall_decision_negative_threat_score_rejected() -> None:
    with pytest.raises(ValidationError):
        FirewallDecision(
            id="decision-1",
            threat_assessment_id="assessment-1",
            action=FirewallAction.MONITOR,
            threat_score=-1.0,
            threat_level=ThreatLevel.LOW,
            reason="n/a",
            decided_at=NOW,
        )
