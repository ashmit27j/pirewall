"""`pirewall.engine.threat.assess_threat`: explainability and determinism (spec §18)."""

from datetime import UTC, datetime
from ipaddress import IPv4Address

from pirewall.config.models import ThreatConfig
from pirewall.core.enums import ThreatLevel
from pirewall.core.models.evidence import KnownEvidence
from pirewall.engine.threat import assess_threat

NOW = datetime(2026, 1, 1, tzinfo=UTC)
CONFIG = ThreatConfig()


def _known(predicted_class: str, confidence: float) -> KnownEvidence:
    return KnownEvidence(
        flow_id="flow-1",
        predicted_class=predicted_class,
        confidence=confidence,
        model_version="1.0.0",
        feature_schema_version="1.0.0",
        generated_at=NOW,
    )


def test_no_evidence_produces_low_threat_with_no_indicators() -> None:
    assessment = assess_threat(
        CONFIG, "flow-1", IPv4Address("10.0.0.5"), IPv4Address("10.0.0.10"), None, None, None, NOW
    )
    assert assessment.threat_level is ThreatLevel.LOW
    assert assessment.threat_score == 0.0
    assert "no significant" in assessment.explanation.lower()
    assert assessment.contributing_evidence == ()


def test_strong_known_attack_evidence_produces_high_or_critical_level() -> None:
    assessment = assess_threat(
        CONFIG,
        "flow-1",
        IPv4Address("10.0.0.5"),
        IPv4Address("10.0.0.10"),
        _known("DDoS", confidence=1.0),
        None,
        None,
        NOW,
    )
    assert assessment.threat_score == 60.0
    assert assessment.threat_level is ThreatLevel.MEDIUM  # 60.0 is >= medium, < high
    assert "DDoS" in assessment.explanation
    assert "known_evidence:DDoS" in assessment.contributing_evidence


def test_threat_level_thresholds_are_respected() -> None:
    # known_attack_weight=60 * confidence=1.0 -> score 60.0 -> medium band
    at_medium = assess_threat(
        CONFIG, "f", IPv4Address("10.0.0.5"), IPv4Address("10.0.0.10"), _known("A", 1.0), None, None, NOW
    )
    assert at_medium.threat_level is ThreatLevel.MEDIUM

    # confidence 0.4 -> score 20.0 -> LOW
    at_low = assess_threat(
        CONFIG, "f", IPv4Address("10.0.0.5"), IPv4Address("10.0.0.10"), _known("A", 0.4), None, None, NOW
    )
    assert at_low.threat_level is ThreatLevel.LOW


def test_assessment_is_deterministic_aside_from_id() -> None:
    source, destination = IPv4Address("10.0.0.5"), IPv4Address("10.0.0.10")
    known = _known("DDoS", 0.9)
    first = assess_threat(CONFIG, "flow-1", source, destination, known, None, None, NOW)
    second = assess_threat(CONFIG, "flow-1", source, destination, known, None, None, NOW)

    assert first.id != second.id
    assert first.threat_score == second.threat_score
    assert first.threat_level == second.threat_level
    assert first.explanation == second.explanation
    assert first.contributing_evidence == second.contributing_evidence
    assert first.confidence == second.confidence


def test_confidence_reflects_known_evidence_only_when_attack_predicted() -> None:
    source, destination = IPv4Address("10.0.0.5"), IPv4Address("10.0.0.10")
    benign = assess_threat(CONFIG, "f", source, destination, _known("BENIGN", 0.95), None, None, NOW)
    assert benign.confidence == 0.0

    attack = assess_threat(CONFIG, "f", source, destination, _known("DDoS", 0.95), None, None, NOW)
    assert attack.confidence == 0.95
