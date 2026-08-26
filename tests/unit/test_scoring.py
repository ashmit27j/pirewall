"""`pirewall.engine.scoring.score_evidence`: deterministic, hand-computed cases (spec §18)."""

from datetime import UTC, datetime

from pirewall.config.models import ThreatConfig
from pirewall.core.enums import BehaviorPatternType
from pirewall.core.models.behavior import BehaviorAssessment
from pirewall.core.models.evidence import AnomalyEvidence, KnownEvidence
from pirewall.engine.scoring import score_evidence

NOW = datetime(2026, 1, 1, tzinfo=UTC)
CONFIG = ThreatConfig()  # known_attack_weight=50, anomaly_weight=25, behavior_weight=25


def _known(predicted_class: str, confidence: float) -> KnownEvidence:
    return KnownEvidence(
        flow_id="flow-1",
        predicted_class=predicted_class,
        confidence=confidence,
        model_version="1.0.0",
        feature_schema_version="1.0.0",
        generated_at=NOW,
    )


def _anomaly(is_anomaly: bool) -> AnomalyEvidence:
    return AnomalyEvidence(
        flow_id="flow-1",
        anomaly_score=-0.5 if is_anomaly else 0.5,
        threshold=0.0,
        is_anomaly=is_anomaly,
        model_version="1.0.0",
        feature_schema_version="1.0.0",
        generated_at=NOW,
    )


def _behavior(patterns: tuple[BehaviorPatternType, ...]) -> BehaviorAssessment:
    return BehaviorAssessment.model_validate(
        {
            "source_ip": "10.0.0.5",
            "detected_patterns": patterns,
            "confidence": 0.5,
            "description": "test",
            "window_start": NOW,
            "window_end": NOW,
        }
    )


def test_no_evidence_scores_zero() -> None:
    breakdown = score_evidence(CONFIG, None, None, None)
    assert breakdown.total == 0.0


def test_benign_known_evidence_contributes_nothing() -> None:
    breakdown = score_evidence(CONFIG, _known("BENIGN", confidence=0.99), None, None)
    assert breakdown.known_attack_contribution == 0.0
    assert breakdown.total == 0.0


def test_weak_known_attack_evidence() -> None:
    breakdown = score_evidence(CONFIG, _known("PortScan", confidence=0.4), None, None)
    assert breakdown.known_attack_contribution == 50.0 * 0.4
    assert breakdown.total == 20.0


def test_strong_known_attack_evidence() -> None:
    breakdown = score_evidence(CONFIG, _known("DDoS", confidence=1.0), None, None)
    assert breakdown.known_attack_contribution == 50.0
    assert breakdown.total == 50.0


def test_anomaly_only_contributes_full_flat_weight() -> None:
    breakdown = score_evidence(CONFIG, None, _anomaly(is_anomaly=True), None)
    assert breakdown.anomaly_contribution == 25.0
    assert breakdown.total == 25.0


def test_non_anomalous_evidence_contributes_nothing() -> None:
    breakdown = score_evidence(CONFIG, None, _anomaly(is_anomaly=False), None)
    assert breakdown.anomaly_contribution == 0.0


def test_behavior_contribution_scales_with_pattern_count() -> None:
    breakdown = score_evidence(
        CONFIG, None, None, _behavior((BehaviorPatternType.SCANNING,))
    )
    expected = 25.0 * (1 / 8)
    assert round(breakdown.behavior_contribution, 6) == round(expected, 6)


def test_multiple_corroborating_evidence_types_sum() -> None:
    breakdown = score_evidence(
        CONFIG,
        _known("DDoS", confidence=1.0),
        _anomaly(is_anomaly=True),
        _behavior((BehaviorPatternType.SCANNING, BehaviorPatternType.HIGH_FREQUENCY)),
    )
    expected = 50.0 + 25.0 + 25.0 * (2 / 8)
    assert round(breakdown.total, 6) == round(expected, 6)


def test_score_is_clamped_to_100() -> None:
    breakdown = score_evidence(
        CONFIG,
        _known("DDoS", confidence=1.0),
        _anomaly(is_anomaly=True),
        _behavior(tuple(BehaviorPatternType)),
    )
    assert breakdown.total == 100.0


def test_scoring_is_deterministic() -> None:
    evidence = (_known("DDoS", 0.8), _anomaly(True), _behavior((BehaviorPatternType.BURST,)))
    first = score_evidence(CONFIG, *evidence)
    second = score_evidence(CONFIG, *evidence)
    assert first == second
