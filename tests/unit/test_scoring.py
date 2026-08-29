"""`pirewall.engine.scoring.score_evidence`: deterministic, hand-computed cases (spec §18)."""

from datetime import UTC, datetime

from pirewall.config.models import ThreatConfig
from pirewall.core.enums import BehaviorPatternType
from pirewall.core.models.behavior import BehaviorAssessment
from pirewall.core.models.evidence import AnomalyEvidence, KnownEvidence
from pirewall.engine.scoring import score_evidence

NOW = datetime(2026, 1, 1, tzinfo=UTC)
CONFIG = ThreatConfig()  # known_attack_weight=60, anomaly_weight=15, behavior_weight=25


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
    assert breakdown.known_attack_contribution == 60.0 * 0.4
    assert breakdown.total == 24.0


def test_strong_known_attack_evidence() -> None:
    breakdown = score_evidence(CONFIG, _known("DDoS", confidence=1.0), None, None)
    assert breakdown.known_attack_contribution == 60.0
    assert breakdown.total == 60.0


def test_anomaly_only_contributes_full_flat_weight() -> None:
    breakdown = score_evidence(CONFIG, None, _anomaly(is_anomaly=True), None)
    assert breakdown.anomaly_contribution == 15.0
    assert breakdown.total == 15.0


# --- calibration properties (docs/ML_PIPELINE.md) -------------------------
# These pin the *reasoning* behind the weights, not just their values, so a
# future retune has to consciously restate the intent rather than quietly
# drift past it.


def test_anomaly_alone_cannot_reach_even_the_low_threshold() -> None:
    """Isolation Forest precision is 0.5300 — right about half the time.

    A detector that is a coin flip must not be able to raise a flow to an
    actionable level unaided; it may only push a score over a line in
    combination with other evidence.
    """
    breakdown = score_evidence(CONFIG, None, _anomaly(is_anomaly=True), None)
    assert breakdown.total < CONFIG.low_threshold


def test_confident_known_attack_alone_clears_medium_but_not_high() -> None:
    """LightGBM binary precision is 0.9927 — the most reliable single signal.

    It should be able to raise a flow on its own, but stop short of `high`
    so that enforcement still wants corroboration.
    """
    breakdown = score_evidence(CONFIG, _known("DDoS", confidence=1.0), None, None)
    assert breakdown.total >= CONFIG.medium_threshold
    assert breakdown.total < CONFIG.high_threshold


def test_known_attack_outweighs_anomaly_by_its_measured_reliability() -> None:
    """The ordering is the point: 0.9927 precision must outrank 0.5300."""
    assert CONFIG.known_attack_weight > CONFIG.behavior_weight > CONFIG.anomaly_weight


def test_weights_still_sum_to_a_full_score() -> None:
    """All three firing at maximum reaches exactly 100 — no dead range."""
    total = CONFIG.known_attack_weight + CONFIG.anomaly_weight + CONFIG.behavior_weight
    assert total == 100.0


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
