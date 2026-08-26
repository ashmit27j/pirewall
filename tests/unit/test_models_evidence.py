"""`KnownEvidence`, `AnomalyEvidence`, and `BehaviorAssessment` domain models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from pirewall.core.enums import BehaviorPatternType
from pirewall.core.models.behavior import BehaviorAssessment
from pirewall.core.models.evidence import AnomalyEvidence, KnownEvidence

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_valid_known_evidence_constructs() -> None:
    ev = KnownEvidence(
        flow_id="flow-1",
        predicted_class="port_scan",
        confidence=0.92,
        class_probabilities={"port_scan": 0.92, "benign": 0.08},
        model_version="lgbm-1.0.0",
        feature_schema_version="1.0.0",
        generated_at=NOW,
    )
    assert ev.confidence == 0.92


def test_known_evidence_confidence_out_of_range_rejected() -> None:
    with pytest.raises(ValidationError):
        KnownEvidence(
            flow_id="flow-1",
            predicted_class="port_scan",
            confidence=1.5,
            model_version="lgbm-1.0.0",
            feature_schema_version="1.0.0",
            generated_at=NOW,
        )


def test_valid_anomaly_evidence_constructs() -> None:
    ev = AnomalyEvidence(
        flow_id="flow-1",
        anomaly_score=-0.3,
        threshold=-0.1,
        is_anomaly=True,
        model_version="iforest-1.0.0",
        feature_schema_version="1.0.0",
        generated_at=NOW,
    )
    assert ev.is_anomaly is True


def test_anomaly_evidence_missing_field_rejected() -> None:
    with pytest.raises(ValidationError):
        AnomalyEvidence.model_validate(
            {
                "flow_id": "flow-1",
                "anomaly_score": -0.3,
                "is_anomaly": True,
                "model_version": "iforest-1.0.0",
                "feature_schema_version": "1.0.0",
                "generated_at": NOW,
            }
        )


def test_valid_behavior_assessment_constructs() -> None:
    assessment = BehaviorAssessment.model_validate(
        {
            "source_ip": "10.0.0.5",
            "detected_patterns": (BehaviorPatternType.SCANNING,),
            "confidence": 0.7,
            "description": "many destination ports probed in a short window",
            "window_start": NOW,
            "window_end": NOW,
        }
    )
    assert BehaviorPatternType.SCANNING in assessment.detected_patterns


def test_behavior_assessment_bad_window_rejected() -> None:
    earlier = datetime(2025, 1, 1, tzinfo=UTC)
    with pytest.raises(ValidationError):
        BehaviorAssessment.model_validate(
            {
                "source_ip": "10.0.0.5",
                "confidence": 0.7,
                "description": "bad window",
                "window_start": NOW,
                "window_end": earlier,
            }
        )


def test_behavior_assessment_ipv6_rejected() -> None:
    with pytest.raises(ValidationError):
        BehaviorAssessment.model_validate(
            {
                "source_ip": "2001:db8::1",
                "confidence": 0.7,
                "description": "ipv6 not supported for v1 (ADDENDUM.md A5)",
                "window_start": NOW,
                "window_end": NOW,
            }
        )
