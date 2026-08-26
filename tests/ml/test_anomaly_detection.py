"""`pirewall.detection.anomaly.detect` against a small trained model."""

from datetime import UTC, datetime
from pathlib import Path

from pirewall.detection.anomaly import detect
from pirewall.features.extractor import extract_features
from pirewall.ml.inference.loader import LoadedIsolationForestModel, load_isolation_forest_model
from pirewall.ml.preprocessing.common import LabeledFlow
from pirewall.ml.training.isolation_forest_trainer import (
    save_isolation_forest_artifact,
    train_isolation_forest,
)
from tests.helpers.flows import make_flow

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _benign_flow(i: int) -> LabeledFlow:
    forward_packets = 5 + (i % 3)
    backward_packets = 3 + (i % 2)
    forward_bytes = 500 + (i % 3) * 30
    backward_bytes = 300 + (i % 2) * 20
    return LabeledFlow(
        flow=make_flow(
            flow_id=f"benign-{i}",
            packet_count=forward_packets + backward_packets,
            byte_count=forward_bytes + backward_bytes,
            forward_packet_count=forward_packets,
            backward_packet_count=backward_packets,
            forward_byte_count=forward_bytes,
            backward_byte_count=backward_bytes,
            duration_seconds=8.0 + (i % 5),
        ),
        label="BENIGN",
    )


def _train_and_load(tmp_path: Path) -> LoadedIsolationForestModel:
    flows = [_benign_flow(i) for i in range(30)]
    result = train_isolation_forest(
        flows,
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes="NOT trained on real data — placeholder for pipeline testing",
    )
    model_path = save_isolation_forest_artifact(result, tmp_path)
    return load_isolation_forest_model(model_path)


def test_detect_returns_evidence_not_a_verdict(tmp_path: Path) -> None:
    loaded = _train_and_load(tmp_path)
    flow = make_flow(flow_id="test-flow")
    vector = extract_features(flow)

    evidence = detect(loaded, vector, threshold=0.0, generated_at=NOW)

    assert evidence.flow_id == "test-flow"
    assert isinstance(evidence.anomaly_score, float)
    assert evidence.threshold == 0.0
    assert evidence.is_anomaly == (evidence.anomaly_score < 0.0)
    assert evidence.model_version == "0.0.1-placeholder"
    assert evidence.generated_at == NOW


def test_detect_flags_wildly_different_flow_as_anomalous(tmp_path: Path) -> None:
    loaded = _train_and_load(tmp_path)
    outlier_flow = make_flow(
        flow_id="outlier",
        packet_count=500_000,
        byte_count=50_000_000,
        forward_packet_count=499_000,
        backward_packet_count=1_000,
        forward_byte_count=49_900_000,
        backward_byte_count=100_000,
        duration_seconds=0.01,
    )
    vector = extract_features(outlier_flow)

    evidence = detect(loaded, vector, threshold=0.0, generated_at=NOW)

    assert evidence.is_anomaly is True
