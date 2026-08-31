"""`pirewall.detection.anomaly.detect` against a small trained model."""

from datetime import UTC, datetime
from pathlib import Path

from pirewall.detection.anomaly import detect, detect_batch
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


def test_detect_batch_matches_individual_detect_for_the_same_flows(tmp_path: Path) -> None:
    """ADDENDUM_2 follow-up pass, section 3: batching must not change any flow's evidence."""
    loaded = _train_and_load(tmp_path)
    vectors = [extract_features(make_flow(flow_id=f"flow-{i}")) for i in range(5)]

    individual = [detect(loaded, vector, threshold=0.0, generated_at=NOW) for vector in vectors]
    batched = detect_batch(loaded, vectors, threshold=0.0, generated_at=NOW)

    assert len(batched) == len(individual)
    for one, many in zip(individual, batched, strict=True):
        assert one.flow_id == many.flow_id
        assert one.anomaly_score == many.anomaly_score
        assert one.is_anomaly == many.is_anomaly
        assert one.model_version == many.model_version


def test_detect_batch_agrees_with_individual_detect_on_the_known_outlier(tmp_path: Path) -> None:
    """The same outlier `test_detect_flags_wildly_different_flow_as_anomalous` (above) checks
    in isolation must get the identical `is_anomaly` verdict when scored as part of a batch
    alongside other flows — not just an identical raw score (already covered by
    `test_detect_batch_matches_individual_detect_for_the_same_flows`), the derived flag too.
    """
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
    vectors = [_benign_flow(i).flow for i in range(3)] + [outlier_flow]
    feature_vectors = [extract_features(flow) for flow in vectors]

    individual_verdict = detect(loaded, feature_vectors[-1], threshold=0.0, generated_at=NOW)
    batched = detect_batch(loaded, feature_vectors, threshold=0.0, generated_at=NOW)

    assert batched[-1].is_anomaly == individual_verdict.is_anomaly
    assert batched[-1].is_anomaly is True


def test_detect_batch_handles_empty_input(tmp_path: Path) -> None:
    loaded = _train_and_load(tmp_path)

    assert detect_batch(loaded, [], threshold=0.0, generated_at=NOW) == []
