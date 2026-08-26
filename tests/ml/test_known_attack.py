"""`pirewall.detection.known_attack.classify` against a small trained model."""

from datetime import UTC, datetime
from pathlib import Path

from pirewall.detection.known_attack import classify
from pirewall.features.extractor import extract_features
from pirewall.ml.inference.loader import LoadedLightGBMModel, load_lightgbm_model
from pirewall.ml.preprocessing.common import LabeledFlow
from pirewall.ml.training.lightgbm_trainer import save_lightgbm_artifact, train_lightgbm
from tests.helpers.flows import make_flow

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _train_and_load(tmp_path: Path) -> LoadedLightGBMModel:
    flows: list[LabeledFlow] = []
    for i in range(10):
        flows.append(LabeledFlow(flow=make_flow(flow_id=f"benign-{i}"), label="BENIGN"))
    for i in range(10):
        flows.append(
            LabeledFlow(
                flow=make_flow(
                    flow_id=f"attack-{i}",
                    packet_count=2000,
                    byte_count=200_000,
                    forward_packet_count=1900,
                    backward_packet_count=100,
                    forward_byte_count=190_000,
                    backward_byte_count=10_000,
                    duration_seconds=1.0,
                ),
                label="Attack",
            )
        )
    result = train_lightgbm(
        flows,
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes="NOT trained on real data — placeholder for pipeline testing",
    )
    model_path = save_lightgbm_artifact(result, tmp_path)
    return load_lightgbm_model(model_path)


def test_classify_benign_flow(tmp_path: Path) -> None:
    loaded = _train_and_load(tmp_path)
    flow = make_flow(flow_id="test-benign")
    vector = extract_features(flow)

    evidence = classify(loaded, vector, NOW)

    assert evidence.flow_id == "test-benign"
    assert evidence.predicted_class in {"BENIGN", "Attack"}
    assert 0.0 <= evidence.confidence <= 1.0
    assert abs(sum(evidence.class_probabilities.values()) - 1.0) < 1e-6
    assert evidence.model_version == "0.0.1-placeholder"
    assert evidence.generated_at == NOW


def test_classify_attack_like_flow_predicts_attack(tmp_path: Path) -> None:
    loaded = _train_and_load(tmp_path)
    attack_flow = make_flow(
        flow_id="test-attack",
        packet_count=2000,
        byte_count=200_000,
        forward_packet_count=1900,
        backward_packet_count=100,
        forward_byte_count=190_000,
        backward_byte_count=10_000,
        duration_seconds=1.0,
    )
    vector = extract_features(attack_flow)

    evidence = classify(loaded, vector, NOW)

    assert evidence.predicted_class == "Attack"
    assert evidence.confidence > 0.5
