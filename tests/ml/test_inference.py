"""`pirewall.ml.inference`: schema-mismatch refusal and successful prediction (spec §15)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from pirewall.core.exceptions import ModelInferenceError, ModelLoadError
from pirewall.core.models.feature_vector import FeatureVector
from pirewall.features.schema import FEATURE_NAMES, SCHEMA_VERSION
from pirewall.ml.artifacts.metadata import save_metadata
from pirewall.ml.inference.common import validate_feature_vector
from pirewall.ml.inference.isolation_forest_predictor import anomaly_score
from pirewall.ml.inference.lightgbm_predictor import predict_class_probabilities
from pirewall.ml.inference.loader import load_isolation_forest_model, load_lightgbm_model
from pirewall.ml.preprocessing.common import LabeledFlow
from pirewall.ml.training.isolation_forest_trainer import (
    save_isolation_forest_artifact,
    train_isolation_forest,
)
from pirewall.ml.training.lightgbm_trainer import save_lightgbm_artifact, train_lightgbm
from tests.helpers.flows import make_flow

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _synthetic_labeled_flows() -> list[LabeledFlow]:
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
    return flows


def _make_feature_vector(**overrides: object) -> FeatureVector:
    defaults: dict[str, object] = {
        "flow_id": "flow-1",
        "schema_version": SCHEMA_VERSION,
        "feature_names": FEATURE_NAMES,
        "values": tuple(0.0 for _ in FEATURE_NAMES),
        "computed_at": NOW,
    }
    defaults.update(overrides)
    return FeatureVector.model_validate(defaults)


def test_lightgbm_load_and_predict_round_trip(tmp_path: Path) -> None:
    result = train_lightgbm(
        _synthetic_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes="NOT trained on real data — placeholder for pipeline testing",
    )
    model_path = save_lightgbm_artifact(result, tmp_path)

    loaded = load_lightgbm_model(model_path)
    assert loaded.metadata.feature_schema_version == SCHEMA_VERSION

    vector = _make_feature_vector()
    raw = predict_class_probabilities(loaded, vector)
    assert raw.shape == (1,)  # binary model: single positive-class probability


def test_lightgbm_load_refuses_schema_version_mismatch(tmp_path: Path) -> None:
    result = train_lightgbm(
        _synthetic_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
    )
    model_path = save_lightgbm_artifact(result, tmp_path)

    stale_metadata = result.metadata.model_copy(update={"feature_schema_version": "0.0.1-stale"})
    save_metadata(stale_metadata, model_path)

    with pytest.raises(ModelInferenceError, match="feature schema"):
        load_lightgbm_model(model_path)


def test_lightgbm_load_missing_file_raises_model_load_error(tmp_path: Path) -> None:
    with pytest.raises(ModelLoadError):
        load_lightgbm_model(tmp_path / "does_not_exist.txt")


def test_lightgbm_predict_refuses_feature_vector_schema_mismatch(tmp_path: Path) -> None:
    result = train_lightgbm(
        _synthetic_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
    )
    model_path = save_lightgbm_artifact(result, tmp_path)
    loaded = load_lightgbm_model(model_path)

    stale_vector = _make_feature_vector(schema_version="0.0.1-stale")
    with pytest.raises(ModelInferenceError):
        predict_class_probabilities(loaded, stale_vector)


def test_validate_feature_vector_checks_ordering(tmp_path: Path) -> None:
    result = train_lightgbm(
        _synthetic_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
    )
    model_path = save_lightgbm_artifact(result, tmp_path)
    loaded = load_lightgbm_model(model_path)

    reordered = _make_feature_vector(feature_names=tuple(reversed(FEATURE_NAMES)))
    with pytest.raises(ModelInferenceError, match="ordering"):
        validate_feature_vector(reordered, loaded.metadata)


def test_isolation_forest_load_and_score_round_trip(tmp_path: Path) -> None:
    result = train_isolation_forest(
        _synthetic_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
    )
    model_path = save_isolation_forest_artifact(result, tmp_path)

    loaded = load_isolation_forest_model(model_path)
    score = anomaly_score(loaded, _make_feature_vector())
    assert isinstance(score, float)


def test_isolation_forest_load_refuses_schema_mismatch(tmp_path: Path) -> None:
    result = train_isolation_forest(
        _synthetic_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
    )
    model_path = save_isolation_forest_artifact(result, tmp_path)

    stale_metadata = result.metadata.model_copy(update={"feature_schema_version": "0.0.1-stale"})
    save_metadata(stale_metadata, model_path)

    with pytest.raises(ModelInferenceError, match="feature schema"):
        load_isolation_forest_model(model_path)
