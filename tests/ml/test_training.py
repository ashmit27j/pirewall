"""LightGBM/Isolation Forest training against small synthetic fixture data (spec §14, §15, §16).

No real CICIDS2017/UNSW-NB15 files are used here — per `docs/PROGRESS.md`,
real dataset training is Environment-dependent and must be run by a human
on their dev machine. These tests only verify the training *pipeline*
itself: it must produce a correctly-shaped, honestly-labeled
`ModelMetadata` and a working artifact round-trip.
"""

from pathlib import Path

import pytest

from pirewall.core.enums import ModelType
from pirewall.ml.artifacts.metadata import load_metadata
from pirewall.ml.preprocessing.common import LabeledFlow
from pirewall.ml.training.isolation_forest_trainer import (
    save_isolation_forest_artifact,
    train_isolation_forest,
)
from pirewall.ml.training.lightgbm_trainer import save_lightgbm_artifact, train_lightgbm
from tests.helpers.flows import make_flow

PLACEHOLDER_NOTES = "NOT trained on real data — placeholder for pipeline testing"


def _synthetic_labeled_flows() -> list[LabeledFlow]:
    flows: list[LabeledFlow] = []
    for i in range(15):
        flows.append(
            LabeledFlow(
                flow=make_flow(
                    flow_id=f"benign-{i}",
                    packet_count=10,
                    byte_count=1000,
                    forward_packet_count=6,
                    backward_packet_count=4,
                    forward_byte_count=600,
                    backward_byte_count=400,
                    duration_seconds=10.0,
                    destination_port=443,
                ),
                label="BENIGN",
            )
        )
    for i in range(15):
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
                    destination_port=22,
                ),
                label="Attack",
            )
        )
    return flows


def test_train_lightgbm_produces_honest_placeholder_metadata() -> None:
    result = train_lightgbm(
        _synthetic_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes=PLACEHOLDER_NOTES,
    )

    assert result.metadata.model_type is ModelType.LIGHTGBM
    assert result.metadata.is_placeholder is True
    assert result.metadata.notes == PLACEHOLDER_NOTES
    assert result.metadata.training_dataset == "synthetic_fixture"
    assert set(result.class_mapping) == {"BENIGN", "Attack"}
    assert 0.0 <= result.accuracy <= 1.0
    assert "accuracy" in result.metadata.evaluation_metrics


def test_train_lightgbm_separates_well_clustered_classes() -> None:
    result = train_lightgbm(
        _synthetic_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes=PLACEHOLDER_NOTES,
        num_boost_round=20,
    )
    # BENIGN and Attack flows are far apart in feature space by construction,
    # so a correctly-wired pipeline should classify the held-out split perfectly.
    assert result.accuracy == 1.0


def test_train_lightgbm_rejects_empty_dataset() -> None:
    with pytest.raises(ValueError, match="empty"):
        train_lightgbm([], training_dataset_name="synthetic_fixture", model_version="0.0.1")


def test_train_isolation_forest_produces_honest_placeholder_metadata() -> None:
    result = train_isolation_forest(
        _synthetic_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes=PLACEHOLDER_NOTES,
    )

    assert result.metadata.model_type is ModelType.ISOLATION_FOREST
    assert result.metadata.is_placeholder is True
    assert result.metadata.notes == PLACEHOLDER_NOTES
    assert 0.0 <= result.precision <= 1.0
    assert 0.0 <= result.recall <= 1.0
    assert "false_positive_rate" in result.metadata.evaluation_metrics


def test_train_isolation_forest_rejects_empty_dataset() -> None:
    with pytest.raises(ValueError, match="empty"):
        train_isolation_forest([], training_dataset_name="synthetic_fixture", model_version="0.0.1")


def test_lightgbm_artifact_round_trips_through_metadata_sidecar(tmp_path: Path) -> None:
    result = train_lightgbm(
        _synthetic_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes=PLACEHOLDER_NOTES,
    )
    model_path = save_lightgbm_artifact(result, tmp_path)

    assert model_path.is_file()
    loaded_metadata = load_metadata(model_path)
    assert loaded_metadata == result.metadata


def test_isolation_forest_artifact_round_trips_through_metadata_sidecar(tmp_path: Path) -> None:
    result = train_isolation_forest(
        _synthetic_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes=PLACEHOLDER_NOTES,
    )
    model_path = save_isolation_forest_artifact(result, tmp_path)

    assert model_path.is_file()
    loaded_metadata = load_metadata(model_path)
    assert loaded_metadata == result.metadata


def test_lambda_l2_is_applied_and_defaults_to_a_nonzero_value() -> None:
    """Regression: lambda_l2 = 0 makes multiclass boosting diverge.

    A leaf's output is -sum(grad) / (sum(hess) + lambda_l2). Under the
    multiclass softmax the hessian p*(1-p) vanishes as the model grows
    confident, so with no L2 term the denominator collapses and leaf values
    grow without bound. On the real CICIDS2017 split that drove max |raw
    score| to 6.4e6 and macro-F1 from 0.8053 (round 10) down to 0.2519
    (round 100) -- the cause of the v0.2.0 artifact's 0.1975.

    This pins the default to something nonzero so the divergence cannot
    return by way of LightGBM's own default of 0.0.
    """
    import inspect

    signature = inspect.signature(train_lightgbm)
    default = signature.parameters["lambda_l2"].default
    assert isinstance(default, float)
    assert default > 0.0, "lambda_l2 must default to a nonzero value"


def test_trained_booster_records_the_l2_parameter() -> None:
    """The parameter must actually reach LightGBM, not just the signature."""
    flows: list[LabeledFlow] = []
    for i in range(12):
        flows.append(LabeledFlow(flow=make_flow(flow_id=f"b-{i}"), label="BENIGN"))
    for i in range(12):
        flows.append(
            LabeledFlow(
                flow=make_flow(
                    flow_id=f"a-{i}",
                    packet_count=1000,
                    byte_count=100_000,
                    forward_packet_count=900,
                    backward_packet_count=100,
                    forward_byte_count=90_000,
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
        notes="NOT trained on real data",
        lambda_l2=2.5,
    )
    assert result.booster.params.get("lambda_l2") == 2.5
