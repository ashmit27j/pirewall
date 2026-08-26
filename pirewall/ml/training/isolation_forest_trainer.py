"""Isolation Forest anomaly detector training (spec §14, §16)."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from pirewall.core.enums import ModelType
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.features.schema import FEATURE_NAMES, SCHEMA_VERSION
from pirewall.ml.artifacts.metadata import save_metadata
from pirewall.ml.preprocessing.common import LabeledFlow
from pirewall.ml.training.common import build_feature_matrix, split_train_test
from pirewall.ml.training.metrics import binary_confusion_counts, binary_rates, is_attack_label

PREPROCESSING_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class IsolationForestTrainingResult:
    """A trained Isolation Forest plus everything needed to persist and evaluate it."""

    model: IsolationForest
    metadata: ModelMetadata
    precision: float
    recall: float
    false_positive_rate: float
    false_negative_rate: float


def train_isolation_forest(
    labeled_flows: Sequence[LabeledFlow],
    *,
    training_dataset_name: str,
    model_version: str,
    is_placeholder: bool = False,
    notes: str | None = None,
    n_estimators: int = 100,
    test_fraction: float = 0.25,
    seed: int = 42,
) -> IsolationForestTrainingResult:
    """Train an Isolation Forest on `labeled_flows` and evaluate attack-vs-normal detection.

    Trained unsupervised on the training split (labels are only used for
    evaluation, per spec §14 "an anomaly is evidence, not automatically
    malicious" — the model itself never sees labels). `is_placeholder`/
    `notes` must be set truthfully by the caller (CLAUDE.md labeling
    honesty).
    """
    if not labeled_flows:
        raise ValueError("cannot train on an empty dataset")

    features, labels = build_feature_matrix(labeled_flows)
    split = split_train_test(features, labels, test_fraction=test_fraction, seed=seed)
    if not split.x_train:
        raise ValueError("training split is empty; provide more labeled flows or a smaller test_fraction")

    model = IsolationForest(n_estimators=n_estimators, random_state=seed)
    _fit(model, split.x_train)

    if split.x_test:
        y_true_is_attack = [is_attack_label(label) for label in split.y_test]
        y_pred_is_attack = [prediction == -1 for prediction in _predict(model, split.x_test)]
        true_positive, false_positive, false_negative, true_negative = binary_confusion_counts(
            y_true_is_attack, y_pred_is_attack
        )
    else:
        true_positive, false_positive, false_negative, true_negative = 0, 0, 0, 0
    rates = binary_rates(true_positive, false_positive, false_negative, true_negative)

    metadata = ModelMetadata(
        model_type=ModelType.ISOLATION_FOREST,
        model_version=model_version,
        training_dataset=training_dataset_name,
        feature_schema_version=SCHEMA_VERSION,
        feature_ordering=FEATURE_NAMES,
        training_timestamp=datetime.now(UTC),
        class_mapping={},
        preprocessing_version=PREPROCESSING_VERSION,
        evaluation_metrics=rates,
        is_placeholder=is_placeholder,
        notes=notes,
    )

    return IsolationForestTrainingResult(
        model=model,
        metadata=metadata,
        precision=rates["precision"],
        recall=rates["recall"],
        false_positive_rate=rates["false_positive_rate"],
        false_negative_rate=rates["false_negative_rate"],
    )


def _fit(model: IsolationForest, x_train: list[list[float]]) -> None:
    """Typed façade over `IsolationForest.fit` — scikit-learn ships no type stubs."""
    model.fit(np.asarray(x_train, dtype=np.float64))  # pyright: ignore[reportUnknownMemberType]


def _predict(model: IsolationForest, x_test: list[list[float]]) -> list[int]:
    """Typed façade over `IsolationForest.predict` (returns -1 for anomaly, 1 for normal)."""
    raw = model.predict(  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        np.asarray(x_test, dtype=np.float64)
    )
    return [int(value) for value in np.asarray(raw, dtype=np.int64)]


def save_isolation_forest_artifact(
    result: IsolationForestTrainingResult, output_dir: Path, filename: str = "isolation_forest_model.joblib"
) -> Path:
    """Persist the model via joblib (scikit-learn's recommended format) and its metadata sidecar."""
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / filename
    joblib.dump(result.model, model_path)  # pyright: ignore[reportUnknownMemberType]
    save_metadata(result.metadata, model_path)
    return model_path
