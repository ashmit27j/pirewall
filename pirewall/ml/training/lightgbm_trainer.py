"""LightGBM known-attack classifier training (spec §14, §16)."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import lightgbm as lgb
import numpy as np
import numpy.typing as npt

from pirewall.core.enums import ModelType
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.features.schema import FEATURE_NAMES, SCHEMA_VERSION
from pirewall.ml.artifacts.metadata import save_metadata
from pirewall.ml.preprocessing.common import LabeledFlow
from pirewall.ml.training.common import build_feature_matrix, split_train_test
from pirewall.ml.training.metrics import accuracy, confusion_matrix, macro_f1, per_class_metrics

PREPROCESSING_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class LightGBMTrainingResult:
    """A trained booster plus everything needed to persist and evaluate it."""

    booster: lgb.Booster
    metadata: ModelMetadata
    class_mapping: dict[str, int]
    accuracy: float
    macro_f1: float
    confusion_matrix: dict[str, dict[str, int]]
    per_class: dict[str, dict[str, float]]


def train_lightgbm(
    labeled_flows: Sequence[LabeledFlow],
    *,
    training_dataset_name: str,
    model_version: str,
    is_placeholder: bool = False,
    notes: str | None = None,
    num_boost_round: int = 50,
    test_fraction: float = 0.25,
    seed: int = 42,
) -> LightGBMTrainingResult:
    """Train a LightGBM classifier on `labeled_flows` and evaluate on a held-out split.

    `is_placeholder`/`notes` must be set truthfully by the caller — this
    function has no way to know whether `labeled_flows` came from a real
    dataset or a small synthetic fixture (CLAUDE.md labeling honesty).
    """
    if not labeled_flows:
        raise ValueError("cannot train on an empty dataset")

    features, labels = build_feature_matrix(labeled_flows)
    split = split_train_test(features, labels, test_fraction=test_fraction, seed=seed)
    if not split.y_train:
        raise ValueError("training split is empty; provide more labeled flows or a smaller test_fraction")

    class_mapping = {label: index for index, label in enumerate(sorted(set(labels)))}
    num_class = len(class_mapping)
    y_train_encoded = [class_mapping[label] for label in split.y_train]

    params: dict[str, object] = {
        "objective": "multiclass" if num_class > 2 else "binary",
        "verbosity": -1,
        "min_data_in_leaf": 1,
        "min_data_in_bin": 1,
        "seed": seed,
    }
    if num_class > 2:
        params["num_class"] = num_class

    train_dataset = lgb.Dataset(np.asarray(split.x_train, dtype=np.float64), label=y_train_encoded)
    booster = _train_booster(params, train_dataset, num_boost_round)

    predicted_labels = (
        _predict_labels(booster, split.x_test, class_mapping, num_class) if split.x_test else []
    )

    labels_sorted = sorted(class_mapping)
    acc = accuracy(split.y_test, predicted_labels) if split.y_test else 0.0
    per_class = per_class_metrics(split.y_test, predicted_labels, labels_sorted) if split.y_test else {}
    macro = macro_f1(per_class)
    matrix = confusion_matrix(split.y_test, predicted_labels, labels_sorted) if split.y_test else {}

    metadata = ModelMetadata(
        model_type=ModelType.LIGHTGBM,
        model_version=model_version,
        training_dataset=training_dataset_name,
        feature_schema_version=SCHEMA_VERSION,
        feature_ordering=FEATURE_NAMES,
        training_timestamp=datetime.now(UTC),
        class_mapping=class_mapping,
        preprocessing_version=PREPROCESSING_VERSION,
        evaluation_metrics={"accuracy": acc, "macro_f1": macro},
        is_placeholder=is_placeholder,
        notes=notes,
    )

    return LightGBMTrainingResult(
        booster=booster,
        metadata=metadata,
        class_mapping=class_mapping,
        accuracy=acc,
        macro_f1=macro,
        confusion_matrix=matrix,
        per_class=per_class,
    )


def _train_booster(
    params: dict[str, object], train_dataset: lgb.Dataset, num_boost_round: int
) -> lgb.Booster:
    """Typed façade over `lgb.train` — LightGBM's own signature has Unknown pieces (callback unions)."""
    return lgb.train(  # pyright: ignore[reportUnknownMemberType]
        params, train_dataset, num_boost_round=num_boost_round
    )


def _predict_proba(booster: lgb.Booster, x_test: list[list[float]]) -> npt.NDArray[np.float64]:
    """Typed façade over `Booster.predict` — its return type includes untyped sparse-matrix variants."""
    raw = booster.predict(  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        np.asarray(x_test, dtype=np.float64)
    )
    return np.asarray(raw, dtype=np.float64)


def _predict_labels(
    booster: lgb.Booster, x_test: list[list[float]], class_mapping: dict[str, int], num_class: int
) -> list[str]:
    index_to_label = {index: label for label, index in class_mapping.items()}
    raw = _predict_proba(booster, x_test)
    predicted_labels: list[str] = []
    for row in raw:
        if num_class > 2:  # noqa: SIM108 - kept as if/else, a nested ternary here hurts readability
            best_index = int(np.argmax(row))
        else:
            best_index = 1 if float(row) > 0.5 else 0
        predicted_labels.append(index_to_label[best_index])
    return predicted_labels


def save_lightgbm_artifact(
    result: LightGBMTrainingResult, output_dir: Path, filename: str = "lightgbm_model.txt"
) -> Path:
    """Persist the booster (LightGBM's own text format) and its metadata sidecar."""
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / filename
    result.booster.save_model(str(model_path))
    save_metadata(result.metadata, model_path)
    return model_path
