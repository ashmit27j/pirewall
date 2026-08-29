"""Isolation Forest anomaly detector training (spec §14, §16)."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from pirewall.core.enums import ModelType
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.features.schema import FEATURE_NAMES, SCHEMA_VERSION
from pirewall.ml.artifacts.metadata import save_metadata
from pirewall.ml.preprocessing.common import LabeledFlow
from pirewall.ml.training.common import build_feature_matrix, split_train_val_test
from pirewall.ml.training.metrics import binary_confusion_counts, binary_rates, is_attack_label
from pirewall.ml.training.resampling import ResamplingConfig, ResamplingResult, resample_training_split

PREPROCESSING_VERSION = "1.0.0"

# sklearn's own IsolationForest type: `float | Literal["auto"]` for
# contamination, `int | float | Literal["auto"]` for max_samples. No stubs
# ship a name for either, so this project names them itself.
Contamination = float | str
MaxSamples = int | float | str


@dataclass(frozen=True, slots=True)
class IsolationForestTrainingResult:
    """A trained Isolation Forest plus everything needed to persist, evaluate, and audit it."""

    model: IsolationForest
    metadata: ModelMetadata
    precision: float
    recall: float
    false_positive_rate: float
    false_negative_rate: float
    split_sizes: dict[str, int]
    resampling: ResamplingResult | None = None


def train_isolation_forest(
    labeled_flows: Sequence[LabeledFlow],
    *,
    training_dataset_name: str,
    model_version: str,
    is_placeholder: bool = False,
    notes: str | None = None,
    n_estimators: int = 100,
    contamination: Contamination = "auto",
    max_samples: MaxSamples = "auto",
    val_fraction: float = 0.15,
    test_fraction: float = 0.15,
    seed: int = 42,
    resampling: ResamplingConfig | None = None,
) -> IsolationForestTrainingResult:
    """Train an Isolation Forest on `labeled_flows` and evaluate attack-vs-normal detection.

    Fit on **normal-only** training rows: dataset labels select which rows
    represent a normal baseline (filtering `is_attack_label(label)` out of
    the training split before `.fit()`), they are never passed to the model
    as a supervised target. This is standard anomaly-detection methodology
    and matters in practice — fitting on a split that still contains a large
    attack fraction (as this trainer once did) teaches Isolation Forest an
    overly loose "normal" boundary and tanks recall. `resampling` (train
    split only, if given) undersamples the normal class before that filter,
    for a faster fit on a large corpus.

    Three-way split (`pirewall.ml.training.common.split_train_val_test`);
    final `precision`/`recall`/`false_positive_rate`/`false_negative_rate`
    are always computed against the held-out **test** split, never touched
    by resampling or by `sweep_isolation_forest_contamination` below — per
    spec §14 "an anomaly is evidence, not automatically malicious".
    `is_placeholder`/`notes` must be set truthfully by the caller (CLAUDE.md
    labeling honesty).
    """
    if not labeled_flows:
        raise ValueError("cannot train on an empty dataset")

    features, labels = build_feature_matrix(labeled_flows)
    split = split_train_val_test(
        features, labels, val_fraction=val_fraction, test_fraction=test_fraction, seed=seed
    )
    if not split.x_train:
        raise ValueError("training split is empty; provide more labeled flows or smaller val/test fractions")

    x_train, y_train = split.x_train, split.y_train
    resampling_result: ResamplingResult | None = None
    if resampling is not None:
        resampling_result = resample_training_split(x_train, y_train, resampling, seed=seed)
        x_train, y_train = resampling_result.x_train, resampling_result.y_train

    normal_x_train = [x for x, label in zip(x_train, y_train, strict=True) if not is_attack_label(label)]
    if not normal_x_train:
        raise ValueError(
            "no normal/benign-labeled flows in the training split; Isolation Forest fits "
            "on normal-only traffic and needs at least one such example (provide more "
            "labeled flows or smaller val/test fractions)"
        )

    model = IsolationForest(
        n_estimators=n_estimators,
        # sklearn's own stubs only declare `contamination`/`max_samples` as
        # `str`; both also accept float (the documented, real API).
        contamination=cast(str, contamination),
        max_samples=cast(str, max_samples),
        random_state=seed,
    )
    _fit(model, normal_x_train)

    rates = evaluate_isolation_forest(model, split.x_test, split.y_test)

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
        split_sizes={"train": len(y_train), "val": len(split.y_val), "test": len(split.y_test)},
        resampling=resampling_result,
    )


def evaluate_isolation_forest(
    model: IsolationForest, x: list[list[float]], y: list[str]
) -> dict[str, float]:
    """Precision/recall/FPR/FNR for `model` -- used for both validation sweeps and final test evaluation."""
    if not x:
        true_positive, false_positive, false_negative, true_negative = 0, 0, 0, 0
    else:
        y_true_is_attack = [is_attack_label(label) for label in y]
        y_pred_is_attack = [prediction == -1 for prediction in _predict(model, x)]
        true_positive, false_positive, false_negative, true_negative = binary_confusion_counts(
            y_true_is_attack, y_pred_is_attack
        )
    return binary_rates(true_positive, false_positive, false_negative, true_negative)


@dataclass(frozen=True, slots=True)
class ContaminationCandidateResult:
    """One `contamination` candidate's rates, measured on the validation split only."""

    contamination: float
    precision: float
    recall: float
    false_positive_rate: float
    false_negative_rate: float


def sweep_isolation_forest_contamination(
    labeled_flows: Sequence[LabeledFlow],
    candidates: Sequence[float],
    *,
    n_estimators: int = 100,
    max_samples: MaxSamples = "auto",
    val_fraction: float = 0.15,
    test_fraction: float = 0.15,
    seed: int = 42,
    resampling: ResamplingConfig | None = None,
) -> list[ContaminationCandidateResult]:
    """Fit one Isolation Forest per candidate `contamination`, evaluated on the **validation** split only.

    Never touches the test split -- this is for picking a `contamination`
    value to hand to `train_isolation_forest` afterward, whose own,
    separate evaluation against the untouched test split is what gets
    reported as the final metric. Uses the same `seed`/fractions as
    `train_isolation_forest` so the two calls see byte-identical
    train/val/test partitions (`split_train_val_test` is deterministic).
    """
    features, labels = build_feature_matrix(labeled_flows)
    split = split_train_val_test(
        features, labels, val_fraction=val_fraction, test_fraction=test_fraction, seed=seed
    )
    if not split.x_val:
        raise ValueError("validation split is empty; provide more labeled flows or a larger val_fraction")

    x_train, y_train = split.x_train, split.y_train
    if resampling is not None:
        resampling_result = resample_training_split(x_train, y_train, resampling, seed=seed)
        x_train, y_train = resampling_result.x_train, resampling_result.y_train

    normal_x_train = [x for x, label in zip(x_train, y_train, strict=True) if not is_attack_label(label)]
    if not normal_x_train:
        raise ValueError("no normal/benign-labeled flows in the training split to sweep against")

    results: list[ContaminationCandidateResult] = []
    for contamination in candidates:
        model = IsolationForest(
            n_estimators=n_estimators,
            contamination=cast(str, contamination),
            max_samples=cast(str, max_samples),
            random_state=seed,
        )
        _fit(model, normal_x_train)
        rates = evaluate_isolation_forest(model, split.x_val, split.y_val)
        results.append(
            ContaminationCandidateResult(
                contamination=contamination,
                precision=rates["precision"],
                recall=rates["recall"],
                false_positive_rate=rates["false_positive_rate"],
                false_negative_rate=rates["false_negative_rate"],
            )
        )
    return results


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
