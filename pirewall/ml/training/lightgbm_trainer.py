"""LightGBM known-attack classifier training (spec §14, §16)."""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import lightgbm as lgb
import numpy as np
import numpy.typing as npt
from sklearn.metrics import precision_recall_curve  # pyright: ignore[reportUnknownVariableType]

from pirewall.core.enums import ModelType
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.features.schema import FEATURE_NAMES, SCHEMA_VERSION
from pirewall.ml.artifacts.metadata import save_metadata
from pirewall.ml.preprocessing.common import LabeledFlow
from pirewall.ml.training.common import build_feature_matrix, split_train_val_test
from pirewall.ml.training.metrics import accuracy, confusion_matrix, macro_f1, per_class_metrics
from pirewall.ml.training.resampling import ResamplingConfig, ResamplingResult, resample_training_split

PREPROCESSING_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class LightGBMTrainingResult:
    """A trained booster plus everything needed to persist, evaluate, and audit it."""

    booster: lgb.Booster
    metadata: ModelMetadata
    class_mapping: dict[str, int]
    accuracy: float
    macro_f1: float
    confusion_matrix: dict[str, dict[str, int]]
    per_class: dict[str, dict[str, float]]
    split_sizes: dict[str, int] = field(default_factory=dict[str, int])
    resampling: ResamplingResult | None = None
    class_weighting_used: bool = False
    thresholds: dict[str, float] | None = None
    """Per-class PR-curve thresholds if `tune_thresholds` was requested, whether or not adopted."""
    thresholds_used: bool = False
    """Whether thresholded decoding won on validation macro-F1 and was used for the test metrics."""


def train_lightgbm(
    labeled_flows: Sequence[LabeledFlow],
    *,
    training_dataset_name: str,
    model_version: str,
    is_placeholder: bool = False,
    notes: str | None = None,
    num_boost_round: int = 50,
    val_fraction: float = 0.15,
    test_fraction: float = 0.15,
    seed: int = 42,
    resampling: ResamplingConfig | None = None,
    class_weighting: bool = False,
    tune_thresholds: bool = False,
    lambda_l2: float = 1.0,
) -> LightGBMTrainingResult:
    """Train a LightGBM classifier on `labeled_flows` and evaluate on a held-out **test** split.

    Three-way split (`pirewall.ml.training.common.split_train_val_test`):
    `resampling`/`class_weighting` only ever touch the training split;
    `tune_thresholds` only ever reads the validation split to pick a
    per-class decision threshold **and to decide whether to use it at all**
    -- per-class F1-optimal thresholds from a PR curve are picked
    independently per class, and for a class with only a handful of
    validation examples that can land on a degenerate extreme (threshold
    near 0.0 or 1.0) that wrecks decoding once every class's margin
    competes at argmax time. Thresholded decoding is only adopted if it
    actually beats plain argmax on validation macro-F1
    (`result.thresholds_used`); otherwise the reported result silently falls
    back to plain argmax, and `result.thresholds` is still returned for
    audit purposes even when not adopted. Final `accuracy`/`macro_f1`/
    `confusion_matrix`/`per_class` are always computed against the test
    split, which nothing above ever sees before that point -- resampling,
    weighting, or threshold selection touching test data would invalidate
    these metrics.

    `is_placeholder`/`notes` must be set truthfully by the caller — this
    function has no way to know whether `labeled_flows` came from a real
    dataset or a small synthetic fixture (CLAUDE.md labeling honesty).
    """
    if not labeled_flows:
        raise ValueError("cannot train on an empty dataset")

    features, labels = build_feature_matrix(labeled_flows)
    split = split_train_val_test(
        features, labels, val_fraction=val_fraction, test_fraction=test_fraction, seed=seed
    )
    if not split.y_train:
        raise ValueError("training split is empty; provide more labeled flows or smaller val/test fractions")

    x_train, y_train = split.x_train, split.y_train
    resampling_result: ResamplingResult | None = None
    if resampling is not None:
        resampling_result = resample_training_split(x_train, y_train, resampling, seed=seed)
        x_train, y_train = resampling_result.x_train, resampling_result.y_train

    class_mapping = {label: index for index, label in enumerate(sorted(set(labels)))}
    num_class = len(class_mapping)
    y_train_encoded = [class_mapping[label] for label in y_train]

    params: dict[str, object] = {
        "objective": "multiclass" if num_class > 2 else "binary",
        "verbosity": -1,
        "min_data_in_leaf": 1,
        "min_data_in_bin": 1,
        # L2 regularisation is NOT optional here, and its LightGBM default
        # (0.0) is unsafe for this problem. A leaf's output is
        # -sum(grad) / (sum(hess) + lambda_l2); under the multiclass softmax
        # the hessian is p*(1-p), which vanishes as the model grows
        # confident. With lambda_l2 = 0 the only thing bounding a leaf is
        # min_sum_hessian_in_leaf (1e-3), so leaf values grow without bound
        # and boosting DIVERGES rather than converges.
        #
        # Measured on the real CICIDS2017 split (docs/ML_DATA_AUDIT.md §F),
        # 12 classes, identical data and seed, varying only this parameter:
        #
        #   lambda_l2 = 0    round 10 macro-F1 0.8053 -> round 100 0.2519
        #                    max |raw score| 2.8e4    -> 6.4e6
        #   lambda_l2 = 1    round 10 macro-F1 0.8039 -> round 100 0.8636
        #                    max |raw score| 21.5     -> 27.8
        #
        # Without it, more boosting makes the model monotonically worse and
        # several classes collapse to 0% recall -- which is what produced
        # the 0.1975 macro-F1 of the v0.2.0 artifact. With it, macro-F1
        # improves monotonically with boosting, as it should.
        "lambda_l2": lambda_l2,
        "seed": seed,
    }
    if num_class > 2:
        params["num_class"] = num_class

    sample_weight = _balanced_sample_weights(y_train, num_class) if class_weighting else None
    train_dataset = lgb.Dataset(
        np.asarray(x_train, dtype=np.float64), label=y_train_encoded, weight=sample_weight
    )
    booster = _train_booster(params, train_dataset, num_boost_round)

    thresholds: dict[str, float] | None = None
    use_thresholds = False
    if tune_thresholds and split.x_val:
        val_proba = _predict_proba_matrix(booster, split.x_val, num_class)
        thresholds = _tune_class_thresholds(val_proba, split.y_val, class_mapping)
        # Self-validating gate: per-class F1-optimal thresholds are picked
        # independently per class from a PR curve, which for a class with
        # only a handful of validation examples can land on a degenerate
        # extreme (0.0 or ~1.0) that looks locally optimal but wrecks
        # decoding once every class's margin competes at argmax time.
        # Only adopt thresholded decoding if it actually beats plain argmax
        # on the *validation* split itself -- never on test.
        labels_sorted_val = sorted(class_mapping)
        argmax_val_labels = _decode_argmax(val_proba, class_mapping)
        thresholded_val_labels = _decode_with_thresholds(val_proba, class_mapping, thresholds)
        argmax_val_f1 = macro_f1(per_class_metrics(split.y_val, argmax_val_labels, labels_sorted_val))
        thresholded_val_per_class = per_class_metrics(split.y_val, thresholded_val_labels, labels_sorted_val)
        thresholded_val_f1 = macro_f1(thresholded_val_per_class)
        use_thresholds = thresholded_val_f1 > argmax_val_f1

    if split.x_test:
        test_proba = _predict_proba_matrix(booster, split.x_test, num_class)
        predicted_labels = (
            _decode_with_thresholds(test_proba, class_mapping, thresholds)
            if use_thresholds and thresholds is not None
            else _decode_argmax(test_proba, class_mapping)
        )
    else:
        predicted_labels = []

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
        split_sizes={"train": len(y_train), "val": len(split.y_val), "test": len(split.y_test)},
        resampling=resampling_result,
        class_weighting_used=class_weighting,
        thresholds=thresholds,
        thresholds_used=use_thresholds,
    )


def _balanced_sample_weights(y_train: Sequence[str], num_class: int) -> npt.NDArray[np.float64]:
    """Per-sample weights via the standard "balanced" heuristic: `n_samples / (n_classes * class_count)`.

    The same formula scikit-learn's `class_weight="balanced"` uses. LightGBM's
    `is_unbalance`/`scale_pos_weight` only apply to `binary`/`multiclassova`
    objectives, not the `multiclass` (softmax) objective this trainer uses
    for >2 classes -- per-sample weights are the documented equivalent.
    """
    counts = Counter(y_train)
    n_samples = len(y_train)
    weight_by_label = {label: n_samples / (num_class * count) for label, count in counts.items()}
    return np.asarray([weight_by_label[label] for label in y_train], dtype=np.float64)


def _train_booster(
    params: dict[str, object], train_dataset: lgb.Dataset, num_boost_round: int
) -> lgb.Booster:
    """Typed façade over `lgb.train` — LightGBM's own signature has Unknown pieces (callback unions)."""
    return lgb.train(  # pyright: ignore[reportUnknownMemberType]
        params, train_dataset, num_boost_round=num_boost_round
    )


def _predict_proba_matrix(
    booster: lgb.Booster, x: list[list[float]], num_class: int
) -> npt.NDArray[np.float64]:
    """Booster.predict, normalized to a `(n_samples, num_class)` probability matrix in both objectives.

    `multiclass` already predicts this shape; `binary` predicts a 1-D
    positive-class probability, reshaped here to `[1 - p, p]` so downstream
    threshold/decode logic doesn't need two code paths.
    """
    raw = booster.predict(  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        np.asarray(x, dtype=np.float64)
    )
    proba = np.asarray(raw, dtype=np.float64)
    if num_class <= 2:
        positive = proba.reshape(-1, 1)
        return np.hstack([1.0 - positive, positive])
    return proba


def _decode_argmax(proba: npt.NDArray[np.float64], class_mapping: dict[str, int]) -> list[str]:
    labels_in_order = sorted(class_mapping, key=lambda label: class_mapping[label])
    return [labels_in_order[int(i)] for i in np.argmax(proba, axis=1)]


_MIN_VALIDATION_POSITIVES_FOR_THRESHOLD_TUNING = 50


def _tune_class_thresholds(
    val_proba: npt.NDArray[np.float64], y_val: Sequence[str], class_mapping: dict[str, int]
) -> dict[str, float]:
    """Per class, pick the validation-split probability threshold maximizing that class's one-vs-rest F1.

    Used only to decode predictions ("thresholded argmax": predict
    `argmax(proba - threshold)` instead of plain `argmax(proba)`) -- plain
    argmax implicitly biases toward whichever class's raw softmax
    probability tends to run highest, usually the majority class, ignoring
    that a rare class's useful operating point is often well below 0.5.

    A class with fewer than `_MIN_VALIDATION_POSITIVES_FOR_THRESHOLD_TUNING`
    validation examples does not get its own PR-curve optimum -- with only a
    handful of points, "the threshold that maximizes F1" is themselves prone
    to hit a degenerate extreme (threshold near 0.0, so the class always
    wins its margin comparison, or near 1.0, so it never does) that measures
    as a local optimum on this tiny sample but generalizes terribly. Such a
    class falls back to the mean of the well-supported classes' tuned
    thresholds instead, keeping it in the same competitive range as a
    "typical" class rather than an arbitrary extreme.
    """
    tuned: dict[str, float] = {}
    underrepresented: list[str] = []
    for label, index in class_mapping.items():
        y_true_binary = [1 if label == actual else 0 for actual in y_val]
        if sum(y_true_binary) < _MIN_VALIDATION_POSITIVES_FOR_THRESHOLD_TUNING:
            underrepresented.append(label)
            continue
        precision, recall, pr_thresholds = _precision_recall_curve(y_true_binary, val_proba[:, index])
        if len(pr_thresholds) == 0:
            underrepresented.append(label)
            continue
        f1_scores = [
            (2 * p * r / (p + r)) if (p + r) > 0 else 0.0
            for p, r in zip(precision[:-1], recall[:-1], strict=True)
        ]
        tuned[label] = float(pr_thresholds[int(np.argmax(f1_scores))])

    fallback = sum(tuned.values()) / len(tuned) if tuned else 0.5
    for label in underrepresented:
        tuned[label] = fallback
    return tuned


def _decode_with_thresholds(
    proba: npt.NDArray[np.float64], class_mapping: dict[str, int], thresholds: dict[str, float]
) -> list[str]:
    labels_in_order = sorted(class_mapping, key=lambda label: class_mapping[label])
    threshold_vector = np.asarray([thresholds[label] for label in labels_in_order], dtype=np.float64)
    margins = proba - threshold_vector
    return [labels_in_order[int(i)] for i in np.argmax(margins, axis=1)]


def _precision_recall_curve(
    y_true_binary: list[int], scores: npt.NDArray[np.float64]
) -> tuple[npt.NDArray[np.float64], npt.NDArray[np.float64], npt.NDArray[np.float64]]:
    """Typed façade over `sklearn.metrics.precision_recall_curve` — scikit-learn ships no type stubs."""
    precision, recall, thresholds = precision_recall_curve(  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        y_true_binary, scores
    )
    return (
        np.asarray(precision, dtype=np.float64),  # pyright: ignore[reportUnknownArgumentType]
        np.asarray(recall, dtype=np.float64),  # pyright: ignore[reportUnknownArgumentType]
        np.asarray(thresholds, dtype=np.float64),  # pyright: ignore[reportUnknownArgumentType]
    )


def save_lightgbm_artifact(
    result: LightGBMTrainingResult, output_dir: Path, filename: str = "lightgbm_model.txt"
) -> Path:
    """Persist the booster (LightGBM's own text format) and its metadata sidecar."""
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / filename
    result.booster.save_model(str(model_path))
    save_metadata(result.metadata, model_path)
    return model_path
