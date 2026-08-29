"""Training-split class-imbalance resampling via `imbalanced-learn`.

**Call this on the training split only.** Undersampling and SMOTE must never
see validation or test rows -- resampling data the model is later evaluated
against would let synthetic/duplicated rows leak into the metrics that are
supposed to measure generalization, invalidating them. Every caller in this
project passes only `ThreeWaySplit.x_train`/`y_train`
(`pirewall.ml.training.common.split_train_val_test`) here.

Two independent, dataset-agnostic knobs, not CICIDS2017-specific label
matching:

* **Undersample** the single most frequent class (auto-detected, not
  hardcoded to "BENIGN" -- the same logic applies unchanged to UNSW-NB15's
  "Normal") down to `undersample_ceiling`, if it exceeds that ceiling.
* **Oversample (SMOTE)** every class at or below `oversample_ceiling` up to
  `oversample_target`.
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
import numpy.typing as npt
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from imblearn.under_sampling import RandomUnderSampler


@dataclass(frozen=True, slots=True)
class ResamplingConfig:
    """Bundles the three resampling knobs so trainer signatures take one argument, not three."""

    undersample_ceiling: int
    oversample_ceiling: int
    oversample_target: int


@dataclass(frozen=True, slots=True)
class ResamplingResult:
    """The resampled training split plus a full before/after audit trail."""

    x_train: list[list[float]]
    y_train: list[str]
    before_counts: dict[str, int]
    after_counts: dict[str, int]
    undersampled_labels: tuple[str, ...]
    oversampled_labels: tuple[str, ...]


def resample_training_split(
    x_train: Sequence[list[float]],
    y_train: Sequence[str],
    config: ResamplingConfig,
    *,
    seed: int = 42,
) -> ResamplingResult:
    """Undersample the majority class and SMOTE the rarest classes, training split only.

    A no-op (returns the input unchanged) if no class exceeds
    `config.undersample_ceiling` and no class is at or below
    `config.oversample_ceiling` -- safe to call unconditionally on small
    fixtures that shouldn't trigger either transform.
    """
    before_counts = dict(Counter(y_train))

    majority_label = max(before_counts, key=lambda label: before_counts[label])
    undersample_strategy: dict[str, int] = {}
    if before_counts[majority_label] > config.undersample_ceiling:
        undersample_strategy[majority_label] = config.undersample_ceiling

    # SMOTE needs at least 2 examples of a class to find any neighbor at
    # all; a singleton class is left untouched rather than raising.
    oversample_strategy: dict[str, int] = {
        label: config.oversample_target
        for label, count in before_counts.items()
        if 2 <= count <= config.oversample_ceiling and count < config.oversample_target
    }

    steps: list[tuple[str, object]] = []
    if undersample_strategy:
        # imbalanced-learn's own stubs only declare `sampling_strategy: str`;
        # the dict form (per-class target counts) is real, documented API.
        steps.append(
            (
                "undersample",
                RandomUnderSampler(sampling_strategy=undersample_strategy, random_state=seed),  # pyright: ignore[reportArgumentType]
            )
        )
    if oversample_strategy:
        min_source_count = min(before_counts[label] for label in oversample_strategy)
        k_neighbors = max(1, min(5, min_source_count - 1))
        steps.append(
            (
                "oversample",
                SMOTE(sampling_strategy=oversample_strategy, k_neighbors=k_neighbors, random_state=seed),  # pyright: ignore[reportArgumentType]
            )
        )

    if not steps:
        return ResamplingResult(
            x_train=list(x_train),
            y_train=list(y_train),
            before_counts=before_counts,
            after_counts=before_counts,
            undersampled_labels=(),
            oversampled_labels=(),
        )

    x_resampled, y_resampled = _fit_resample(steps, x_train, y_train)
    x_out = [list(row) for row in x_resampled]
    y_out = [str(label) for label in y_resampled]
    after_counts = dict(Counter(y_out))

    return ResamplingResult(
        x_train=x_out,
        y_train=y_out,
        before_counts=before_counts,
        after_counts=after_counts,
        undersampled_labels=tuple(undersample_strategy),
        oversampled_labels=tuple(oversample_strategy),
    )


def _fit_resample(
    steps: list[tuple[str, object]], x_train: Sequence[list[float]], y_train: Sequence[str]
) -> tuple[npt.NDArray[np.float64], npt.NDArray[np.str_]]:
    """Typed façade over `imblearn.pipeline.Pipeline.fit_resample` -- imbalanced-learn ships no type stubs."""
    pipeline = ImbPipeline(steps)  # pyright: ignore[reportUnknownArgumentType]
    x_arr = np.asarray(x_train, dtype=np.float64)
    y_arr = np.asarray(y_train, dtype=np.str_)
    x_resampled, y_resampled = pipeline.fit_resample(  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        x_arr, y_arr
    )
    return (
        np.asarray(x_resampled, dtype=np.float64),  # pyright: ignore[reportUnknownArgumentType]
        np.asarray(y_resampled, dtype=np.str_),  # pyright: ignore[reportUnknownArgumentType]
    )
