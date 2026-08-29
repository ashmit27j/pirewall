"""Shared training helpers: canonical feature extraction and a deterministic split.

Every trainer builds its feature matrix by calling
`pirewall.features.extract_features` on the adapters' `Flow` output — never
its own feature math (CLAUDE.md "one canonical feature-extraction module").
"""

import random
from collections.abc import Sequence
from dataclasses import dataclass

from pirewall.features.extractor import extract_features
from pirewall.ml.preprocessing.common import LabeledFlow


def build_feature_matrix(labeled_flows: Sequence[LabeledFlow]) -> tuple[list[list[float]], list[str]]:
    """Turn labeled flows into (X, y) via Phase 3's canonical extractor."""
    features: list[list[float]] = []
    labels: list[str] = []
    for item in labeled_flows:
        vector = extract_features(item.flow)
        features.append(list(vector.values))
        labels.append(item.label)
    return features, labels


@dataclass(frozen=True, slots=True)
class Split:
    """A deterministic train/test partition of a feature matrix."""

    x_train: list[list[float]]
    y_train: list[str]
    x_test: list[list[float]]
    y_test: list[str]


def split_train_test(
    features: Sequence[list[float]],
    labels: Sequence[str],
    test_fraction: float = 0.25,
    seed: int = 42,
) -> Split:
    """Shuffle deterministically (fixed `seed`) and hold out `test_fraction` for evaluation.

    Deliberately a plain stdlib implementation rather than
    `sklearn.model_selection.train_test_split` — scikit-learn ships no
    inline type information, and this operation is simple enough that a
    fully-typed, dependency-free version is clearer than annotating around
    an untyped library boundary.
    """
    count = len(features)
    if count != len(labels):
        raise ValueError("features and labels must have the same length")

    indices = list(range(count))
    random.Random(seed).shuffle(indices)
    test_count = round(count * test_fraction) if count > 1 else 0
    test_indices = set(indices[:test_count])

    x_train: list[list[float]] = []
    y_train: list[str] = []
    x_test: list[list[float]] = []
    y_test: list[str] = []
    for i in range(count):
        if i in test_indices:
            x_test.append(features[i])
            y_test.append(labels[i])
        else:
            x_train.append(features[i])
            y_train.append(labels[i])
    return Split(x_train=x_train, y_train=y_train, x_test=x_test, y_test=y_test)


@dataclass(frozen=True, slots=True)
class ThreeWaySplit:
    """A deterministic, per-class-stratified train/validation/test partition.

    Validation is for threshold/hyperparameter selection; test is the
    once-only holdout for final reported metrics. Never resample or tune
    against `x_test`/`y_test` -- doing so invalidates every metric computed
    from it.
    """

    x_train: list[list[float]]
    y_train: list[str]
    x_val: list[list[float]]
    y_val: list[str]
    x_test: list[list[float]]
    y_test: list[str]


def split_train_val_test(
    features: Sequence[list[float]],
    labels: Sequence[str],
    val_fraction: float = 0.15,
    test_fraction: float = 0.15,
    seed: int = 42,
) -> ThreeWaySplit:
    """Shuffle and partition **per class** into train/validation/test.

    Stratified per class (not a single global shuffle) so a rare class --
    CICIDS2017's Heartbleed has 11 rows total -- still gets some
    representation in validation and test rather than landing entirely in
    one split by chance. Every row goes to exactly one split (a row's
    integer position is disjoint across the three output lists), so there
    is no train/validation/test overlap by construction.
    """
    if val_fraction < 0 or test_fraction < 0 or val_fraction + test_fraction >= 1.0:
        raise ValueError("val_fraction and test_fraction must be >= 0 and sum to < 1.0")
    count = len(features)
    if count != len(labels):
        raise ValueError("features and labels must have the same length")

    by_label: dict[str, list[int]] = {}
    for i, label in enumerate(labels):
        by_label.setdefault(label, []).append(i)

    rng = random.Random(seed)
    train_idx: list[int] = []
    val_idx: list[int] = []
    test_idx: list[int] = []
    for indices in by_label.values():
        shuffled = list(indices)
        rng.shuffle(shuffled)
        n = len(shuffled)
        if n <= 1:
            train_idx.extend(shuffled)
            continue
        n_test = min(round(n * test_fraction), n - 1)
        n_val = min(round(n * val_fraction), n - 1 - n_test)
        test_idx.extend(shuffled[:n_test])
        val_idx.extend(shuffled[n_test : n_test + n_val])
        train_idx.extend(shuffled[n_test + n_val :])

    # Concatenating per-class blocks above leaves each split ordered as
    # [all of class A][all of class B].... A downstream consumer that reads
    # sequentially -- e.g. LightGBM's histogram bin construction, which
    # samples from the front of the dataset -- would then see a training
    # set that looks almost entirely like whichever class comes first
    # (BENIGN, ~1.6M of ~2M CICIDS2017 training rows), producing feature
    # bins that can't resolve other classes' value ranges at all. Shuffle
    # each split's row order (not composition -- membership is already
    # fixed above) so no consumer can observe the class-block structure.
    rng.shuffle(train_idx)
    rng.shuffle(val_idx)
    rng.shuffle(test_idx)

    def gather(indices: list[int]) -> tuple[list[list[float]], list[str]]:
        return [features[i] for i in indices], [labels[i] for i in indices]

    x_train, y_train = gather(train_idx)
    x_val, y_val = gather(val_idx)
    x_test, y_test = gather(test_idx)
    return ThreeWaySplit(
        x_train=x_train, y_train=y_train, x_val=x_val, y_val=y_val, x_test=x_test, y_test=y_test
    )
