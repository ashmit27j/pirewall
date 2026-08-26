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
