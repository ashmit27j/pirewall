"""Shared training helpers: canonical feature extraction and a deterministic split.

Every trainer builds its feature matrix by calling
`pirewall.features.extract_features` on the adapters' `Flow` output — never
its own feature math (CLAUDE.md "one canonical feature-extraction module").
"""

import random
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

import numpy as np
import numpy.typing as npt

from pirewall.features.extractor import extract_features
from pirewall.features.schema import FEATURE_NAMES
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


def build_feature_matrix_streaming(
    labeled_flows: Iterable[LabeledFlow], chunk_rows: int = 100_000
) -> tuple[npt.NDArray[np.float64], list[str]]:
    """Stream flows into one contiguous feature array, holding no flow list.

    The memory-safe counterpart to `build_feature_matrix`. Measured on the
    real CICIDS2017 corpus (2,830,628 rows, `docs/ML_DATA_AUDIT.md` §H):

    | representation                        | bytes/row | full corpus |
    |---------------------------------------|-----------|-------------|
    | `LabeledFlow` objects (Pydantic)      |     3,857 |   10.17 GB  |
    | `list[list[float]]`                   |       764 |    2.01 GB  |
    | `float64` numpy array                 |       232 |    0.61 GB  |

    Materialising the flows *and* the list-of-lists peaks near 12.2 GB,
    which does not fit in 8 GB of RAM — the previous full-corpus retrain
    drove 4.2 GB of swap and had to be abandoned. Consuming an iterator and
    writing straight into `float64` blocks keeps only `chunk_rows` flows
    alive at a time, so peak memory is the final array (~0.61 GB) plus one
    chunk.

    `float64` rather than `float32` deliberately: `bytes_per_second` reaches
    2.07e9 in this corpus, beyond float32's ~7 significant digits. The
    memory saved (0.3 GB) is not worth introducing a precision question
    into the one array every model trains on.
    """
    blocks: list[npt.NDArray[np.float64]] = []
    labels: list[str] = []
    buffer = np.empty((chunk_rows, len(FEATURE_NAMES)), dtype=np.float64)
    filled = 0
    for item in labeled_flows:
        buffer[filled] = extract_features(item.flow).values
        labels.append(item.label)
        filled += 1
        if filled == chunk_rows:
            blocks.append(buffer.copy())
            filled = 0
    if filled:
        blocks.append(buffer[:filled].copy())
    if not blocks:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float64), labels
    return np.concatenate(blocks, axis=0), labels


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

    train_idx, val_idx, test_idx = split_indices_train_val_test(
        labels, val_fraction=val_fraction, test_fraction=test_fraction, seed=seed
    )

    def gather(indices: list[int]) -> tuple[list[list[float]], list[str]]:
        return [features[i] for i in indices], [labels[i] for i in indices]

    x_train, y_train = gather(train_idx)
    x_val, y_val = gather(val_idx)
    x_test, y_test = gather(test_idx)
    return ThreeWaySplit(
        x_train=x_train, y_train=y_train, x_val=x_val, y_val=y_val, x_test=x_test, y_test=y_test
    )


def split_indices_train_val_test(
    labels: Sequence[str],
    val_fraction: float = 0.15,
    test_fraction: float = 0.15,
    seed: int = 42,
) -> tuple[list[int], list[int], list[int]]:
    """The split itself, as row indices — the single definition of the partition.

    `split_train_val_test` is a thin wrapper that gathers rows from these
    indices. Callers holding features as a numpy array (the streaming path,
    which cannot afford `list[list[float]]`) index the array with these
    instead, so both paths partition identically for a given seed — there is
    no second copy of the shuffling logic that could drift.
    """
    if val_fraction < 0 or test_fraction < 0 or val_fraction + test_fraction >= 1.0:
        raise ValueError("val_fraction and test_fraction must be >= 0 and sum to < 1.0")

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
    return train_idx, val_idx, test_idx
