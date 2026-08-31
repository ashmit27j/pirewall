"""Runs Isolation Forest inference for one `FeatureVector` (spec §14)."""

import numpy as np

from pirewall.core.models.feature_vector import FeatureVector
from pirewall.ml.inference.common import validate_feature_vector
from pirewall.ml.inference.loader import LoadedIsolationForestModel


def anomaly_score(model: LoadedIsolationForestModel, feature_vector: FeatureVector) -> float:
    """Return the raw anomaly score for one flow's features.

    Follows scikit-learn's own convention: lower (more negative) means more
    anomalous. Interpreting this score against a threshold is the caller's
    job (`pirewall.detection.anomaly`), not this module's.
    """
    validate_feature_vector(feature_vector, model.metadata)
    raw = model.model.decision_function(  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        np.asarray([feature_vector.values], dtype=np.float64)
    )
    return float(np.asarray(raw, dtype=np.float64)[0])  # pyright: ignore[reportUnknownArgumentType]


def anomaly_score_batch(
    model: LoadedIsolationForestModel, feature_vectors: list[FeatureVector]
) -> list[float]:
    """Same as `anomaly_score`, but scores every vector in one `decision_function` call.

    `decision_function`'s cost is almost entirely scikit-learn/Python
    per-call overhead, not tree traversal — measured at ~30.7 ms/call on a
    real Pi 4 regardless of batch size 1 vs. 200
    (`benchmarks/2026-08-30/REPORT.md` §3-4;
    `benchmarks/2026-08-31-anomaly-batching/quick_benchmark.py`). Scoring N
    flows in one call amortizes that fixed cost across all of them instead
    of paying it N times — this is the entire reason batched scoring exists
    (ADDENDUM_2 follow-up pass, section 3). Returns scores in the same
    order as `feature_vectors`.
    """
    if not feature_vectors:
        return []
    for feature_vector in feature_vectors:
        validate_feature_vector(feature_vector, model.metadata)
    raw = model.model.decision_function(  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        np.asarray([fv.values for fv in feature_vectors], dtype=np.float64)
    )
    return [
        float(value)
        for value in np.asarray(raw, dtype=np.float64)  # pyright: ignore[reportUnknownArgumentType, reportUnknownVariableType]
    ]
