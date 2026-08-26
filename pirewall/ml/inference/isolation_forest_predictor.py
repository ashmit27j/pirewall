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
