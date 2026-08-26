"""Runs LightGBM inference for one `FeatureVector` (spec §14)."""

import numpy as np
import numpy.typing as npt

from pirewall.core.models.feature_vector import FeatureVector
from pirewall.ml.inference.common import validate_feature_vector
from pirewall.ml.inference.loader import LoadedLightGBMModel


def predict_class_probabilities(
    model: LoadedLightGBMModel, feature_vector: FeatureVector
) -> npt.NDArray[np.float64]:
    """Return LightGBM's raw prediction for one flow's features (one input row).

    Shape `(1, num_class)` for a multiclass model, or `(1,)` holding the
    positive-class probability for a binary model — callers
    (`pirewall.detection.known_attack`) know which based on
    `len(model.metadata.class_mapping)`.
    """
    validate_feature_vector(feature_vector, model.metadata)
    raw = model.booster.predict(  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        np.asarray([feature_vector.values], dtype=np.float64)
    )
    return np.asarray(raw, dtype=np.float64)
