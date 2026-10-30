"""Runs LightGBM inference for one `FeatureVector` (spec §14)."""

import numpy as np
import numpy.typing as npt

from pirewall.core.exceptions import ModelInferenceError
from pirewall.core.models.feature_vector import FeatureVector
from pirewall.ml.calibration import IsotonicCalibration
from pirewall.ml.inference.common import validate_feature_vector
from pirewall.ml.inference.loader import LoadedLightGBMModel


def predict_class_probabilities(
    model: LoadedLightGBMModel, feature_vector: FeatureVector
) -> npt.NDArray[np.float64]:
    """Return LightGBM's class probabilities for one flow's features (one input row).

    Shape `(1, num_class)` for a multiclass model, or `(1,)` holding the
    positive-class probability for a binary model — callers
    (`pirewall.detection.known_attack`) know which based on
    `len(model.metadata.class_mapping)`.

    A phase-19 binary artifact carries an isotonic calibration map and its
    output is calibrated through it here, once, so every caller sees the
    same probability the operating point was chosen on. Multiclass v1
    artifacts carry no calibration and are returned unchanged.
    """
    validate_feature_vector(feature_vector, model.metadata)
    raw = model.booster.predict(  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        np.asarray([feature_vector.values], dtype=np.float64)
    )
    values = np.asarray(raw, dtype=np.float64)
    metadata = model.metadata
    if metadata.calibration_method is None:
        return values
    if metadata.calibration_method != "isotonic":
        raise ModelInferenceError(
            f"model {metadata.model_version} declares unsupported calibration method "
            f"{metadata.calibration_method!r}"
        )
    if len(metadata.class_mapping) > 2:
        raise ModelInferenceError("isotonic calibration is only supported for binary models")
    return IsotonicCalibration(x=metadata.calibration_x, y=metadata.calibration_y).apply_many(values)
