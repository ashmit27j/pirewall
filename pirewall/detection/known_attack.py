"""Wraps LightGBM inference into a `KnownEvidence` domain object (spec §14).

The ML layer produces evidence, never commands (CLAUDE.md) — this module's
only output is a `KnownEvidence` instance; it never touches the firewall.
"""

from datetime import datetime

from pirewall.core.models.evidence import KnownEvidence
from pirewall.core.models.feature_vector import FeatureVector
from pirewall.ml.inference.lightgbm_predictor import predict_class_probabilities
from pirewall.ml.inference.loader import LoadedLightGBMModel


def classify(
    model: LoadedLightGBMModel, feature_vector: FeatureVector, generated_at: datetime
) -> KnownEvidence:
    """Run known-attack classification for one flow's features."""
    raw = predict_class_probabilities(model, feature_vector)
    class_mapping = model.metadata.class_mapping
    index_to_label = {index: label for label, index in class_mapping.items()}
    num_class = len(class_mapping)

    if num_class > 2:
        class_probabilities = {index_to_label[i]: float(raw[i]) for i in range(num_class)}
    else:
        positive_probability = float(raw[0])
        class_probabilities = {
            index_to_label[0]: 1.0 - positive_probability,
            index_to_label[1]: positive_probability,
        }

    predicted_class = max(class_probabilities, key=lambda label: class_probabilities[label])
    confidence = class_probabilities[predicted_class]

    return KnownEvidence(
        flow_id=feature_vector.flow_id,
        predicted_class=predicted_class,
        confidence=confidence,
        class_probabilities=class_probabilities,
        model_version=model.metadata.model_version,
        feature_schema_version=model.metadata.feature_schema_version,
        generated_at=generated_at,
    )
