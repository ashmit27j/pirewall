"""Wraps Isolation Forest inference into an `AnomalyEvidence` domain object (spec §14).

An anomaly is evidence, not automatically malicious — this module never
decides anything, it only reports the score and a threshold-derived flag.
"""

from datetime import datetime

from pirewall.core.models.evidence import AnomalyEvidence
from pirewall.core.models.feature_vector import FeatureVector
from pirewall.ml.inference.isolation_forest_predictor import anomaly_score as _decision_score
from pirewall.ml.inference.isolation_forest_predictor import (
    anomaly_score_batch as _decision_score_batch,
)
from pirewall.ml.inference.loader import LoadedIsolationForestModel


def detect(
    model: LoadedIsolationForestModel,
    feature_vector: FeatureVector,
    threshold: float,
    generated_at: datetime,
) -> AnomalyEvidence:
    """Score one flow's features for anomalousness against `threshold`.

    `threshold` is `config.detection.anomaly_score_threshold` — passed in
    rather than read here, keeping this module free of config plumbing.
    Follows scikit-learn's convention: a score below `threshold` is flagged
    as anomalous.
    """
    score = _decision_score(model, feature_vector)
    return AnomalyEvidence(
        flow_id=feature_vector.flow_id,
        anomaly_score=score,
        threshold=threshold,
        is_anomaly=score < threshold,
        model_version=model.metadata.model_version,
        feature_schema_version=model.metadata.feature_schema_version,
        generated_at=generated_at,
    )


def detect_batch(
    model: LoadedIsolationForestModel,
    feature_vectors: list[FeatureVector],
    threshold: float,
    generated_at: datetime,
) -> list[AnomalyEvidence]:
    """Batched analogue of `detect`: scores every vector in one Isolation Forest call.

    Returns one `AnomalyEvidence` per input, in the same order. Every field
    is computed exactly the way `detect` computes it for a single flow —
    scoring in a batch changes nothing about the result for any individual
    flow, only how many `decision_function` calls it costs to get there
    (see `anomaly_score_batch`'s docstring; ADDENDUM_2 follow-up pass,
    section 3).
    """
    scores = _decision_score_batch(model, feature_vectors)
    return [
        AnomalyEvidence(
            flow_id=feature_vector.flow_id,
            anomaly_score=score,
            threshold=threshold,
            is_anomaly=score < threshold,
            model_version=model.metadata.model_version,
            feature_schema_version=model.metadata.feature_schema_version,
            generated_at=generated_at,
        )
        for feature_vector, score in zip(feature_vectors, scores, strict=True)
    ]
