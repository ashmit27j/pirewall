"""Shared per-call schema guard for runtime inference (spec §15)."""

from pirewall.core.exceptions import ModelInferenceError
from pirewall.core.models.feature_vector import FeatureVector
from pirewall.core.models.model_metadata import ModelMetadata


def validate_feature_vector(feature_vector: FeatureVector, metadata: ModelMetadata) -> None:
    """Raise `ModelInferenceError` if `feature_vector` doesn't match `metadata`'s schema.

    `pirewall.ml.inference.loader` already refuses to load a model whose
    metadata mismatches the runtime schema; this is a second, per-call
    check against the *specific* `FeatureVector` being scored — defense in
    depth against a stale vector reaching inference after a model reload.
    """
    if feature_vector.schema_version != metadata.feature_schema_version:
        raise ModelInferenceError(
            f"feature vector schema {feature_vector.schema_version!r} does not match "
            f"model schema {metadata.feature_schema_version!r}"
        )
    if feature_vector.feature_names != metadata.feature_ordering:
        raise ModelInferenceError("feature vector ordering does not match model feature ordering")
