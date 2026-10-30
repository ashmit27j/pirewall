"""Loads trained artifacts on the Pi side, refusing a feature-schema mismatch (spec §15).

`load_lightgbm_model`/`load_isolation_forest_model` are the *only* place a
model file is read from disk at runtime — everything downstream
(`pirewall.detection.known_attack`/`anomaly`) works with the returned,
already-validated `Loaded*Model`.

Phase 19 introduced a second frozen schema version. By default these loaders
accept any version this build can compute (2.0.0 for v1, 3.0.0 for v2) and
validate the artifact's ordering against *that* version's frozen list. A
caller that must have one specific version (the v2 runtime asking for the
3.0.0 models) passes `expected_schema_version=...`. Unknown versions are
always refused; the per-call `validate_feature_vector` check still prevents
a vector from one version ever reaching a model trained on another.
"""

from dataclasses import dataclass
from pathlib import Path

import joblib
import lightgbm as lgb
from sklearn.ensemble import IsolationForest

from pirewall.core.exceptions import ModelInferenceError, ModelLoadError
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.features.schema import feature_names, supports_schema_version
from pirewall.ml.artifacts.metadata import load_metadata


def _check_schema_compatibility(
    metadata: ModelMetadata, model_path: Path, expected_schema_version: str | None
) -> None:
    """Raise `ModelInferenceError` if `metadata` doesn't match a supported feature schema.

    This is the "Runtime Feature Schema == Model Feature Schema" gate. The
    artifact's declared version selects the frozen ordering it must match;
    an optional `expected_schema_version` additionally pins the caller's
    requirement (e.g. the v2 pipeline refuses a 2.0.0 artifact).
    """
    version = metadata.feature_schema_version
    if expected_schema_version is not None and version != expected_schema_version:
        raise ModelInferenceError(
            f"model at {model_path} was trained against feature schema {version!r} "
            f"but this caller requires {expected_schema_version!r}; refusing to load"
        )
    if not supports_schema_version(version):
        raise ModelInferenceError(
            f"model at {model_path} declares unknown feature schema {version!r}; "
            "refusing to load"
        )
    expected_ordering = feature_names(version)
    if metadata.feature_ordering != expected_ordering:
        raise ModelInferenceError(
            f"model at {model_path} has a different feature ordering than feature schema "
            f"{version!r} despite matching version strings; refusing to load"
        )


@dataclass(frozen=True, slots=True)
class LoadedLightGBMModel:
    """A LightGBM booster whose feature schema has already been validated against runtime."""

    booster: lgb.Booster
    metadata: ModelMetadata


@dataclass(frozen=True, slots=True)
class LoadedIsolationForestModel:
    """An Isolation Forest whose feature schema has already been validated against runtime."""

    model: IsolationForest
    metadata: ModelMetadata


def load_lightgbm_model(
    model_path: Path, expected_schema_version: str | None = None
) -> LoadedLightGBMModel:
    """Load the LightGBM artifact at `model_path` plus its metadata sidecar.

    Raises `ModelLoadError` if the file/metadata can't be read, or
    `ModelInferenceError` if the model's feature schema is unknown, doesn't
    match `expected_schema_version`, or disagrees with its own ordering —
    no `LoadedLightGBMModel` is ever returned for an unusable or
    incompatible artifact.
    """
    metadata = load_metadata(model_path)
    _check_schema_compatibility(metadata, model_path, expected_schema_version)
    try:
        booster = lgb.Booster(model_file=str(model_path))
    except Exception as exc:
        raise ModelLoadError(f"failed to load LightGBM model from {model_path}: {exc}") from exc
    return LoadedLightGBMModel(booster=booster, metadata=metadata)


def load_isolation_forest_model(
    model_path: Path, expected_schema_version: str | None = None
) -> LoadedIsolationForestModel:
    """Load the Isolation Forest artifact at `model_path` plus its metadata sidecar.

    Same guarantees as `load_lightgbm_model`.
    """
    metadata = load_metadata(model_path)
    _check_schema_compatibility(metadata, model_path, expected_schema_version)
    try:
        model = joblib.load(model_path)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    except Exception as exc:
        raise ModelLoadError(f"failed to load Isolation Forest model from {model_path}: {exc}") from exc
    if not isinstance(model, IsolationForest):
        raise ModelLoadError(f"file at {model_path} did not deserialize to an IsolationForest")
    return LoadedIsolationForestModel(model=model, metadata=metadata)
