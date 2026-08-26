"""Loads trained artifacts on the Pi side, refusing a feature-schema mismatch (spec §15).

`load_lightgbm_model`/`load_isolation_forest_model` are the *only* place a
model file is read from disk at runtime — everything downstream
(`pirewall.detection.known_attack`/`anomaly`) works with the returned,
already-validated `Loaded*Model`.
"""

from dataclasses import dataclass
from pathlib import Path

import joblib
import lightgbm as lgb
from sklearn.ensemble import IsolationForest

from pirewall.core.exceptions import ModelInferenceError, ModelLoadError
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.features.schema import FEATURE_NAMES, SCHEMA_VERSION
from pirewall.ml.artifacts.metadata import load_metadata


def _check_schema_compatibility(metadata: ModelMetadata, model_path: Path) -> None:
    """Raise `ModelInferenceError` if `metadata` doesn't match the runtime feature schema (spec §15).

    This is the "Runtime Feature Schema == Model Feature Schema" gate — a
    mismatch here means the rest of this module must never run inference
    against this artifact.
    """
    if metadata.feature_schema_version != SCHEMA_VERSION:
        raise ModelInferenceError(
            f"model at {model_path} was trained against feature schema "
            f"{metadata.feature_schema_version!r} but the runtime schema is "
            f"{SCHEMA_VERSION!r}; refusing to load"
        )
    if metadata.feature_ordering != FEATURE_NAMES:
        raise ModelInferenceError(
            f"model at {model_path} has a different feature ordering than the runtime "
            "schema despite matching version strings; refusing to load"
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


def load_lightgbm_model(model_path: Path) -> LoadedLightGBMModel:
    """Load the LightGBM artifact at `model_path` plus its metadata sidecar.

    Raises `ModelLoadError` if the file/metadata can't be read, or
    `ModelInferenceError` if the model's feature schema doesn't match the
    runtime schema (spec §15) — either way, no `LoadedLightGBMModel` is
    ever returned for an unusable or incompatible artifact.
    """
    metadata = load_metadata(model_path)
    _check_schema_compatibility(metadata, model_path)
    try:
        booster = lgb.Booster(model_file=str(model_path))
    except Exception as exc:
        raise ModelLoadError(f"failed to load LightGBM model from {model_path}: {exc}") from exc
    return LoadedLightGBMModel(booster=booster, metadata=metadata)


def load_isolation_forest_model(model_path: Path) -> LoadedIsolationForestModel:
    """Load the Isolation Forest artifact at `model_path` plus its metadata sidecar.

    Same guarantees as `load_lightgbm_model`.
    """
    metadata = load_metadata(model_path)
    _check_schema_compatibility(metadata, model_path)
    try:
        model = joblib.load(model_path)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    except Exception as exc:
        raise ModelLoadError(f"failed to load Isolation Forest model from {model_path}: {exc}") from exc
    if not isinstance(model, IsolationForest):
        raise ModelLoadError(f"file at {model_path} did not deserialize to an IsolationForest")
    return LoadedIsolationForestModel(model=model, metadata=metadata)
