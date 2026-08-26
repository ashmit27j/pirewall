"""Canonical feature extraction shared by training and runtime inference (Phase 3)."""

from pirewall.features.extractor import extract_features
from pirewall.features.schema import (
    FEATURE_DEFINITIONS,
    FEATURE_NAMES,
    SCHEMA_VERSION,
    FeatureDefinition,
    FeatureType,
)

__all__ = [
    "FEATURE_DEFINITIONS",
    "FEATURE_NAMES",
    "SCHEMA_VERSION",
    "FeatureDefinition",
    "FeatureType",
    "extract_features",
]
