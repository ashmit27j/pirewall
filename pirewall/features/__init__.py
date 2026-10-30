"""Canonical feature extraction shared by training and runtime inference (Phase 3)."""

from pirewall.features.extractor import extract_features
from pirewall.features.schema import (
    FEATURE_DEFINITIONS,
    FEATURE_NAMES,
    LEGACY_FEATURE_DEFINITIONS,
    LEGACY_FEATURE_NAMES,
    LEGACY_SCHEMA_VERSION,
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    FeatureDefinition,
    FeatureType,
    PortCategory,
    feature_definitions,
    feature_names,
    port_category,
    supports_schema_version,
)

__all__ = [
    "FEATURE_DEFINITIONS",
    "FEATURE_NAMES",
    "LEGACY_FEATURE_DEFINITIONS",
    "LEGACY_FEATURE_NAMES",
    "LEGACY_SCHEMA_VERSION",
    "SCHEMA_VERSION",
    "SUPPORTED_SCHEMA_VERSIONS",
    "FeatureDefinition",
    "FeatureType",
    "PortCategory",
    "extract_features",
    "feature_definitions",
    "feature_names",
    "port_category",
    "supports_schema_version",
]
