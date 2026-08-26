"""Canonical feature schema: versioning and internal consistency (spec §11, §15)."""

from pirewall.features.schema import FEATURE_DEFINITIONS, FEATURE_NAMES, SCHEMA_VERSION


def test_schema_version_is_set() -> None:
    assert SCHEMA_VERSION
    assert isinstance(SCHEMA_VERSION, str)


def test_feature_names_match_definitions_order() -> None:
    assert tuple(d.name for d in FEATURE_DEFINITIONS) == FEATURE_NAMES


def test_no_duplicate_feature_names() -> None:
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)


def test_schema_is_non_empty() -> None:
    assert len(FEATURE_NAMES) > 0
