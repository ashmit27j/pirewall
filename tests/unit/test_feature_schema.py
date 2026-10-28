"""Canonical feature schema: versioning and internal consistency (spec §11, §15)."""

import re

from pirewall.features.extractor import extract_features
from pirewall.features.schema import FEATURE_DEFINITIONS, FEATURE_NAMES, SCHEMA_VERSION
from tests.helpers.flows import make_flow


def test_schema_version_is_set() -> None:
    assert SCHEMA_VERSION
    assert isinstance(SCHEMA_VERSION, str)


def test_feature_names_match_definitions_order() -> None:
    assert tuple(d.name for d in FEATURE_DEFINITIONS) == FEATURE_NAMES


def test_no_duplicate_feature_names() -> None:
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)


def test_schema_is_non_empty() -> None:
    assert len(FEATURE_NAMES) > 0


def test_no_feature_is_a_mac_address_or_derived_from_one() -> None:
    """MAC is identity, never a model feature (ADDENDUM_4.md D3, CLAUDE.md v2 invariants).

    A vendor prefix (OUI) is the same leak in smaller form: it would teach a
    model which brand of device is "suspicious".
    """
    forbidden = re.compile(r"mac|oui|ether|hwaddr|vendor", re.IGNORECASE)
    leaking = [name for name in FEATURE_NAMES if forbidden.search(name)]
    assert leaking == []


def test_the_extractor_ignores_the_flow_macs() -> None:
    """Two flows that differ only in their MACs produce the identical feature vector."""
    plain = make_flow()
    with_macs = plain.model_copy(
        update={"source_mac": "02:00:00:00:00:20", "destination_mac": "ff:ff:ff:ff:ff:ff"}
    )
    assert extract_features(with_macs).values == extract_features(plain).values
