"""Canonical feature schema: versioning and internal consistency (spec §11, §15)."""

import re

import pytest

from pirewall.features.extractor import extract_features
from pirewall.features.schema import (
    FEATURE_DEFINITIONS,
    FEATURE_NAMES,
    LEGACY_FEATURE_DEFINITIONS,
    LEGACY_FEATURE_NAMES,
    LEGACY_SCHEMA_VERSION,
    PORT_CATEGORY_DESCRIPTIONS,
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
from tests.helpers.flows import make_flow

# Pinned deliberately: a change here is a schema bump, not a refactor.
EXPECTED_V3_NAMES = (
    "duration_seconds",
    "packet_count",
    "forward_packet_count",
    "backward_packet_count",
    "payload_byte_count",
    "forward_payload_byte_count",
    "backward_payload_byte_count",
    "packets_per_second",
    "payload_bytes_per_second",
    "mean_payload_size",
    "std_payload_size",
    "min_payload_size",
    "max_payload_size",
    "mean_inter_arrival_seconds",
    "std_inter_arrival_seconds",
    "min_inter_arrival_seconds",
    "max_inter_arrival_seconds",
    "forward_backward_payload_ratio",
    "destination_port_category",
    "protocol_is_tcp",
    "protocol_is_udp",
    "protocol_is_icmp",
    "protocol_is_other",
)

EXPECTED_V2_NAMES = (
    "duration_seconds",
    "packet_count",
    "forward_packet_count",
    "backward_packet_count",
    "payload_byte_count",
    "forward_payload_byte_count",
    "backward_payload_byte_count",
    "packets_per_second",
    "payload_bytes_per_second",
    "mean_payload_size",
    "std_payload_size",
    "min_payload_size",
    "max_payload_size",
    "mean_inter_arrival_seconds",
    "std_inter_arrival_seconds",
    "min_inter_arrival_seconds",
    "max_inter_arrival_seconds",
    "forward_backward_payload_ratio",
    "destination_port",
    "protocol_is_tcp",
    "protocol_is_udp",
    "protocol_is_icmp",
    "protocol_is_other",
)


def test_schema_version_is_pinned() -> None:
    assert SCHEMA_VERSION == "3.0.0"
    assert LEGACY_SCHEMA_VERSION == "2.0.0"
    assert SUPPORTED_SCHEMA_VERSIONS == ("3.0.0", "2.0.0")


def test_feature_names_are_pinned_per_version() -> None:
    assert FEATURE_NAMES == EXPECTED_V3_NAMES
    assert LEGACY_FEATURE_NAMES == EXPECTED_V2_NAMES
    assert feature_names("3.0.0") == EXPECTED_V3_NAMES
    assert feature_names("2.0.0") == EXPECTED_V2_NAMES


def test_feature_names_match_definitions_order() -> None:
    assert tuple(d.name for d in FEATURE_DEFINITIONS) == FEATURE_NAMES
    assert tuple(d.name for d in LEGACY_FEATURE_DEFINITIONS) == LEGACY_FEATURE_NAMES
    assert feature_definitions("2.0.0") == LEGACY_FEATURE_DEFINITIONS
    assert feature_definitions("3.0.0") == FEATURE_DEFINITIONS


def test_no_duplicate_feature_names() -> None:
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)
    assert len(set(LEGACY_FEATURE_NAMES)) == len(LEGACY_FEATURE_NAMES)


def test_schema_is_non_empty() -> None:
    assert len(FEATURE_NAMES) > 0
    assert len(LEGACY_FEATURE_NAMES) > 0


def test_3_0_0_replaces_raw_port_with_a_coarse_category() -> None:
    """Raw ports are identity/shortcut features (ADDENDUM_4 D3, critique_ml §3)."""
    assert "destination_port" not in FEATURE_NAMES
    assert "destination_port_category" in FEATURE_NAMES
    category = FEATURE_DEFINITIONS[FEATURE_NAMES.index("destination_port_category")]
    assert category.feature_type is FeatureType.CATEGORY
    # 2.0.0 keeps its raw port, because v1 artifacts were trained on it.
    assert "destination_port" in LEGACY_FEATURE_NAMES


def test_no_other_excluded_identity_field_is_a_feature() -> None:
    """IP/MAC/OUI/SNI/app/timestamp fields can never be model inputs."""
    forbidden = re.compile(
        r"mac|oui|ether|hwaddr|vendor|source_ip|destination_ip|sni|server_name|"
        r"application|app_name|user_agent|timestamp|first_seen|last_seen|source_port",
        re.IGNORECASE,
    )
    for name in (*FEATURE_NAMES, *LEGACY_FEATURE_NAMES):
        assert forbidden.search(name) is None, name


def test_no_feature_is_a_mac_address_or_derived_from_one() -> None:
    """MAC is identity, never a model feature (ADDENDUM_4.md D3, CLAUDE.md v2 invariants).

    A vendor prefix (OUI) is the same leak in smaller form: it would teach a
    model which brand of device is "suspicious".
    """
    forbidden = re.compile(r"mac|oui|ether|hwaddr|vendor", re.IGNORECASE)
    leaking = [name for name in (*FEATURE_NAMES, *LEGACY_FEATURE_NAMES) if forbidden.search(name)]
    assert leaking == []


def test_the_extractor_ignores_the_flow_macs() -> None:
    """Two flows that differ only in their MACs produce the identical feature vector."""
    plain = make_flow()
    with_macs = plain.model_copy(
        update={"source_mac": "02:00:00:00:00:20", "destination_mac": "ff:ff:ff:ff:ff:ff"}
    )
    assert extract_features(with_macs).values == extract_features(plain).values


def test_port_category_mapping_is_total_and_documented() -> None:
    assert port_category(None) is PortCategory.NONE
    for port in range(65_536):
        category = port_category(port)
        assert isinstance(category, PortCategory)
        assert category in PORT_CATEGORY_DESCRIPTIONS
    assert set(PORT_CATEGORY_DESCRIPTIONS) == set(PortCategory)


@pytest.mark.parametrize(
    ("port", "expected"),
    [
        (None, PortCategory.NONE),
        (80, PortCategory.WEB),
        (443, PortCategory.WEB),
        (8080, PortCategory.WEB),
        (8443, PortCategory.WEB),
        (53, PortCategory.DNS),
        (22, PortCategory.SSH),
        (25, PortCategory.MAIL),
        (587, PortCategory.MAIL),
        (0, PortCategory.OTHER_WELL_KNOWN),
        (21, PortCategory.OTHER_WELL_KNOWN),
        (123, PortCategory.OTHER_WELL_KNOWN),
        (1023, PortCategory.OTHER_WELL_KNOWN),
        (1024, PortCategory.EPHEMERAL),
        (3389, PortCategory.EPHEMERAL),
        (65535, PortCategory.EPHEMERAL),
    ],
)
def test_port_category_named_buckets_and_boundaries(
    port: int | None, expected: PortCategory
) -> None:
    assert port_category(port) is expected


def test_unknown_schema_version_is_refused() -> None:
    assert not supports_schema_version("1.0.0")
    with pytest.raises(KeyError):
        feature_names("1.0.0")
    assert all(isinstance(d, FeatureDefinition) for d in FEATURE_DEFINITIONS)
