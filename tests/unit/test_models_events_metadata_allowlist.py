"""`SecurityEvent`, `ModelMetadata`, and `AllowlistEntry` domain models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from pirewall.core.enums import EventSeverity, ModelType, Protocol, SecurityEventType
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.model_metadata import ModelMetadata

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_valid_security_event_constructs() -> None:
    event = SecurityEvent.model_validate(
        {
            "timestamp": NOW,
            "severity": EventSeverity.WARNING,
            "event_type": SecurityEventType.FIREWALL_BLOCK,
            "subsystem": "firewall.manager",
            "source": "203.0.113.5",
            "destination": "10.0.0.5",
            "protocol": Protocol.TCP,
            "threat_score": 88.0,
            "reason": "repeated failed SSH auth",
        }
    )
    assert event.id


def test_security_event_bad_threat_score_rejected() -> None:
    with pytest.raises(ValidationError):
        SecurityEvent(
            timestamp=NOW,
            severity=EventSeverity.INFO,
            event_type=SecurityEventType.SYSTEM_WARNING,
            subsystem="core",
            threat_score=200.0,
        )


def test_valid_model_metadata_constructs() -> None:
    metadata = ModelMetadata(
        model_type=ModelType.LIGHTGBM,
        model_version="1.0.0",
        training_dataset="CICIDS2017",
        feature_schema_version="1.0.0",
        feature_ordering=("packet_count", "byte_count"),
        training_timestamp=NOW,
        preprocessing_version="1.0.0",
        evaluation_metrics={"accuracy": 0.95},
    )
    assert metadata.is_placeholder is False


def test_placeholder_model_metadata_labeled_explicitly() -> None:
    metadata = ModelMetadata(
        model_type=ModelType.ISOLATION_FOREST,
        model_version="0.0.1-placeholder",
        training_dataset="synthetic_fixture",
        feature_schema_version="1.0.0",
        feature_ordering=("packet_count",),
        training_timestamp=NOW,
        preprocessing_version="1.0.0",
        is_placeholder=True,
        notes="NOT trained on real data — placeholder for pipeline testing",
    )
    assert metadata.is_placeholder is True
    assert "placeholder" in (metadata.notes or "").lower()


def test_model_metadata_empty_feature_ordering_rejected() -> None:
    with pytest.raises(ValidationError):
        ModelMetadata(
            model_type=ModelType.LIGHTGBM,
            model_version="1.0.0",
            training_dataset="CICIDS2017",
            feature_schema_version="1.0.0",
            feature_ordering=(),
            training_timestamp=NOW,
            preprocessing_version="1.0.0",
        )


def test_valid_allowlist_entry_constructs() -> None:
    entry = AllowlistEntry.model_validate(
        {
            "target": "192.168.1.50/32",
            "reason": "Admin PC — never adaptively block",
            "created_at": NOW,
            "created_by": "ashmit",
        }
    )
    assert entry.id


def test_allowlist_entry_ipv6_target_rejected() -> None:
    with pytest.raises(ValidationError):
        AllowlistEntry.model_validate(
            {
                "target": "2001:db8::/128",
                "reason": "n/a",
                "created_at": NOW,
                "created_by": "ashmit",
            }
        )


def test_allowlist_entry_out_of_range_port_rejected() -> None:
    with pytest.raises(ValidationError):
        AllowlistEntry.model_validate(
            {
                "target": "192.168.1.50/32",
                "port": 70000,
                "reason": "n/a",
                "created_at": NOW,
                "created_by": "ashmit",
            }
        )
