"""`FeatureVector` domain model: valid construction and validation failures."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from pirewall.core.models.feature_vector import FeatureVector

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_valid_feature_vector_constructs() -> None:
    fv = FeatureVector(
        flow_id="flow-1",
        schema_version="1.0.0",
        feature_names=("packet_count", "byte_count"),
        values=(10.0, 1000.0),
        computed_at=NOW,
    )
    assert len(fv.feature_names) == len(fv.values)


def test_mismatched_lengths_rejected() -> None:
    with pytest.raises(ValidationError):
        FeatureVector(
            flow_id="flow-1",
            schema_version="1.0.0",
            feature_names=("packet_count", "byte_count"),
            values=(10.0,),
            computed_at=NOW,
        )


def test_duplicate_feature_names_rejected() -> None:
    with pytest.raises(ValidationError):
        FeatureVector(
            flow_id="flow-1",
            schema_version="1.0.0",
            feature_names=("packet_count", "packet_count"),
            values=(10.0, 20.0),
            computed_at=NOW,
        )


def test_empty_feature_names_rejected() -> None:
    with pytest.raises(ValidationError):
        FeatureVector(
            flow_id="flow-1",
            schema_version="1.0.0",
            feature_names=(),
            values=(),
            computed_at=NOW,
        )
