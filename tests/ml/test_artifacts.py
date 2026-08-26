"""`pirewall.ml.artifacts.metadata`: save/load round-trip and failure handling (spec §15)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from pirewall.core.enums import ModelType
from pirewall.core.exceptions import ModelLoadError
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.ml.artifacts.metadata import load_metadata, metadata_path_for, save_metadata


def _make_metadata() -> ModelMetadata:
    return ModelMetadata(
        model_type=ModelType.LIGHTGBM,
        model_version="0.0.1-placeholder",
        training_dataset="synthetic_fixture",
        feature_schema_version="1.0.0",
        feature_ordering=("packet_count", "byte_count"),
        training_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        preprocessing_version="1.0.0",
        is_placeholder=True,
        notes="NOT trained on real data — placeholder for pipeline testing",
    )


def test_save_then_load_round_trips(tmp_path: Path) -> None:
    model_path = tmp_path / "model.txt"
    model_path.write_text("fake model bytes", encoding="utf-8")
    metadata = _make_metadata()

    saved_path = save_metadata(metadata, model_path)
    assert saved_path == metadata_path_for(model_path)
    assert saved_path.is_file()

    loaded = load_metadata(model_path)
    assert loaded == metadata


def test_load_missing_metadata_raises_model_load_error(tmp_path: Path) -> None:
    with pytest.raises(ModelLoadError, match="not found"):
        load_metadata(tmp_path / "model.txt")


def test_load_corrupt_metadata_raises_model_load_error(tmp_path: Path) -> None:
    model_path = tmp_path / "model.txt"
    metadata_path = metadata_path_for(model_path)
    metadata_path.write_text("not valid json {{{", encoding="utf-8")

    with pytest.raises(ModelLoadError, match="invalid"):
        load_metadata(model_path)
