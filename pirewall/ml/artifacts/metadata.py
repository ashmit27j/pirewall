"""`ModelMetadata` (de)serialization — the JSON sidecar every trained artifact ships with (spec §15).

Model files themselves are gitignored (spec §12/§35); this module is what
lets `pirewall.ml.inference` (Phase 5) check a loaded model's feature
schema version against the runtime schema before ever running inference.
"""

from pathlib import Path

from pirewall.core.exceptions import ModelLoadError
from pirewall.core.models.model_metadata import ModelMetadata


def metadata_path_for(model_path: Path) -> Path:
    """The sidecar metadata path for a given model artifact path."""
    return model_path.with_name(model_path.name + ".metadata.json")


def save_metadata(metadata: ModelMetadata, model_path: Path) -> Path:
    """Write `metadata` next to `model_path`. Returns the metadata file's path."""
    path = metadata_path_for(model_path)
    path.write_text(metadata.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_metadata(model_path: Path) -> ModelMetadata:
    """Load the metadata sidecar for `model_path`. Raises `ModelLoadError` if missing/invalid."""
    path = metadata_path_for(model_path)
    if not path.is_file():
        raise ModelLoadError(f"model metadata file not found at {path}")
    try:
        return ModelMetadata.model_validate_json(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ModelLoadError(f"invalid model metadata at {path}: {exc}") from exc
