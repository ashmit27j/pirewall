"""Trained model artifacts (gitignored) and their metadata sidecar format."""

from pirewall.ml.artifacts.metadata import load_metadata, metadata_path_for, save_metadata

__all__ = ["load_metadata", "metadata_path_for", "save_metadata"]
