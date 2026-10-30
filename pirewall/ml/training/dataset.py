"""Read the frozen split files written by `scripts/dataset/build_dataset.py` (phase 19).

Training and evaluation must never re-split rows: the builder is the only
place splits are made, and every read here re-checks the split's SHA-256
against `dataset_manifest.json`. Reading a test split appends an entry to the
dataset's append-only access ledger, so "touched once" is auditable rather
than a promise in a docstring.
"""

import csv
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import numpy as np
import numpy.typing as npt

from pirewall.features.schema import SCHEMA_VERSION, feature_names
from pirewall.ml.labels import is_attack_label

MANIFEST_NAME = "dataset_manifest.json"
LEDGER_NAME = "test_access_ledger.jsonl"


class DatasetError(Exception):
    """A refusal with an operator-actionable message."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class SplitTable:
    """One split's rows, already checked against the manifest hash."""

    name: str
    path: Path
    sha256: str
    rows: tuple[dict[str, str], ...]

    def column(self, name: str) -> list[str]:
        return [row[name] for row in self.rows]

    @property
    def labels(self) -> list[str]:
        return self.column("label")

    @property
    def families(self) -> list[str]:
        return self.column("family")

    @property
    def run_ids(self) -> list[str]:
        return self.column("run_id")

    @property
    def env_tags(self) -> list[str]:
        return self.column("env_tag")

    def matrix(self, names: Sequence[str]) -> npt.NDArray[np.float64]:
        """The feature matrix in the schema's frozen column order, never the CSV's."""
        try:
            values = [[float(row[name]) for name in names] for row in self.rows]
        except (KeyError, ValueError) as exc:
            raise DatasetError(f"{self.path}: a feature column is missing or not numeric: {exc}") from exc
        return np.asarray(values, dtype=np.float64)

    def is_attack(self) -> list[bool]:
        return [is_attack_label(label) for label in self.labels]


@dataclass(frozen=True, slots=True)
class Dataset:
    """A built dataset: manifest + lazily read, hash-checked splits."""

    directory: Path
    manifest: dict[str, object]
    manifest_sha256: str
    dataset_id: str
    env_tags: tuple[str, ...]
    names: tuple[str, ...]
    ledger_path: Path
    _splits: dict[str, dict[str, object]]

    def split_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._splits))

    def split_info(self, name: str) -> dict[str, object]:
        try:
            return self._splits[name]
        except KeyError as exc:
            raise DatasetError(
                f"{self.directory}: no split {name!r}; have {sorted(self._splits)}"
            ) from exc

    def read(self, name: str) -> SplitTable:
        info = self.split_info(name)
        relative = Path(str(info.get("path", "")))
        path = relative if relative.is_absolute() else self.directory / relative
        expected = str(info.get("sha256", ""))
        if not path.is_file():
            raise DatasetError(f"split {name!r} is missing: {path}")
        actual = _sha256_file(path)
        if actual != expected:
            raise DatasetError(
                f"split {name!r} hash changed: manifest says {expected}, file is {actual}; "
                "rebuild the dataset instead of editing split files"
            )
        with path.open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            fieldnames = reader.fieldnames or []
            required = [*self.names, "label", "family", "run_id", "env_tag"]
            missing = [column for column in required if column not in fieldnames]
            if missing:
                raise DatasetError(f"{path}: missing required columns {missing}")
            rows = tuple(dict(row) for row in reader)
        return SplitTable(name=name, path=path, sha256=actual, rows=rows)

    def record_access(self, split_names: Sequence[str], *, purpose: str) -> None:
        """Append one line per test split read, with its manifest hash and purpose."""
        now = datetime.now(UTC).isoformat()
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with self.ledger_path.open("a", encoding="utf-8", newline="\n") as stream:
            for name in split_names:
                info = self.split_info(name)
                stream.write(
                    json.dumps(
                        {
                            "timestamp": now,
                            "action": "read",
                            "dataset_id": self.dataset_id,
                            "split": name,
                            "sha256": info.get("sha256"),
                            "rows": info.get("rows"),
                            "env_tags": info.get("env_tags", []),
                            "purpose": purpose,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
            stream.flush()


def load_dataset(directory: Path, *, require_schema: str = SCHEMA_VERSION) -> Dataset:
    """Load a builder output directory, refusing an unexpected schema or manifest."""
    manifest_path = directory / MANIFEST_NAME
    if not manifest_path.is_file():
        raise DatasetError(f"{directory}: missing {MANIFEST_NAME}; run scripts/dataset/build_dataset.py")
    payload = manifest_path.read_bytes()
    try:
        manifest = cast(dict[str, object], json.loads(payload))
    except ValueError as exc:
        raise DatasetError(f"{manifest_path}: invalid JSON: {exc}") from exc
    schema = str(manifest.get("feature_schema_version", ""))
    if schema != require_schema:
        raise DatasetError(
            f"{directory}: dataset schema {schema!r}; phase-19 training needs {require_schema!r}"
        )
    names = tuple(str(name) for name in cast(Sequence[object], manifest.get("feature_names", [])))
    if names != feature_names(require_schema):
        raise DatasetError(f"{directory}: feature_names disagree with schema {require_schema}")
    raw_splits = manifest.get("splits")
    if not isinstance(raw_splits, dict) or not raw_splits:
        raise DatasetError(f"{directory}: manifest has no splits")
    splits = {
        str(name): cast(dict[str, object], info)
        for name, info in cast(dict[object, object], raw_splits).items()
        if isinstance(info, dict)
    }
    if not splits:
        raise DatasetError(f"{directory}: manifest has no readable splits")
    tags = tuple(str(tag) for tag in cast(Sequence[object], manifest.get("env_tags", [])))
    ledger = manifest.get("test_access_ledger")
    ledger_path = directory / LEDGER_NAME
    if isinstance(ledger, dict) and ledger.get("path"):
        ledger_path = Path(str(ledger["path"]))
    dataset_id = str(manifest.get("dataset_id", ""))
    if not dataset_id:
        raise DatasetError(f"{directory}: manifest has no dataset_id")
    return Dataset(
        directory=directory,
        manifest=manifest,
        manifest_sha256=hashlib.sha256(payload).hexdigest(),
        dataset_id=dataset_id,
        env_tags=tags,
        names=names,
        ledger_path=ledger_path,
        _splits=splits,
    )


def input_manifest_hashes(dataset: Dataset) -> dict[str, str]:
    """The `{path: sha256}` map recorded in the dataset manifest's `inputs`."""
    hashes: dict[str, str] = {}
    for item in cast(Sequence[object], dataset.manifest.get("inputs", [])):
        if isinstance(item, dict):
            entry = cast(dict[str, object], item)
            hashes[str(entry.get("path", ""))] = str(entry.get("manifest_sha256", ""))
    return hashes
