"""D2/D3 training on frozen phase-19 splits (critique_ml §4-§5).

The trainer never splits rows itself: it reads `benign_train`,
`benign_validation`, `attack_train` and `attack_validation` from a builder
output, fits on train, and chooses every threshold on validation. The test
blocks are not read here at all; `scripts/train/evaluate_phase19.py` is the
one place that touches them, and it records the read in the dataset ledger.

D2 fits an Isolation Forest on benign training flows only. D3 fits a binary
LightGBM (benign vs attack), isotonically calibrates it on validation, and
adds an optional coarse family head trained on attack training rows.
"""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import numpy.typing as npt
from sklearn.ensemble import IsolationForest

from pirewall.core.enums import ModelType
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.features.schema import SCHEMA_VERSION, feature_names
from pirewall.ml.artifacts.metadata import save_metadata
from pirewall.ml.calibration import IsotonicCalibration, ThresholdChoice, fit_isotonic, threshold_for_fpr
from pirewall.ml.training.dataset import Dataset, DatasetError, SplitTable, input_manifest_hashes
from pirewall.ml.training.metrics import binary_rates

PREPROCESSING_VERSION = "1.0.0"
D2_FILENAME = "isolation_forest_model.joblib"
D3_FILENAME = "lightgbm_model.txt"
FAMILY_FILENAME = "lightgbm_family_model.txt"
SUMMARY_FILENAME = "training_summary.json"

TARGET_FPR = 1e-3
"""Validation per-flow benign false-positive rate the operating points target (critique_ml §5)."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_rows(split: SplitTable, minimum: int = 1) -> None:
    if len(split.rows) < minimum:
        raise DatasetError(f"{split.path}: needs at least {minimum} rows, has {len(split.rows)}")


def _matrix(splits: Sequence[SplitTable], names: Sequence[str]) -> npt.NDArray[np.float64]:
    blocks = [split.matrix(names) for split in splits if split.rows]
    if not blocks:
        return np.empty((0, len(names)), dtype=np.float64)
    return np.vstack(blocks)


def _labels(splits: Sequence[SplitTable]) -> list[str]:
    return [row["label"] for split in splits for row in split.rows]


def _families(splits: Sequence[SplitTable]) -> list[str]:
    return [row["family"] for split in splits for row in split.rows]


def _env_tag(dataset: Dataset) -> str:
    return ",".join(dataset.env_tags) if dataset.env_tags else "unknown"


def _notes(dataset: Dataset) -> str:
    tags = _env_tag(dataset)
    return (
        f"phase-19 model trained on dataset {dataset.dataset_id} (env: {tags}); "
        "not a real-deployment quality result unless every tag is pi-live/pi-scripted"
    )


def _base_metadata(
    dataset: Dataset, *, model_type: ModelType, model_version: str, class_mapping: dict[str, int]
) -> ModelMetadata:
    mock = "mock" in dataset.env_tags
    return ModelMetadata(
        model_type=model_type,
        model_version=model_version,
        training_dataset=f"phase19:{dataset.dataset_id}",
        feature_schema_version=SCHEMA_VERSION,
        feature_ordering=feature_names(SCHEMA_VERSION),
        training_timestamp=datetime.now(UTC),
        class_mapping=class_mapping,
        preprocessing_version=PREPROCESSING_VERSION,
        evaluation_metrics={},
        is_placeholder=mock,
        notes=_notes(dataset),
        env_tag=_env_tag(dataset),
        dataset_id=dataset.dataset_id,
        dataset_manifest_sha256=dataset.manifest_sha256,
        input_manifest_sha256=input_manifest_hashes(dataset),
    )


@dataclass(frozen=True, slots=True)
class D2Result:
    model: IsolationForest
    metadata: ModelMetadata
    threshold: ThresholdChoice


def train_d2(
    dataset: Dataset, *, model_version: str = "3.0.0", seed: int = 42, n_estimators: int = 200
) -> D2Result:
    """Fit an Isolation Forest on the benign training block and threshold on validation."""
    train = dataset.read("benign_train")
    validation = dataset.read("benign_validation")
    _require_rows(train, 2)
    _require_rows(validation, 2)
    names = dataset.names
    x_train = train.matrix(names)
    x_validation = validation.matrix(names)

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination="auto",
        max_samples="auto",
        random_state=seed,
    )
    model.fit(x_train)  # pyright: ignore[reportUnknownMemberType]
    raw_scores = model.decision_function(x_validation)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    scores = [float(value) for value in np.asarray(raw_scores, dtype=np.float64).reshape(-1)]
    choice = threshold_for_fpr(scores, TARGET_FPR, lower_is_attack=True)
    metadata = _base_metadata(
        dataset, model_type=ModelType.ISOLATION_FOREST, model_version=model_version, class_mapping={}
    ).model_copy(
        update={
            "operating_threshold": choice.threshold,
            "operating_threshold_rationale": choice.rationale(lower_is_attack=True),
            "evaluation_metrics": {
                "validation_false_positive_rate": choice.achieved_fpr,
                "validation_rows": float(choice.benign_rows),
            },
        }
    )
    return D2Result(model=model, metadata=metadata, threshold=choice)


def _train_booster(params: dict[str, object], x: npt.NDArray[np.float64], y: Sequence[int]) -> lgb.Booster:
    train_dataset = lgb.Dataset(np.asarray(x, dtype=np.float64), label=list(y))
    return lgb.train(params, train_dataset, num_boost_round=200)  # pyright: ignore[reportUnknownMemberType]


def _predict(booster: lgb.Booster, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
    raw = booster.predict(np.asarray(x, dtype=np.float64))  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    return np.asarray(raw, dtype=np.float64)


@dataclass(frozen=True, slots=True)
class D3Result:
    booster: lgb.Booster
    metadata: ModelMetadata
    threshold: ThresholdChoice
    calibration: IsotonicCalibration
    family_booster: lgb.Booster | None = None
    family_metadata: ModelMetadata | None = None
    split_sizes: dict[str, int] = field(default_factory=dict[str, int])


def train_d3(
    dataset: Dataset,
    *,
    model_version: str = "3.0.0",
    seed: int = 42,
    train_family_head: bool = True,
) -> D3Result:
    """Fit binary LightGBM + isotonic calibration + optional coarse family head.

    Calibration is fitted on the validation block, then the operating
    threshold is the validation benign quantile for `TARGET_FPR`. Both fit
    and threshold see only validation rows; test is untouched.
    """
    benign_train = dataset.read("benign_train")
    attack_train = dataset.read("attack_train")
    benign_validation = dataset.read("benign_validation")
    attack_validation = dataset.read("attack_validation")
    _require_rows(benign_train, 2)
    _require_rows(attack_train, 2)
    _require_rows(benign_validation, 2)
    _require_rows(attack_validation, 2)
    names = dataset.names

    x_train = _matrix((benign_train, attack_train), names)
    y_train = [0] * len(benign_train.rows) + [1] * len(attack_train.rows)
    x_validation = _matrix((benign_validation, attack_validation), names)
    y_validation = [0] * len(benign_validation.rows) + [1] * len(attack_validation.rows)

    params: dict[str, object] = {
        "objective": "binary",
        "metric": "binary_logloss",
        "verbosity": -1,
        "min_data_in_leaf": 20,
        "lambda_l2": 1.0,
        "seed": seed,
        "num_threads": 2,
    }
    booster = _train_booster(params, x_train, y_train)
    raw_validation = _predict(booster, x_validation).reshape(-1)
    calibration = fit_isotonic(
        [float(value) for value in raw_validation],
        [bool(label) for label in y_validation],
    )
    calibrated = calibration.apply_many(raw_validation)
    benign_mask = np.asarray([label == 0 for label in y_validation])
    choice = threshold_for_fpr(
        calibrated[benign_mask].tolist(), TARGET_FPR, lower_is_attack=False
    )
    predicted_attack = calibrated >= choice.threshold
    rates = binary_rates(
        int(np.sum(predicted_attack & ~benign_mask)),
        int(np.sum(predicted_attack & benign_mask)),
        int(np.sum(~predicted_attack & ~benign_mask)),
        int(np.sum(~predicted_attack & benign_mask)),
    )
    metadata = _base_metadata(
        dataset,
        model_type=ModelType.LIGHTGBM,
        model_version=model_version,
        class_mapping={"benign": 0, "attack": 1},
    ).model_copy(
        update={
            "operating_threshold": choice.threshold,
            "operating_threshold_rationale": choice.rationale(lower_is_attack=False),
            "calibration_method": "isotonic",
            "calibration_x": calibration.x,
            "calibration_y": calibration.y,
            "evaluation_metrics": {
                **rates,
                "validation_false_positive_rate": choice.achieved_fpr,
                "validation_rows": float(len(y_validation)),
            },
        }
    )

    family_booster: lgb.Booster | None = None
    family_metadata: ModelMetadata | None = None
    family_labels = [family for family in _families((attack_train,)) if family]
    if train_family_head and len(set(family_labels)) >= 2:
        classes = sorted(set(family_labels))
        mapping = {family: index for index, family in enumerate(classes)}
        family_y = [mapping[family] for family in family_labels]
        family_params: dict[str, object] = {
            "objective": "multiclass",
            "num_class": len(classes),
            "metric": "multi_logloss",
            "verbosity": -1,
            "min_data_in_leaf": 5,
            "lambda_l2": 1.0,
            "seed": seed,
            "num_threads": 2,
        }
        family_booster = _train_booster(family_params, attack_train.matrix(names), family_y)
        family_metadata = _base_metadata(
            dataset, model_type=ModelType.LIGHTGBM, model_version=model_version, class_mapping=mapping
        ).model_copy(
            update={
                "notes": _notes(dataset) + "; coarse family head (cuttable)",
                "evaluation_metrics": {"training_families": float(len(classes))},
            }
        )

    return D3Result(
        booster=booster,
        metadata=metadata,
        threshold=choice,
        calibration=calibration,
        family_booster=family_booster,
        family_metadata=family_metadata,
        split_sizes={
            "train": len(y_train),
            "validation": len(y_validation),
            "benign_train": len(benign_train.rows),
            "attack_train": len(attack_train.rows),
            "benign_validation": len(benign_validation.rows),
            "attack_validation": len(attack_validation.rows),
        },
    )


def _with_artifact_hash(metadata: ModelMetadata, path: Path) -> ModelMetadata:
    return metadata.model_copy(update={"artifact_sha256": _sha256_file(path)})


@dataclass(frozen=True, slots=True)
class SavedArtifacts:
    paths: dict[str, Path]
    summary_path: Path


def save_d2(result: D2Result, output_dir: Path, *, filename: str = D2_FILENAME) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    joblib.dump(result.model, path)  # pyright: ignore[reportUnknownMemberType]
    save_metadata(_with_artifact_hash(result.metadata, path), path)
    return path


def save_d3(result: D3Result, output_dir: Path, *, filename: str = D3_FILENAME) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    path = output_dir / filename
    result.booster.save_model(str(path))
    save_metadata(_with_artifact_hash(result.metadata, path), path)
    paths["lightgbm"] = path
    if result.family_booster is not None and result.family_metadata is not None:
        family_path = output_dir / FAMILY_FILENAME
        result.family_booster.save_model(str(family_path))
        save_metadata(_with_artifact_hash(result.family_metadata, family_path), family_path)
        paths["family"] = family_path
    return paths


def summary_for(
    dataset: Dataset,
    *,
    d2: D2Result | None,
    d3: D3Result | None,
    artifacts: dict[str, Path] | None = None,
) -> dict[str, object]:
    """A JSON-serialisable record of what was trained and on which blocks.

    `artifacts` maps a logical name (`d2`, `lightgbm`, `family`) to the path
    it was saved at; when present, the recorded SHA-256 is read back from the
    file so it is the hash of what actually reached disk.
    """
    saved = artifacts or {}
    hashes = {name: _sha256_file(path) for name, path in saved.items() if path.is_file()}
    payload: dict[str, object] = {
        "tool": "scripts/train/train_phase19.py",
        "created_at": datetime.now(UTC).isoformat(),
        "dataset_id": dataset.dataset_id,
        "dataset_manifest_sha256": dataset.manifest_sha256,
        "feature_schema_version": SCHEMA_VERSION,
        "env_tags": list(dataset.env_tags),
        "target_fpr": TARGET_FPR,
        "splits": {
            name: {
                "sha256": dataset.split_info(name).get("sha256"),
                "rows": dataset.split_info(name).get("rows"),
            }
            for name in (
                "benign_train",
                "benign_validation",
                "attack_train",
                "attack_validation",
            )
        },
    }
    if d2 is not None:
        payload["d2"] = {
            "filename": D2_FILENAME,
            "threshold": d2.threshold.threshold,
            "target_fpr": d2.threshold.target_fpr,
            "achieved_fpr": d2.threshold.achieved_fpr,
            "benign_validation_rows": d2.threshold.benign_rows,
            "benign_validation_flagged": d2.threshold.benign_flagged,
            "resolution": d2.threshold.resolution,
            "rationale": d2.threshold.rationale(lower_is_attack=True),
            "artifact_sha256": hashes.get("d2", d2.metadata.artifact_sha256),
        }
    if d3 is not None:
        payload["d3"] = {
            "filename": D3_FILENAME,
            "threshold": d3.threshold.threshold,
            "target_fpr": d3.threshold.target_fpr,
            "achieved_fpr": d3.threshold.achieved_fpr,
            "benign_validation_rows": d3.threshold.benign_rows,
            "benign_validation_flagged": d3.threshold.benign_flagged,
            "resolution": d3.threshold.resolution,
            "rationale": d3.threshold.rationale(lower_is_attack=False),
            "family_classes": sorted(d3.family_metadata.class_mapping if d3.family_metadata else {}),
            "split_sizes": d3.split_sizes,
            "artifact_sha256": hashes.get("lightgbm", d3.metadata.artifact_sha256),
            "family_artifact_sha256": hashes.get("family"),
        }
    return payload


def write_summary(payload: dict[str, object], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / SUMMARY_FILENAME
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
