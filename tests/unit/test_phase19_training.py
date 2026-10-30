"""Phase-19 calibration, frozen-split loading and D2/D3 training (critique_ml §4-§6).

These tests pin the arithmetic the reports depend on. The end-to-end case
trains on a tiny synthetic split, never on real data, and asserts the sidecar
is complete enough for the runtime loader and for a reviewer to reconstruct
the operating point. It is a plumbing test, not a model-quality result.
"""

import csv
import hashlib
import json
import math
from pathlib import Path

import numpy as np
import pytest
from scripts.train import train_phase19

from pirewall.core.exceptions import ModelInferenceError
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.features.schema import SCHEMA_VERSION, feature_names
from pirewall.ml.artifacts.metadata import load_metadata
from pirewall.ml.calibration import (
    IsotonicCalibration,
    expected_alerts_per_day,
    fit_isotonic,
    threshold_for_fpr,
)
from pirewall.ml.inference.loader import (
    load_isolation_forest_model,
    load_lightgbm_model,
)
from pirewall.ml.training import phase19
from pirewall.ml.training.dataset import DatasetError, load_dataset

FEATURES = feature_names(SCHEMA_VERSION)
METADATA_COLUMNS = ("label", "family", "run_id", "source_pcap", "env_tag")
SPLITS = (
    "benign_train",
    "benign_validation",
    "benign_gap",
    "benign_test",
    "attack_train",
    "attack_validation",
    "attack_test_run_holdout",
    "attack_test_leave_one_tool_out",
    "attack_test_parameter_holdout",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rows(
    *,
    count: int,
    attack: bool,
    seed: int,
    family: str = "scan",
    attack_shift: float = 2.0,
    run_id: str | None = None,
) -> list[dict[str, str]]:
    values = np.random.default_rng(seed).normal(size=(count, len(FEATURES)))
    if attack:
        values += attack_shift
    rows: list[dict[str, str]] = []
    for row in values:
        record = {name: f"{value:.9g}" for name, value in zip(FEATURES, row, strict=True)}
        record.update(
            {
                "label": family if attack else "benign",
                "family": family if attack else "",
                "run_id": run_id or f"{'attack' if attack else 'benign'}-{seed}",
                "source_pcap": f"{'attack' if attack else 'benign'}-{seed}.pcap",
                "env_tag": "mock",
            }
        )
        rows.append(record)
    return rows


def _write_split(directory: Path, name: str, rows: list[dict[str, str]]) -> dict[str, object]:
    path = directory / f"{name}.csv"
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=[*FEATURES, *METADATA_COLUMNS])
        writer.writeheader()
        writer.writerows(rows)
    return {"path": path.name, "sha256": _sha256(path), "rows": len(rows), "env_tags": ["mock"]}


def build_frozen_dataset(directory: Path, *, attack_validation: int = 20) -> Path:
    """A tiny builder-shaped dataset on disk; no builder re-split happens here."""
    directory.mkdir(parents=True, exist_ok=True)
    contents = {
        "benign_train": [
            *_rows(count=20, attack=False, seed=1),
            *_rows(count=20, attack=False, seed=11),
        ],
        "benign_validation": _rows(count=20, attack=False, seed=2),
        "benign_gap": [],
        "benign_test": _rows(count=10, attack=False, seed=3),
        "attack_train": [
            *_rows(count=20, attack=True, seed=4, family="scan"),
            *_rows(count=20, attack=True, seed=5, family="flood"),
        ],
        "attack_validation": [
            *_rows(count=attack_validation // 2, attack=True, seed=6, family="scan"),
            *_rows(count=attack_validation // 2, attack=True, seed=7, family="flood"),
        ],
        "attack_test_run_holdout": _rows(count=5, attack=True, seed=8, family="scan"),
        "attack_test_leave_one_tool_out": _rows(count=5, attack=True, seed=9, family="scan"),
        "attack_test_parameter_holdout": _rows(count=5, attack=True, seed=10, family="scan"),
    }
    splits = {name: _write_split(directory, name, contents[name]) for name in SPLITS}
    manifest: dict[str, object] = {
        "dataset_id": "b" * 64,
        "feature_schema_version": SCHEMA_VERSION,
        "feature_names": list(FEATURES),
        "env_tags": ["mock"],
        "splits": splits,
        "inputs": [
            {
                "path": "lab/mock/out",
                "manifest_sha256": "c" * 64,
                "env_tag": "mock",
            }
        ],
        "test_access_ledger": {"path": str(directory / "test_access_ledger.jsonl")},
    }
    (directory / "dataset_manifest.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    return directory


def _rewrite_manifest(directory: Path, manifest: dict[str, object]) -> None:
    (directory / "dataset_manifest.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")


# --------------------------------------------------------------- calibration


def test_isotonic_is_monotonic_and_reproduces_linear_interpolation() -> None:
    calibration = IsotonicCalibration(x=(0.0, 1.0, 2.0), y=(0.0, 0.5, 1.0))
    assert calibration.apply(-1.0) == 0.0
    assert calibration.apply(3.0) == 1.0
    assert calibration.apply(0.5) == pytest.approx(0.25)
    applied = calibration.apply_many([0.0, 0.5, 2.0])
    assert list(applied) == pytest.approx([0.0, 0.25, 1.0])


def test_fitting_isotonic_produces_sorted_monotonic_knots() -> None:
    scores = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
    labels = [False, False, True, False, True, True]

    calibration = fit_isotonic(scores, labels)

    assert list(calibration.x) == sorted(calibration.x)
    assert all(left <= right for left, right in zip(calibration.y, calibration.y[1:], strict=False))
    assert all(0.0 <= value <= 1.0 for value in calibration.y)


def test_isotonic_refuses_an_empty_or_single_class_block() -> None:
    with pytest.raises(ValueError, match="empty"):
        fit_isotonic([], [])
    with pytest.raises(ValueError, match="both benign and attack"):
        fit_isotonic([0.1, 0.2], [False, False])


def test_lower_is_attack_threshold_flags_at_most_the_target_fraction() -> None:
    benign = [-0.9, -0.8, -0.7, -0.6, -0.5, -0.4, -0.3, -0.2, -0.1, 0.0]

    choice = threshold_for_fpr(benign, 0.2, lower_is_attack=True)

    assert choice.benign_rows == 10
    assert choice.benign_flagged == 2
    assert choice.achieved_fpr == pytest.approx(0.2)
    assert choice.resolution == pytest.approx(0.1)
    assert "below threshold" in choice.rationale(lower_is_attack=True)


def test_a_target_finer_than_one_validation_row_is_reported_not_faked() -> None:
    benign = [-0.9, -0.5, -0.1]

    lower = threshold_for_fpr(benign, 1e-3, lower_is_attack=True)
    higher = threshold_for_fpr(benign, 1e-3, lower_is_attack=False)

    assert lower.benign_flagged == 0
    assert higher.benign_flagged == 0
    assert lower.threshold < min(benign)
    assert higher.threshold > max(benign)
    assert lower.resolution == pytest.approx(1 / 3)
    assert "one validation row" in lower.rationale(lower_is_attack=True)


def test_probability_thresholds_include_ties_and_reject_bad_targets() -> None:
    choice = threshold_for_fpr([0.2, 0.4, 0.6, 0.8], 0.25, lower_is_attack=False)
    assert choice.benign_flagged == 1
    assert choice.achieved_fpr == pytest.approx(0.25)
    assert choice.threshold == pytest.approx(0.8)

    with pytest.raises(ValueError, match="target_fpr"):
        threshold_for_fpr([0.2], 1.0, lower_is_attack=False)
    with pytest.raises(ValueError, match="benign validation rows"):
        threshold_for_fpr([], 0.1, lower_is_attack=False)


def test_expected_alerts_scale_with_flow_rate_and_fpr() -> None:
    assert expected_alerts_per_day(0.001, 50_000) == pytest.approx(50.0)
    assert math.isclose(expected_alerts_per_day(0.0, 10**9), 0.0)


# ------------------------------------------------------------ frozen dataset


def test_frozen_dataset_reads_hash_checked_splits_and_a_records_test_access(
    tmp_path: Path,
) -> None:
    directory = build_frozen_dataset(tmp_path / "dataset")
    dataset = load_dataset(directory)

    assert dataset.dataset_id == "b" * 64
    assert dataset.env_tags == ("mock",)
    assert dataset.split_info("attack_validation")["rows"] == 20
    split = dataset.read("benign_train")
    assert len(split.rows) == 40
    assert split.matrix(FEATURES).shape == (40, len(FEATURES))
    assert split.is_attack() == [False] * 40

    dataset.record_access(["benign_test"], purpose="unit-test")
    ledger = (directory / "test_access_ledger.jsonl").read_text(encoding="utf-8").splitlines()
    entry = json.loads(ledger[-1])
    assert entry["dataset_id"] == "b" * 64
    assert entry["split"] == "benign_test"
    assert entry["sha256"] == dataset.split_info("benign_test")["sha256"]
    assert entry["purpose"] == "unit-test"


def test_a_changed_split_is_refused_instead_of_trained_on(tmp_path: Path) -> None:
    directory = build_frozen_dataset(tmp_path / "dataset")
    dataset = load_dataset(directory)
    path = directory / "benign_train.csv"
    path.write_text(path.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")

    with pytest.raises(DatasetError, match="hash changed"):
        dataset.read("benign_train")


def test_wrong_schema_and_missing_columns_are_refused(tmp_path: Path) -> None:
    directory = build_frozen_dataset(tmp_path / "dataset")
    manifest = json.loads((directory / "dataset_manifest.json").read_text(encoding="utf-8"))
    manifest["feature_schema_version"] = "2.0.0"
    _rewrite_manifest(directory, manifest)
    with pytest.raises(DatasetError, match="phase-19 training needs"):
        load_dataset(directory)

    directory = build_frozen_dataset(tmp_path / "missing")
    manifest = json.loads((directory / "dataset_manifest.json").read_text(encoding="utf-8"))
    path = directory / "benign_train.csv"
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        fieldnames = [name for name in reader.fieldnames or [] if name != "family"]
        rows = [{name: row[name] for name in fieldnames} for row in reader]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    manifest["splits"]["benign_train"]["sha256"] = _sha256(path)
    _rewrite_manifest(directory, manifest)
    with pytest.raises(DatasetError, match="missing required columns"):
        load_dataset(directory).read("benign_train")


# ---------------------------------------------------------------- end to end


def _assert_complete_sidecar(metadata: ModelMetadata, artifact: Path) -> None:
    assert metadata.feature_schema_version == SCHEMA_VERSION
    assert metadata.feature_ordering == FEATURES
    assert metadata.env_tag == "mock"
    assert metadata.dataset_id == "b" * 64
    assert metadata.dataset_manifest_sha256 is not None
    assert metadata.input_manifest_sha256 == {"lab/mock/out": "c" * 64}
    assert metadata.operating_threshold is not None
    assert metadata.operating_threshold_rationale
    assert metadata.artifact_sha256 == _sha256(artifact)
    assert metadata.is_placeholder is True, "mock training must never look like a real result"


def test_mock_training_writes_complete_sidecars_and_the_loader_accepts_them(
    tmp_path: Path,
) -> None:
    directory = build_frozen_dataset(tmp_path / "dataset")
    dataset = load_dataset(directory)
    output = tmp_path / "models"

    d2 = phase19.train_d2(dataset, n_estimators=20)
    d3 = phase19.train_d3(dataset)
    d2_path = phase19.save_d2(d2, output)
    paths = phase19.save_d3(d3, output)
    summary_path = phase19.write_summary(
        phase19.summary_for(dataset, d2=d2, d3=d3, artifacts={"d2": d2_path, **paths}), output
    )

    d2_metadata = load_metadata(d2_path)
    d3_metadata = load_metadata(paths["lightgbm"])
    _assert_complete_sidecar(d2_metadata, d2_path)
    _assert_complete_sidecar(d3_metadata, paths["lightgbm"])
    assert d3_metadata.calibration_method == "isotonic"
    assert d3_metadata.calibration_x
    assert len(d3_metadata.calibration_x) == len(d3_metadata.calibration_y)
    assert d2_metadata.calibration_method is None

    loaded_d2 = load_isolation_forest_model(d2_path, expected_schema_version=SCHEMA_VERSION)
    loaded_d3 = load_lightgbm_model(paths["lightgbm"], expected_schema_version=SCHEMA_VERSION)
    assert loaded_d2.metadata.model_type.value == "isolation_forest"
    assert loaded_d3.metadata.class_mapping == {"benign": 0, "attack": 1}
    with pytest.raises(ModelInferenceError, match=r"requires '2\.0\.0'"):
        load_lightgbm_model(paths["lightgbm"], expected_schema_version="2.0.0")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["env_tags"] == ["mock"]
    assert summary["feature_schema_version"] == SCHEMA_VERSION
    assert summary["d2"]["artifact_sha256"] == _sha256(d2_path)
    assert summary["d3"]["artifact_sha256"] == _sha256(paths["lightgbm"])
    assert summary["d3"]["split_sizes"]["benign_train"] == 40
    assert summary["d3"]["family_classes"] == ["flood", "scan"]
    # Test blocks stay unread by training, so only the builder's own ledger entry exists.
    assert not (directory / "test_access_ledger.jsonl").exists()


def test_training_commands_refuse_a_missing_dataset(tmp_path: Path) -> None:
    exit_code = train_phase19.main(
        ["--dataset", str(tmp_path / "nowhere"), "--output-dir", str(tmp_path / "out")]
    )
    assert exit_code == 2


def test_training_cli_skip_flags_and_seed_are_recorded(tmp_path: Path) -> None:
    directory = build_frozen_dataset(tmp_path / "dataset")
    output = tmp_path / "models"
    exit_code = train_phase19.main(
        [
            "--dataset",
            str(directory),
            "--output-dir",
            str(output),
            "--skip-d2",
            "--no-family-head",
            "--seed",
            "7",
        ]
    )
    assert exit_code == 0
    assert not (output / phase19.D2_FILENAME).exists()
    assert (output / phase19.D3_FILENAME).exists()
    assert not (output / phase19.FAMILY_FILENAME).exists()
    summary = json.loads((output / phase19.SUMMARY_FILENAME).read_text(encoding="utf-8"))
    assert "d2" not in summary
    assert summary["d3"]["family_classes"] == []
