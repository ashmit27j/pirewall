"""Phase-19 evaluation, shortcut audit and report gating (critique_ml §5-§10).

The arithmetic tests pin the numbers Table V and Figs 3-5 rest on. The
integration tests run the real audit and evaluator over a tiny synthetic
dataset: they prove refusal paths (a leaked feature, a second test read, a
missing audit), not model quality. Every number produced here is mock.
"""

import csv
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pytest
from scripts.train import evaluate_phase19, shortcut_audit

from pirewall.core.models.feature_vector import FeatureVector
from pirewall.features.schema import SCHEMA_VERSION, feature_names
from pirewall.ml.calibration import IsotonicCalibration
from pirewall.ml.evaluation import (
    average_precision,
    psi,
    recall_at_fpr,
    reliability_bins,
    roc_auc,
    score_summary,
)
from pirewall.ml.inference.lightgbm_predictor import predict_class_probabilities
from pirewall.ml.inference.loader import load_lightgbm_model
from pirewall.ml.training import phase19
from pirewall.ml.training.dataset import DatasetError, load_dataset
from tests.unit.test_phase19_training import build_frozen_dataset

FEATURES = feature_names(SCHEMA_VERSION)


# ---------------------------------------------------------- metric arithmetic


def test_roc_auc_handles_perfect_reversed_and_tied_scores() -> None:
    assert roc_auc([0.1, 0.2, 0.8, 0.9], [False, False, True, True]) == pytest.approx(1.0)
    assert roc_auc([0.9, 0.8, 0.2, 0.1], [False, False, True, True]) == pytest.approx(0.0)
    assert roc_auc([0.5, 0.5, 0.5, 0.5], [False, True, False, True]) == pytest.approx(0.5)
    # One class absent: ROC-AUC is undefined, and 0.5 is the honest placeholder.
    assert roc_auc([0.1, 0.2], [False, False]) == pytest.approx(0.5)


def test_average_precision_weights_each_newly_reached_positive() -> None:
    perfect = average_precision([0.9, 0.8, 0.7, 0.6], [True, True, False, False])
    assert perfect.value == pytest.approx(1.0)
    assert perfect.prevalence == pytest.approx(0.5)
    assert perfect.positives == 2
    assert perfect.rows == 4

    interleaved = average_precision([0.9, 0.8, 0.7, 0.6], [True, False, True, False])
    assert interleaved.value == pytest.approx((1.0 + 2 / 3) / 2)

    empty = average_precision([0.1, 0.2], [False, False])
    assert empty.value == 0.0
    assert empty.positives == 0


def test_recall_at_fpr_thresholds_on_benign_and_reports_resolution() -> None:
    benign = [0.1, 0.2, 0.3, 0.4, 0.5]
    attack = [0.6, 0.7, 0.8]

    choice = recall_at_fpr(benign, attack, 0.2, lower_is_attack=False)

    assert choice.threshold == pytest.approx(0.5)
    assert choice.benign_flagged == 1
    assert choice.achieved_fpr == pytest.approx(0.2)
    assert choice.attack_flagged == 3
    assert choice.recall == pytest.approx(1.0)
    assert choice.resolution == pytest.approx(0.2)
    assert choice.resolvable

    finer = recall_at_fpr(benign, attack, 1e-3, lower_is_attack=False)
    assert finer.benign_flagged == 0
    assert finer.threshold > max(benign)
    assert not finer.resolvable


def test_reliability_bins_omit_empty_bins_instead_of_drawing_zero() -> None:
    bins = reliability_bins([0.05, 0.15, 0.15, 0.95], [False, False, True, True], bins=10)

    assert [bin.rows for bin in bins] == [1, 2, 1]
    assert bins[1].mean_score == pytest.approx(0.15)
    assert bins[1].observed_rate == pytest.approx(0.5)
    assert bins[-1].lower == pytest.approx(0.9)


def test_psi_is_zero_for_identical_samples_and_high_for_a_shift() -> None:
    rng = np.random.default_rng(19)
    reference = rng.normal(size=2000).tolist()
    shifted = (rng.normal(size=2000) + 3.0).tolist()

    assert psi(reference, reference) == pytest.approx(0.0, abs=1e-9)
    assert psi(reference, shifted) > 0.25


def test_score_summary_is_population_shape_not_a_probability() -> None:
    summary = score_summary([1.0, 2.0, 3.0])

    assert summary.rows == 3
    assert summary.mean == pytest.approx(2.0)
    assert summary.std == pytest.approx(1.0)
    assert (summary.minimum, summary.p50, summary.maximum) == (1.0, 2.0, 3.0)


# ------------------------------------------------------------- audit gating


def _trained_models(directory: Path, output: Path) -> tuple[Path, dict[str, Path]]:
    dataset = load_dataset(directory)
    d2 = phase19.train_d2(dataset, n_estimators=20)
    d3 = phase19.train_d3(dataset, train_family_head=False)
    return phase19.save_d2(d2, output), phase19.save_d3(d3, output)


def test_the_audit_passes_a_dataset_with_no_single_feature_shortcut(
    tmp_path: Path,
) -> None:
    directory = build_frozen_dataset(tmp_path / "dataset")
    _, paths = _trained_models(directory, tmp_path / "models")

    result = shortcut_audit.audit(load_dataset(directory), paths["lightgbm"])

    assert result["passed"] is True, result["failures"]
    assert result["dataset_id"] == "b" * 64
    assert result["run_capture_separation"]["run"]["groups"] == 2
    assert result["run_capture_separation"]["capture"]["groups"] == 2


def _rewrite_split_feature(
    directory: Path, split: str, feature: str, values: list[tuple[str, str]]
) -> None:
    """Rewrite one feature per source_pcap, then re-pin the split's manifest hash."""
    manifest_path = directory / "dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    path = directory / f"{split}.csv"
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)
    replacement = dict(values)
    for row in rows:
        row[feature] = replacement[row["source_pcap"]]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    manifest["splits"][split]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")


def test_the_audit_fails_and_names_a_feature_that_identifies_the_capture(
    tmp_path: Path,
) -> None:
    directory = build_frozen_dataset(tmp_path / "dataset")
    # One constant value per benign capture cannot be anything but leakage:
    # it has no behavioral meaning and separates captures perfectly.
    _rewrite_split_feature(
        directory,
        "benign_train",
        "duration_seconds",
        [("benign-1.pcap", "1"), ("benign-11.pcap", "2")],
    )
    _, paths = _trained_models(directory, tmp_path / "models")

    result = shortcut_audit.audit(load_dataset(directory), paths["lightgbm"])

    assert result["passed"] is False
    assert any("duration_seconds" in failure for failure in result["failures"])
    assert any("capture" in failure for failure in result["failures"])


def test_audit_cli_writes_the_result_and_exits_non_zero_on_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = build_frozen_dataset(tmp_path / "dataset")
    _rewrite_split_feature(
        directory,
        "benign_train",
        "duration_seconds",
        [("benign-1.pcap", "1"), ("benign-11.pcap", "2")],
    )
    _, paths = _trained_models(directory, tmp_path / "models")
    output = tmp_path / "audit.json"

    exit_code = shortcut_audit.main(
        [
            "--dataset",
            str(directory),
            "--model",
            str(paths["lightgbm"]),
            "--output",
            str(output),
        ]
    )

    assert exit_code == 1
    assert json.loads(output.read_text(encoding="utf-8"))["passed"] is False
    assert "report blocked" in capsys.readouterr().err


# --------------------------------------------------------- evaluator gating


def _write_audit(path: Path, *, passed: bool, dataset_id: str, model_path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "passed": passed,
                "failures": [] if passed else ["duration_seconds: leaked"],
                "dataset_id": dataset_id,
                "model_path": str(model_path),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_evaluate_writes_reportable_data_once_and_refuses_a_second_read(
    tmp_path: Path,
) -> None:
    directory = build_frozen_dataset(tmp_path / "dataset")
    d2_path, paths = _trained_models(directory, tmp_path / "models")
    output = tmp_path / "report"
    dataset = load_dataset(directory)

    metrics = evaluate_phase19.evaluate(
        dataset,
        d2_path=d2_path,
        d3_path=paths["lightgbm"],
        output_dir=output,
        benign_flows_per_day=None,
        allow_repeat_test_read=False,
        purpose="evaluate_phase19: unit-test",
    )

    assert metrics["env_tags"] == ["mock"]
    assert metrics["reportable_as_model_quality"] is False
    assert metrics["test_splits"]["benign_test"]["env_tags"] == ["mock"]
    assert metrics["test_rows"] == {"benign": 10, "attack": 15}
    assert metrics["d2"]["operating_threshold"] is not None
    assert metrics["d3"]["operating_threshold"] is not None
    assert metrics["d3"]["reliability"]
    for name in (
        "metrics.json",
        "table_v.csv",
        "fig3_score_distributions.csv",
        "fig4_reliability.csv",
        "fig5_psi.csv",
    ):
        assert (output / name).is_file()

    with pytest.raises(DatasetError, match="already read"):
        evaluate_phase19.evaluate(
            dataset,
            d2_path=d2_path,
            d3_path=paths["lightgbm"],
            output_dir=tmp_path / "second",
            benign_flows_per_day=None,
            allow_repeat_test_read=False,
            purpose="evaluate_phase19: unit-test",
        )


def test_evaluate_cli_refuses_a_failed_audit_and_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = build_frozen_dataset(tmp_path / "dataset")
    d2_path, paths = _trained_models(directory, tmp_path / "models")
    audit = _write_audit(
        tmp_path / "audit.json", passed=False, dataset_id="b" * 64, model_path=paths["lightgbm"]
    )
    output = tmp_path / "report"

    exit_code = evaluate_phase19.main(
        [
            "--dataset",
            str(directory),
            "--d2",
            str(d2_path),
            "--d3",
            str(paths["lightgbm"]),
            "--audit",
            str(audit),
            "--output-dir",
            str(output),
        ]
    )

    assert exit_code == 1
    assert not output.exists()
    assert "shortcut audit blocked the report" in capsys.readouterr().err


def test_evaluate_cli_refuses_an_audit_from_a_different_model(tmp_path: Path) -> None:
    directory = build_frozen_dataset(tmp_path / "dataset")
    d2_path, paths = _trained_models(directory, tmp_path / "models")
    audit = _write_audit(
        tmp_path / "audit.json",
        passed=True,
        dataset_id="b" * 64,
        model_path=tmp_path / "other-model.txt",
    )

    exit_code = evaluate_phase19.main(
        [
            "--dataset",
            str(directory),
            "--d2",
            str(d2_path),
            "--d3",
            str(paths["lightgbm"]),
            "--audit",
            str(audit),
            "--output-dir",
            str(tmp_path / "report"),
        ]
    )

    assert exit_code == 1
    assert not (tmp_path / "report" / "metrics.json").exists()


# ------------------------------------------------- calibrated inference parity


def test_runtime_predictor_applies_the_same_isotonic_map_as_the_evaluator(
    tmp_path: Path,
) -> None:
    directory = build_frozen_dataset(tmp_path / "dataset")
    _, paths = _trained_models(directory, tmp_path / "models")
    loaded = load_lightgbm_model(paths["lightgbm"], expected_schema_version=SCHEMA_VERSION)
    row = load_dataset(directory).read("benign_validation").rows[0]
    vector = FeatureVector(
        flow_id="parity-1",
        schema_version=SCHEMA_VERSION,
        feature_names=FEATURES,
        values=tuple(float(row[name]) for name in FEATURES),
        computed_at=datetime.now(UTC),
    )

    raw = loaded.booster.predict(np.asarray([vector.values], dtype=np.float64))
    expected = IsotonicCalibration(
        x=loaded.metadata.calibration_x, y=loaded.metadata.calibration_y
    ).apply_many(np.asarray(raw, dtype=np.float64))

    predicted = predict_class_probabilities(loaded, vector)

    assert predicted.shape == expected.shape
    assert predicted[0] == pytest.approx(expected[0])
    assert 0.0 <= predicted[0] <= 1.0
