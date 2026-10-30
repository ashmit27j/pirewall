"""Evaluate a phase-19 D2/D3 pair on the frozen test blocks, once (critique_ml §5, §10).

The test split is read here and nowhere else. Every read is appended to the
dataset's access ledger; a second evaluation run refuses unless the operator
explicitly passes `--allow-repeat-test-read`, so "touched once" is enforced
by the tool rather than remembered by a human.

Outputs, all carrying the dataset's env tag, are the data behind the paper's
Table V and Figs 3-5 (rendering is phase 20):

    metrics.json                    every number, provenance and caveat
    table_v.csv                     PR-AUC / ROC-AUC / recall at 1e-3/1e-4
    fig3_score_distributions.csv    benign vs attack score summaries + histograms
    fig4_reliability.csv            D3 calibration bins
    fig5_psi.csv                    per-feature train/test PSI
"""

import argparse
import csv
import json
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import numpy.typing as npt

from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.features.schema import SCHEMA_VERSION
from pirewall.ml.calibration import IsotonicCalibration
from pirewall.ml.evaluation import (
    RecallAtFpr,
    average_precision,
    psi,
    recall_at_fpr,
    reliability_bins,
    roc_auc,
    score_summary,
)
from pirewall.ml.inference.loader import (
    load_isolation_forest_model,
    load_lightgbm_model,
)
from pirewall.ml.labels import is_attack_label
from pirewall.ml.training.dataset import Dataset, DatasetError, load_dataset

TEST_SPLITS = (
    "benign_test",
    "attack_test_run_holdout",
    "attack_test_leave_one_tool_out",
    "attack_test_parameter_holdout",
)
TARGET_FPRS = (1e-3, 1e-4)
PSI_MAJOR_SHIFT = 0.25


def _existing_read(dataset: Dataset) -> str | None:
    if not dataset.ledger_path.is_file():
        return None
    for line in dataset.ledger_path.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get("action") == "read" and str(entry.get("purpose", "")).startswith(
            "evaluate_phase19"
        ):
            return str(entry.get("timestamp"))
    return None


def _matrix(rows: list[dict[str, str]], names: tuple[str, ...]) -> npt.NDArray[np.float64]:
    try:
        return np.asarray(
            [[float(row[name]) for name in names] for row in rows], dtype=np.float64
        )
    except (KeyError, ValueError) as exc:
        raise DatasetError(f"test split has a missing or non-numeric feature: {exc}") from exc


def _labels(rows: list[dict[str, str]]) -> npt.NDArray[np.bool_]:
    return np.asarray([is_attack_label(row["label"]) for row in rows], dtype=np.bool_)


def _scores(booster: object, matrix: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
    raw = booster.predict(matrix)  # type: ignore[attr-defined]
    return np.asarray(raw, dtype=np.float64).reshape(-1)


def _calibrated(
    raw: npt.NDArray[np.float64], metadata: ModelMetadata
) -> npt.NDArray[np.float64]:
    method = metadata.calibration_method
    if method is None:
        return raw
    if method != "isotonic":
        raise DatasetError(f"unsupported calibration method {method!r}")
    return IsotonicCalibration(
        x=tuple(metadata.calibration_x), y=tuple(metadata.calibration_y)
    ).apply_many(raw)


def _histogram(scores: npt.NDArray[np.float64], *, bins: int = 20) -> tuple[list[float], list[int]]:
    edges = np.linspace(float(scores.min()), float(scores.max()), bins + 1)
    if edges[0] == edges[-1]:
        return [float(edges[0]), float(edges[-1])], [len(scores)]
    counts, edges = np.histogram(scores, bins=edges)
    return [float(value) for value in edges], [int(value) for value in counts]


def _recall(choice: RecallAtFpr) -> dict[str, object]:
    return {
        "target_fpr": choice.target_fpr,
        "achieved_fpr": choice.achieved_fpr,
        "threshold": choice.threshold,
        "recall": choice.recall,
        "benign_rows": choice.benign_rows,
        "benign_flagged": choice.benign_flagged,
        "attack_rows": choice.attack_rows,
        "attack_flagged": choice.attack_flagged,
        "resolution": choice.resolution,
        "resolvable": choice.resolvable,
    }


def _model_metrics(
    *,
    scores: npt.NDArray[np.float64],
    labels: npt.NDArray[np.bool_],
    threshold: float,
    lower_is_attack: bool,
) -> dict[str, object]:
    benign = scores[~labels]
    attack = scores[labels]
    if lower_is_attack:
        benign_flagged = benign < threshold
        attack_flagged = attack < threshold
    else:
        benign_flagged = benign >= threshold
        attack_flagged = attack >= threshold
    return {
        "operating_threshold": threshold,
        "benign_false_positive_rate": float(benign_flagged.mean()) if len(benign) else 0.0,
        "attack_recall": float(attack_flagged.mean()) if len(attack) else 0.0,
        "roc_auc": roc_auc(scores.tolist(), labels.tolist()),
        "average_precision": average_precision(scores.tolist(), labels.tolist()).value,
        "benign_scores": asdict(score_summary(benign.tolist())),
        "attack_scores": asdict(score_summary(attack.tolist())),
        "score_histograms": {
            "benign": dict(zip(("edges", "counts"), _histogram(benign), strict=True)),
            "attack": dict(zip(("edges", "counts"), _histogram(attack), strict=True)),
        },
    }


def _benign_rate_per_day(rows: list[dict[str, str]]) -> float | None:
    stamps = sorted(
        int(row["first_seen_us"]) for row in rows if row.get("first_seen_us", "").isdigit()
    )
    if len(stamps) < 2 or stamps[-1] <= stamps[0]:
        return None
    days = (stamps[-1] - stamps[0]) / 1_000_000 / 86_400
    return len(rows) / days if days > 0 else None


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def evaluate(
    dataset: Dataset,
    *,
    d2_path: Path,
    d3_path: Path,
    output_dir: Path,
    benign_flows_per_day: float | None,
    allow_repeat_test_read: bool,
    purpose: str,
) -> dict[str, object]:
    previous = _existing_read(dataset)
    if previous is not None and not allow_repeat_test_read:
        raise DatasetError(
            f"test blocks were already read at {previous}; pass --allow-repeat-test-read "
            "only if this is a deliberate re-evaluation"
        )

    names = dataset.names
    test_tables = {}
    for name in TEST_SPLITS:
        table = dataset.read(name)
        if table.rows:
            test_tables[name] = table
    dataset.record_access(list(test_tables), purpose=purpose)
    if "benign_test" not in test_tables:
        raise DatasetError("benign_test is empty; there is no test FPR to report")
    attack_tables = [table for name, table in test_tables.items() if name != "benign_test"]
    if not attack_tables:
        raise DatasetError("all attack test blocks are empty; there is no test recall to report")

    benign_rows = test_tables["benign_test"].rows
    attack_rows = [row for table in attack_tables for row in table.rows]
    x_benign = _matrix(benign_rows, names)
    x_attack = _matrix(attack_rows, names)
    y_benign = np.zeros(len(benign_rows), dtype=np.bool_)
    y_attack = np.ones(len(attack_rows), dtype=np.bool_)
    x_all = np.vstack((x_benign, x_attack))
    y_all = np.concatenate((y_benign, y_attack))

    d2 = load_isolation_forest_model(d2_path, expected_schema_version=SCHEMA_VERSION)
    d3 = load_lightgbm_model(d3_path, expected_schema_version=SCHEMA_VERSION)
    if d2.metadata.operating_threshold is None:
        raise DatasetError(f"{d2_path}: metadata has no operating_threshold")
    if d3.metadata.operating_threshold is None:
        raise DatasetError(f"{d3_path}: metadata has no operating_threshold")

    d2_all = np.asarray(
        d2.model.decision_function(x_all), dtype=np.float64  # type: ignore[attr-defined]
    ).reshape(-1)
    d3_raw = _scores(d3.booster, x_all)
    d3_all = _calibrated(d3_raw, d3.metadata)

    rate = benign_flows_per_day
    if rate is None:
        rate = _benign_rate_per_day(benign_rows)

    d2_metrics = _model_metrics(
        scores=d2_all, labels=y_all, threshold=d2.metadata.operating_threshold, lower_is_attack=True
    )
    d3_metrics = _model_metrics(
        scores=d3_all, labels=y_all, threshold=d3.metadata.operating_threshold, lower_is_attack=False
    )
    d2_metrics["recall_at_fpr"] = {
        f"{target:g}": _recall(
            recall_at_fpr(
                d2_all[~y_all].tolist(), d2_all[y_all].tolist(), target, lower_is_attack=True
            )
        )
        for target in TARGET_FPRS
    }
    d3_metrics["recall_at_fpr"] = {
        f"{target:g}": _recall(
            recall_at_fpr(
                d3_all[~y_all].tolist(), d3_all[y_all].tolist(), target, lower_is_attack=False
            )
        )
        for target in TARGET_FPRS
    }
    reliability = reliability_bins(d3_all.tolist(), y_all.tolist())
    d3_metrics["reliability"] = [
        {
            "lower": item.lower,
            "upper": item.upper,
            "rows": item.rows,
            "positives": item.positives,
            "mean_score": item.mean_score,
            "observed_rate": item.observed_rate,
        }
        for item in reliability
    ]

    if rate is not None:
        d2_metrics["benign_flows_per_day"] = rate
        d2_metrics["expected_alerts_per_day"] = (
            float(d2_metrics["benign_false_positive_rate"]) * rate
        )
        d3_metrics["benign_flows_per_day"] = rate
        d3_metrics["expected_alerts_per_day"] = (
            float(d3_metrics["benign_false_positive_rate"]) * rate
        )

    train = dataset.read("benign_train")
    x_train = train.matrix(names)

    psi_values = {
        name: psi(x_train[:, index].tolist(), x_benign[:, index].tolist())
        for index, name in enumerate(names)
        if len(np.unique(x_train[:, index])) > 1
    }

    tags = list(dataset.env_tags)
    reportable = bool(tags) and all(tag.startswith("pi-") for tag in tags)
    metrics: dict[str, object] = {
        "tool": "scripts/train/evaluate_phase19.py",
        "created_at": datetime.now(UTC).isoformat(),
        "feature_schema_version": SCHEMA_VERSION,
        "dataset_id": dataset.dataset_id,
        "dataset_manifest_sha256": dataset.manifest_sha256,
        "env_tags": tags,
        "reportable_as_model_quality": reportable,
        "quality_caveat": (
            "real pi-live/pi-scripted test blocks"
            if reportable
            else "mock/bootstrap data: not a model-quality result"
        ),
        "test_splits": {
            name: {
                "sha256": table.sha256,
                "rows": len(table.rows),
                "env_tags": sorted(set(table.env_tags)),
            }
            for name, table in test_tables.items()
        },
        "test_rows": {"benign": len(benign_rows), "attack": len(attack_rows)},
        "benign_flows_per_day": rate,
        "d2": d2_metrics,
        "d3": d3_metrics,
        "psi": {
            "major_shift_threshold": PSI_MAJOR_SHIFT,
            "values": psi_values,
            "major_shift_features": sorted(
                name for name, value in psi_values.items() if value >= PSI_MAJOR_SHIFT
            ),
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_csv(
        output_dir / "table_v.csv",
        [
            "model",
            "threshold",
            "benign_fpr",
            "attack_recall",
            "average_precision",
            "roc_auc",
            "recall_at_fpr_1e-3",
            "recall_at_fpr_1e-4",
            "expected_alerts_per_day",
            "env_tag",
        ],
        [
            {
                "model": model,
                "threshold": values["operating_threshold"],
                "benign_fpr": values["benign_false_positive_rate"],
                "attack_recall": values["attack_recall"],
                "average_precision": values["average_precision"],
                "roc_auc": values["roc_auc"],
                "recall_at_fpr_1e-3": values["recall_at_fpr"]["0.001"]["recall"],
                "recall_at_fpr_1e-4": values["recall_at_fpr"]["0.0001"]["recall"],
                "expected_alerts_per_day": values.get("expected_alerts_per_day"),
                "env_tag": ",".join(tags),
            }
            for model, values in (("D2", d2_metrics), ("D3", d3_metrics))
        ],
    )
    _write_csv(
        output_dir / "fig3_score_distributions.csv",
        ["model", "class", "rows", "mean", "std", "minimum", "p50", "p90", "p99", "maximum"],
        [
            {"model": model, "class": label, **values[f"{label}_scores"]}
            for model, values in (("D2", d2_metrics), ("D3", d3_metrics))
            for label in ("benign", "attack")
        ],
    )
    _write_csv(
        output_dir / "fig4_reliability.csv",
        ["lower", "upper", "rows", "positives", "mean_score", "observed_rate"],
        d3_metrics["reliability"],
    )
    _write_csv(
        output_dir / "fig5_psi.csv",
        ["feature", "psi", "major_shift"],
        [
            {
                "feature": name,
                "psi": value,
                "major_shift": value >= PSI_MAJOR_SHIFT,
            }
            for name, value in sorted(psi_values.items(), key=lambda item: item[1], reverse=True)
        ],
    )
    return metrics


def _check_audit(path: Path, dataset: Dataset, d3_path: Path) -> str | None:
    """Return a refusal message if the audit did not pass for this dataset/model."""
    try:
        audit = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return f"cannot read audit {path}: {exc}"
    if audit.get("passed") is not True:
        failures = audit.get("failures") or ["audit did not pass"]
        return "shortcut audit blocked the report: " + "; ".join(str(item) for item in failures)
    if str(audit.get("dataset_id")) != dataset.dataset_id:
        return f"audit in {path} is for dataset {audit.get('dataset_id')}, not {dataset.dataset_id}"
    if Path(str(audit.get("model_path"))).resolve() != d3_path.resolve():
        return f"audit in {path} is for model {audit.get('model_path')}, not {d3_path}"
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--d2", type=Path, required=True, help="phase-19 Isolation Forest")
    parser.add_argument("--d3", type=Path, required=True, help="phase-19 LightGBM")
    parser.add_argument("--audit", type=Path, required=True, help="shortcut_audit.py JSON result")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--benign-flows-per-day",
        type=float,
        default=None,
        help="override the benign test block's observed flow rate",
    )
    parser.add_argument("--allow-repeat-test-read", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        dataset = load_dataset(args.dataset)
        refusal = _check_audit(args.audit, dataset, args.d3)
        if refusal is not None:
            print(f"evaluate_phase19: {refusal}", file=sys.stderr)
            return 1
        metrics = evaluate(
            dataset,
            d2_path=args.d2,
            d3_path=args.d3,
            output_dir=args.output_dir,
            benign_flows_per_day=args.benign_flows_per_day,
            allow_repeat_test_read=args.allow_repeat_test_read,
            purpose="evaluate_phase19: until-first-report",
        )
    except (DatasetError, ValueError, OSError) as exc:
        print(f"evaluate_phase19: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"output": str(args.output_dir / "metrics.json"), "env_tags": metrics["env_tags"]},
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
