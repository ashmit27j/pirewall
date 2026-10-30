"""Shortcut audit for phase-19 D3, run before any metric is reported (critique_ml §6).

Five checks, all computed from the frozen train/validation blocks only (the
test blocks are never read):

1. LightGBM gain importance per feature.
2. A one-feature model per feature: if one feature alone nearly solves the
   task, the full model's number is not evidence of learned behaviour.
3. Permutation importance: shuffle one validation column at a time and
   record the PR-AUC drop.
4. Port-category ablation: train with and without
   `destination_port_category` and compare validation PR-AUC.
5. Run/capture separation on the benign training block: no feature value may
   be almost exclusive to one run or one capture file. This is the check
   that catches a leaked run identifier that is not an explicit dataset
   column. Restricting it to benign rows keeps "this attack produced 64-byte
   datagrams" from being misreported as leakage.

A failed check exits non-zero and names the feature, so no report can be
rendered from an unaudited model. `--force` is deliberately absent.
"""

import argparse
import json
import sys
from pathlib import Path

import lightgbm as lgb
import numpy as np
import numpy.typing as npt

from pirewall.features.schema import SCHEMA_VERSION
from pirewall.ml.evaluation import AveragePrecision, average_precision
from pirewall.ml.inference.loader import load_lightgbm_model
from pirewall.ml.labels import is_attack_label
from pirewall.ml.training.dataset import Dataset, DatasetError, load_dataset

PORT_FEATURE = "destination_port_category"
MAX_SINGLE_FEATURE_AP = 0.98
MAX_EXCLUSIVE_SHARE = 0.95
MIN_RUN_ROWS = 20
MAX_GROUP_ETA = 0.95
PERMUTATION_SEED = 19

_PARAMS: dict[str, object] = {
    "objective": "binary",
    "metric": "binary_logloss",
    "verbosity": -1,
    "min_data_in_leaf": 10,
    "lambda_l2": 1.0,
    "num_threads": 2,
    "seed": PERMUTATION_SEED,
}


def _train(x: npt.NDArray[np.float64], y: npt.NDArray[np.int8]) -> lgb.Booster:
    dataset = lgb.Dataset(x, label=y)
    return lgb.train(_PARAMS, dataset, num_boost_round=40)  # pyright: ignore[reportUnknownMemberType]


def _predict(booster: lgb.Booster, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
    predicted = booster.predict(x)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    return np.asarray(predicted, dtype=np.float64).reshape(-1)


def _eta_squared(values: npt.NDArray[np.float64], groups: list[str]) -> float:
    """Share of a feature's variance explained by group means (correlation ratio)."""
    total = float(np.var(values))
    if total <= 0.0:
        return 0.0
    group_values = np.asarray(groups)
    between = 0.0
    for group in sorted(set(groups)):
        mask = group_values == group
        between += float(mask.sum()) * (float(values[mask].mean()) - float(values.mean())) ** 2
    return float(between / (len(values) * total))


def _exclusive_values(
    values: npt.NDArray[np.float64], groups: list[str], *, minimum_rows: int
) -> list[dict[str, object]]:
    """Values that cover almost one group and appear in no other group."""
    group_values = np.asarray(groups)
    findings: list[dict[str, object]] = []
    for group in sorted(set(groups)):
        mask = group_values == group
        rows = int(mask.sum())
        if rows < minimum_rows:
            continue
        unique, counts = np.unique(values[mask], return_counts=True)
        dominant_index = int(np.argmax(counts))
        share = float(counts[dominant_index] / rows)
        if share < MAX_EXCLUSIVE_SHARE:
            continue
        dominant = float(unique[dominant_index])
        elsewhere = values[~mask]
        if np.any(elsewhere == dominant):
            continue
        findings.append({"group": group, "value": dominant, "share": share, "rows": rows})
    return findings


def audit(dataset: Dataset, model_path: Path) -> dict[str, object]:
    names = dataset.names
    train_splits = (dataset.read("benign_train"), dataset.read("attack_train"))
    validation_splits = (dataset.read("benign_validation"), dataset.read("attack_validation"))
    if any(not split.rows for split in (*train_splits, *validation_splits)):
        raise DatasetError("shortcut audit needs non-empty train and validation blocks")

    x_train = np.vstack([split.matrix(names) for split in train_splits])
    y_train = np.asarray(
        [is_attack_label(row["label"]) for split in train_splits for row in split.rows],
        dtype=np.int8,
    )
    x_validation = np.vstack([split.matrix(names) for split in validation_splits])
    y_validation = np.asarray(
        [is_attack_label(row["label"]) for split in validation_splits for row in split.rows],
        dtype=np.bool_,
    )
    groups = {"run": list(train_splits[0].run_ids), "capture": train_splits[0].column("source_pcap")}
    benign_train_matrix = train_splits[0].matrix(names)

    loaded = load_lightgbm_model(model_path, expected_schema_version=SCHEMA_VERSION)
    booster = loaded.booster
    baseline = average_precision(_predict(booster, x_validation).tolist(), y_validation.tolist())

    importances = np.asarray(booster.feature_importance(importance_type="gain"), dtype=np.float64)
    importance_total = float(importances.sum())
    importance = {
        name: (float(value) / importance_total if importance_total > 0 else 0.0)
        for name, value in zip(names, importances, strict=True)
    }

    single_feature: dict[str, dict[str, object]] = {}
    for index, name in enumerate(names):
        trained = _train(x_train[:, [index]], y_train)
        metrics: AveragePrecision = average_precision(
            _predict(trained, x_validation[:, [index]]).tolist(), y_validation.tolist()
        )
        single_feature[name] = {"average_precision": metrics.value}

    rng = np.random.default_rng(PERMUTATION_SEED)
    permutation: dict[str, dict[str, float]] = {}
    baseline_predictions = _predict(booster, x_validation)
    baseline_ap = average_precision(baseline_predictions.tolist(), y_validation.tolist()).value
    for index, name in enumerate(names):
        shuffled = x_validation.copy()
        shuffled[:, index] = rng.permutation(shuffled[:, index])
        ap = average_precision(_predict(booster, shuffled).tolist(), y_validation.tolist()).value
        permutation[name] = {"average_precision": ap, "drop": baseline_ap - ap}

    port_index = names.index(PORT_FEATURE) if PORT_FEATURE in names else None
    ablation: dict[str, object] = {"feature": PORT_FEATURE, "present": port_index is not None}
    if port_index is not None:
        keep = [index for index in range(len(names)) if index != port_index]
        without = _train(x_train[:, keep], y_train)
        without_ap = average_precision(
            _predict(without, x_validation[:, keep]).tolist(), y_validation.tolist()
        ).value
        ablation.update(
            {
                "with_average_precision": baseline_ap,
                "without_average_precision": without_ap,
                "delta": baseline_ap - without_ap,
            }
        )

    separation: dict[str, dict[str, object]] = {}
    for group_name, group_ids in groups.items():
        group_count = len(set(group_ids))
        if group_count < 2:
            # With one capture (or one run) every value is trivially exclusive
            # to it, so the check says nothing. Record the skip rather than
            # fail a dataset that only had one capture.
            separation[group_name] = {
                "groups": group_count,
                "skipped": "needs at least two groups to separate",
                "eta_squared": {},
                "eta_squared_top": [],
                "exclusive_value_features": {},
            }
            continue
        eta = {
            name: _eta_squared(benign_train_matrix[:, index], group_ids)
            for index, name in enumerate(names)
        }
        exclusive = {
            name: _exclusive_values(
                benign_train_matrix[:, index], group_ids, minimum_rows=MIN_RUN_ROWS
            )
            for index, name in enumerate(names)
        }
        separation[group_name] = {
            "groups": len(set(group_ids)),
            "eta_squared": eta,
            "eta_squared_top": sorted(eta.items(), key=lambda item: item[1], reverse=True)[:5],
            "exclusive_value_features": {
                name: findings for name, findings in exclusive.items() if findings
            },
        }

    failures: list[str] = []
    for name, metrics in single_feature.items():
        value = float(metrics["average_precision"])
        if value >= MAX_SINGLE_FEATURE_AP:
            failures.append(
                f"{name}: one feature alone reaches PR-AUC {value:.4f} on validation "
                f"(>= {MAX_SINGLE_FEATURE_AP})"
            )
    for group_name in ("run", "capture"):
        reported = separation[group_name]
        for name, findings in reported["exclusive_value_features"].items():  # type: ignore[union-attr]
            failures.append(
                f"{name}: value {findings[0]['value']:g} covers "
                f"{findings[0]['share']:.1%} of {findings[0]['group']} and no other "
                f"{group_name}; it identifies that {group_name}"
            )
        for name, value in reported["eta_squared"].items():  # type: ignore[union-attr]
            if float(value) >= MAX_GROUP_ETA:
                failures.append(
                    f"{name}: {float(value):.3f} of its variance is explained by {group_name} id "
                    f"(>= {MAX_GROUP_ETA}); it separates {group_name}s on its own"
                )

    return {
        "tool": "scripts/train/shortcut_audit.py",
        "feature_schema_version": SCHEMA_VERSION,
        "dataset_id": dataset.dataset_id,
        "env_tags": list(dataset.env_tags),
        "model_path": str(model_path),
        "model_version": loaded.metadata.model_version,
        "train_rows": len(y_train),
        "validation_rows": len(y_validation),
        "baseline_average_precision": baseline.value,
        "feature_importance_gain": importance,
        "single_feature_models": single_feature,
        "permutation_importance": permutation,
        "port_category_ablation": ablation,
        "run_capture_separation": separation,
        "thresholds": {
            "max_single_feature_average_precision": MAX_SINGLE_FEATURE_AP,
            "max_exclusive_value_share": MAX_EXCLUSIVE_SHARE,
            "min_run_rows": MIN_RUN_ROWS,
            "max_group_eta_squared": MAX_GROUP_ETA,
        },
        "passed": not failures,
        "failures": failures,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True, help="trained phase-19 LightGBM artifact")
    parser.add_argument("--output", type=Path, required=True, help="JSON audit result")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        dataset = load_dataset(args.dataset)
        result = audit(dataset, args.model)
    except (DatasetError, ValueError, OSError) as exc:
        print(f"shortcut_audit: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not result["passed"]:
        for failure in result["failures"]:  # type: ignore[union-attr]
            print(f"shortcut_audit: FAIL: {failure}", file=sys.stderr)
        print(f"shortcut_audit: report blocked; details in {args.output}", file=sys.stderr)
        return 1
    print(json.dumps({"passed": True, "output": str(args.output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
