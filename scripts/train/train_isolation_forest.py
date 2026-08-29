"""CLI: train the Isolation Forest anomaly detector from a dataset (spec §14, §16).

Run on a **development machine**, not the Pi (spec §4):

    python -m scripts.train.train_isolation_forest \\
        --dataset cicids --dataset-path /path/to/cicids2017.csv \\
        --model-version 1.0.0 --output-dir pirewall/ml/artifacts

`--dataset-path` accepts more than one file (e.g. all 8 CICIDS2017
"MachineLearningCVE" per-day CSVs) — each is loaded independently through
the adapter and the resulting flows concatenated.

Pass `--placeholder --notes "..."` when training on anything other than the
real dataset (CLAUDE.md labeling honesty).

**Tuning** (imbalance-remediation session): `--contamination` and
`--max-samples` are passed straight through to `sklearn.ensemble.IsolationForest`
("auto" or a number). Pass `--contamination-sweep 0.05,0.1,0.15,0.2` to try
several candidates against the **validation** split first and automatically
use whichever scores highest F1 as `--contamination` for the final run
(reported metrics still come from the untouched test split — see
`pirewall.ml.training.isolation_forest_trainer.sweep_isolation_forest_contamination`).
Training-split-only undersampling of the normal class is on by default
(`--undersample-ceiling`, disable with `--no-resampling`) to keep the
normal-only fit fast on a large corpus.
"""

import argparse
import sys
from pathlib import Path

from pirewall.ml.training.isolation_forest_trainer import (
    save_isolation_forest_artifact,
    sweep_isolation_forest_contamination,
    train_isolation_forest,
)
from pirewall.ml.training.resampling import ResamplingConfig
from scripts.train._common import DATASET_CHOICES, load_dataset_or_exit, make_console_output_encoding_safe


def _parse_contamination(value: str) -> float | str:
    return value if value == "auto" else float(value)


def _parse_max_samples(value: str) -> int | float | str:
    if value == "auto":
        return value
    return float(value) if "." in value else int(value)


def _parse_contamination_candidates(value: str) -> list[float]:
    return [float(item) for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train the Isolation Forest anomaly detector.")
    parser.add_argument("--dataset", choices=DATASET_CHOICES, required=True)
    parser.add_argument("--dataset-path", type=Path, required=True, nargs="+")
    parser.add_argument("--output-dir", type=Path, default=Path("pirewall/ml/artifacts"))
    parser.add_argument("--model-version", required=True)
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--val-fraction", type=float, default=0.15)
    parser.add_argument("--test-fraction", type=float, default=0.15)
    parser.add_argument("--contamination", type=_parse_contamination, default="auto")
    parser.add_argument("--max-samples", type=_parse_max_samples, default="auto")
    parser.add_argument(
        "--contamination-sweep",
        type=_parse_contamination_candidates,
        default=None,
        metavar="C1,C2,...",
        help="Comma-separated contamination candidates to try against the validation split; "
        "the best-F1 candidate is used as --contamination for the final (test-evaluated) run.",
    )
    parser.add_argument(
        "--resampling",
        dest="resampling",
        action="store_true",
        default=True,
        help="Undersample the normal class on the training split before the normal-only fit (default: on).",
    )
    parser.add_argument("--no-resampling", dest="resampling", action="store_false")
    parser.add_argument("--undersample-ceiling", type=int, default=150_000)
    parser.add_argument(
        "--placeholder",
        action="store_true",
        help="Mark this artifact as NOT trained on real data for real detection use.",
    )
    parser.add_argument("--notes", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    make_console_output_encoding_safe()
    args = build_parser().parse_args(argv)

    dataset = load_dataset_or_exit(args.dataset, args.dataset_path)
    if dataset is None:
        return 1

    resampling_config = (
        ResamplingConfig(
            undersample_ceiling=args.undersample_ceiling, oversample_ceiling=0, oversample_target=0
        )
        if args.resampling
        else None
    )

    contamination = args.contamination
    if args.contamination_sweep:
        sweep_results = sweep_isolation_forest_contamination(
            dataset.labeled_flows,
            args.contamination_sweep,
            n_estimators=args.n_estimators,
            max_samples=args.max_samples,
            val_fraction=args.val_fraction,
            test_fraction=args.test_fraction,
            resampling=resampling_config,
        )
        print("contamination_sweep (validation split):")
        best = sweep_results[0]
        best_f1 = 0.0
        for candidate in sweep_results:
            p, r = candidate.precision, candidate.recall
            f1 = (2 * p * r / (p + r)) if (p + r) > 0 else 0.0
            print(
                f"  contamination={candidate.contamination:.4f} precision={p:.4f} recall={r:.4f} "
                f"fpr={candidate.false_positive_rate:.4f} fnr={candidate.false_negative_rate:.4f} f1={f1:.4f}"
            )
            if f1 >= best_f1:
                best_f1 = f1
                best = candidate
        contamination = best.contamination
        print(f"selected contamination={contamination} (highest validation F1={best_f1:.4f})")

    result = train_isolation_forest(
        dataset.labeled_flows,
        training_dataset_name=args.dataset,
        model_version=args.model_version,
        is_placeholder=args.placeholder,
        notes=args.notes,
        n_estimators=args.n_estimators,
        contamination=contamination,
        max_samples=args.max_samples,
        val_fraction=args.val_fraction,
        test_fraction=args.test_fraction,
        resampling=resampling_config,
    )

    model_path = save_isolation_forest_artifact(result, args.output_dir)
    print(f"saved model to {model_path}")
    print(f"split_sizes={result.split_sizes}")
    if result.resampling is not None:
        print(f"resampling_before={result.resampling.before_counts}")
        print(f"resampling_after={result.resampling.after_counts}")
    print(
        f"precision={result.precision:.4f} recall={result.recall:.4f} "
        f"fpr={result.false_positive_rate:.4f} fnr={result.false_negative_rate:.4f}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
