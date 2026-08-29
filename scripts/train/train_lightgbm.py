"""CLI: train the LightGBM known-attack classifier from a dataset (spec §14, §16).

Run on a **development machine**, not the Pi (spec §4):

    python -m scripts.train.train_lightgbm \\
        --dataset cicids --dataset-path /path/to/cicids2017.csv \\
        --model-version 1.0.0 --output-dir pirewall/ml/artifacts

`--dataset-path` accepts more than one file (e.g. all 8 CICIDS2017
"MachineLearningCVE" per-day CSVs) — each is loaded independently through
the adapter and the resulting flows concatenated:

    python -m scripts.train.train_lightgbm \\
        --dataset cicids --dataset-path data/cicids2017/*.csv \\
        --model-version 1.0.0 --output-dir pirewall/ml/artifacts

Use `--dataset unsw` with a UNSW-NB15 training/testing partition CSV
instead. Pass `--placeholder --notes "..."` when training on anything other
than the real dataset (CLAUDE.md labeling honesty) — never omit these for a
model whose evaluation metrics shouldn't be mistaken for real performance.

**Class-imbalance handling** (imbalance-remediation session), all default
ON -- training-split-only resampling (`--undersample-ceiling`/
`--oversample-ceiling`/`--oversample-target`, disable with
`--no-resampling`), balanced per-sample class weights (disable with
`--no-class-weighting`), and validation-split PR-curve per-class threshold
tuning (disable with `--no-threshold-tuning`). See
`pirewall.ml.training.resampling`/`pirewall.ml.training.lightgbm_trainer`
for exactly what each does and why -- in short, resampling and weighting
only ever touch the training split, threshold tuning only ever touches
validation, and reported metrics always come from the untouched test split.
"""

import argparse
import sys
from pathlib import Path

from pirewall.ml.training.lightgbm_trainer import save_lightgbm_artifact, train_lightgbm_from_arrays
from pirewall.ml.training.resampling import ResamplingConfig
from scripts.train._common import (
    DATASET_CHOICES,
    make_console_output_encoding_safe,
    stream_feature_matrix_or_exit,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train the LightGBM known-attack classifier.")
    parser.add_argument("--dataset", choices=DATASET_CHOICES, required=True)
    parser.add_argument("--dataset-path", type=Path, required=True, nargs="+")
    parser.add_argument("--output-dir", type=Path, default=Path("pirewall/ml/artifacts"))
    parser.add_argument("--model-version", required=True)
    parser.add_argument("--num-boost-round", type=int, default=100)
    parser.add_argument("--val-fraction", type=float, default=0.15)
    parser.add_argument("--test-fraction", type=float, default=0.15)
    parser.add_argument(
        "--resampling",
        dest="resampling",
        action="store_true",
        default=True,
        help="Undersample the majority class / SMOTE the rarest classes on the training split (default: on).",
    )
    parser.add_argument("--no-resampling", dest="resampling", action="store_false")
    parser.add_argument("--undersample-ceiling", type=int, default=150_000)
    parser.add_argument("--oversample-ceiling", type=int, default=1_600)
    parser.add_argument("--oversample-target", type=int, default=5_000)
    parser.add_argument(
        "--class-weighting",
        dest="class_weighting",
        action="store_true",
        default=True,
        help="Balanced per-sample class weights on the training split (default: on).",
    )
    parser.add_argument("--no-class-weighting", dest="class_weighting", action="store_false")
    parser.add_argument(
        "--threshold-tuning",
        dest="threshold_tuning",
        action="store_true",
        default=True,
        help="Per-class PR-curve decision thresholds from the validation split (default: on).",
    )
    parser.add_argument("--no-threshold-tuning", dest="threshold_tuning", action="store_false")
    parser.add_argument(
        "--exclude-rare-classes",
        dest="exclude_rare_classes",
        action="store_true",
        default=True,
        help=(
            "Withhold classes below pirewall.ml.labels."
            "MIN_SUPERVISED_TRAINING_EXAMPLES from the supervised target "
            "(default: on). Their rows stay in the test split and are "
            "reported separately."
        ),
    )
    parser.add_argument(
        "--no-exclude-rare-classes", dest="exclude_rare_classes", action="store_false"
    )
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

    loaded = stream_feature_matrix_or_exit(args.dataset, args.dataset_path)
    if loaded is None:
        return 1
    features, labels = loaded
    print(f"loaded {features.shape[0]} flows into a {features.dtype} array "
          f"({features.nbytes / 2**20:.0f} MB)")

    resampling_config = (
        ResamplingConfig(
            undersample_ceiling=args.undersample_ceiling,
            oversample_ceiling=args.oversample_ceiling,
            oversample_target=args.oversample_target,
        )
        if args.resampling
        else None
    )

    result = train_lightgbm_from_arrays(
        features,
        labels,
        training_dataset_name=args.dataset,
        model_version=args.model_version,
        is_placeholder=args.placeholder,
        notes=args.notes,
        num_boost_round=args.num_boost_round,
        val_fraction=args.val_fraction,
        test_fraction=args.test_fraction,
        resampling=resampling_config,
        class_weighting=args.class_weighting,
        tune_thresholds=args.threshold_tuning,
        exclude_rare_classes=args.exclude_rare_classes,
    )

    model_path = save_lightgbm_artifact(result, args.output_dir)
    print(f"saved model to {model_path}")
    print(f"split_sizes={result.split_sizes}")
    print(
        f"trained_classes={len(result.class_mapping)} "
        f"excluded_from_training={list(result.excluded_labels)}"
    )
    if result.resampling is not None:
        print(f"resampling_before={result.resampling.before_counts}")
        print(f"resampling_after={result.resampling.after_counts}")
        print(f"undersampled={result.resampling.undersampled_labels}")
        print(f"oversampled={result.resampling.oversampled_labels}")
    print(f"class_weighting_used={result.class_weighting_used}")
    if result.thresholds is not None:
        print(f"thresholds_used={result.thresholds_used}")
        print(f"thresholds={result.thresholds}")
    print(f"accuracy={result.accuracy:.4f} macro_f1={result.macro_f1:.4f}")
    print(f"confusion_matrix={result.confusion_matrix}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
