"""CLI: train the LightGBM known-attack classifier from a dataset (spec §14, §16).

Run on a **development machine**, not the Pi (spec §4):

    python -m scripts.train.train_lightgbm \\
        --dataset cicids --dataset-path /path/to/cicids2017.csv \\
        --model-version 1.0.0 --output-dir pirewall/ml/artifacts

Use `--dataset unsw` with a UNSW-NB15 training/testing partition CSV
instead. Pass `--placeholder --notes "..."` when training on anything other
than the real dataset (CLAUDE.md labeling honesty) — never omit these for a
model whose evaluation metrics shouldn't be mistaken for real performance.
"""

import argparse
import sys
from pathlib import Path

from pirewall.ml.training.lightgbm_trainer import save_lightgbm_artifact, train_lightgbm
from scripts.train._common import DATASET_CHOICES, load_dataset_or_exit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train the LightGBM known-attack classifier.")
    parser.add_argument("--dataset", choices=DATASET_CHOICES, required=True)
    parser.add_argument("--dataset-path", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("pirewall/ml/artifacts"))
    parser.add_argument("--model-version", required=True)
    parser.add_argument("--num-boost-round", type=int, default=100)
    parser.add_argument("--test-fraction", type=float, default=0.25)
    parser.add_argument(
        "--placeholder",
        action="store_true",
        help="Mark this artifact as NOT trained on real data for real detection use.",
    )
    parser.add_argument("--notes", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    dataset = load_dataset_or_exit(args.dataset, args.dataset_path)
    if dataset is None:
        return 1

    result = train_lightgbm(
        dataset.labeled_flows,
        training_dataset_name=args.dataset,
        model_version=args.model_version,
        is_placeholder=args.placeholder,
        notes=args.notes,
        num_boost_round=args.num_boost_round,
        test_fraction=args.test_fraction,
    )

    model_path = save_lightgbm_artifact(result, args.output_dir)
    print(f"saved model to {model_path}")
    print(f"accuracy={result.accuracy:.4f} macro_f1={result.macro_f1:.4f}")
    print(f"confusion_matrix={result.confusion_matrix}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
