"""Train phase-19 D2/D3 artifacts from a frozen dataset (critique_ml §4-§9).

    python -m scripts.train.train_phase19 --dataset data/phase19/dataset \\
        --output-dir data/phase19/models

Reads only `benign_train`, `benign_validation`, `attack_train` and
`attack_validation`; the test blocks are not touched here. Artifacts carry
the complete phase-19 sidecar (schema, env tag, dataset/manifest hashes,
operating threshold and rationale, calibration points, artifact SHA-256).
"""

import argparse
import json
import sys
from pathlib import Path

from pirewall.ml.training.dataset import DatasetError, load_dataset
from pirewall.ml.training.phase19 import (
    save_d2,
    save_d3,
    summary_for,
    train_d2,
    train_d3,
    write_summary,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dataset", type=Path, required=True, help="build_dataset output directory")
    parser.add_argument("--output-dir", type=Path, default=Path("data/phase19/models"))
    parser.add_argument("--model-version", default="3.0.0")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--skip-d2", action="store_true")
    parser.add_argument("--skip-d3", action="store_true")
    parser.add_argument(
        "--no-family-head",
        action="store_true",
        help="skip the coarse family head (it is the first thing to cut)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        dataset = load_dataset(args.dataset)
        d2 = None if args.skip_d2 else train_d2(dataset, model_version=args.model_version, seed=args.seed)
        d3 = None if args.skip_d3 else train_d3(
            dataset,
            model_version=args.model_version,
            seed=args.seed,
            train_family_head=not args.no_family_head,
        )
        paths: dict[str, str] = {}
        artifacts: dict[str, Path] = {}
        if d2 is not None:
            d2_path = save_d2(d2, args.output_dir)
            paths["d2"] = str(d2_path)
            artifacts["d2"] = d2_path
        if d3 is not None:
            saved = save_d3(d3, args.output_dir)
            paths.update({name: str(path) for name, path in saved.items()})
            artifacts.update(saved)
        summary = summary_for(dataset, d2=d2, d3=d3, artifacts=artifacts)
        summary["artifacts"] = paths
        summary_path = write_summary(summary, args.output_dir)
    except (DatasetError, ValueError, OSError) as exc:
        print(f"train_phase19: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"summary": str(summary_path), "artifacts": paths}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
