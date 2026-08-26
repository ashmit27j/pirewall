"""Shared CLI plumbing for the `scripts/train/` entry points."""

import sys
from pathlib import Path

from pirewall.core.exceptions import DatasetError
from pirewall.ml.preprocessing.cicids_adapter import load_cicids2017
from pirewall.ml.preprocessing.common import DatasetLoadResult
from pirewall.ml.preprocessing.unsw_adapter import load_unsw_nb15

DATASET_CHOICES = ("cicids", "unsw")


def load_dataset_or_exit(dataset: str, path: Path) -> DatasetLoadResult | None:
    """Load `dataset` from `path`, printing a clear, actionable message and returning `None` on failure.

    Never raises — every failure mode (missing file, missing required
    column, zero usable rows) is reported to stderr so a human running this
    from the command line gets a clear, actionable error (spec §12/§13),
    not a stack trace.
    """
    loader = load_cicids2017 if dataset == "cicids" else load_unsw_nb15
    try:
        result = loader(path)
    except DatasetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None

    if result.skipped_rows:
        print(
            f"warning: skipped {result.skipped_rows} row(s): {dict(result.skip_reasons)}",
            file=sys.stderr,
        )
    if not result.labeled_flows:
        print(f"error: no usable rows were loaded from {path}", file=sys.stderr)
        return None

    return result
