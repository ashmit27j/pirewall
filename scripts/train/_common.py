"""Shared CLI plumbing for the `scripts/train/` entry points."""

import io
import sys
from collections.abc import Sequence
from pathlib import Path

from pirewall.core.exceptions import DatasetError
from pirewall.ml.preprocessing.cicids_adapter import load_cicids2017
from pirewall.ml.preprocessing.common import DatasetLoadResult
from pirewall.ml.preprocessing.unsw_adapter import load_unsw_nb15

DATASET_CHOICES = ("cicids", "unsw")


def make_console_output_encoding_safe() -> None:
    """Make stdout/stderr tolerate un-encodable characters instead of crashing.

    Dataset labels are arbitrary external strings (e.g. CICIDS2017 ships a
    mojibake replacement character in some Web Attack labels) -- printing
    them must not crash on a non-UTF-8 console (cp1252 on Windows) after
    training and artifact-saving have already succeeded. A no-op if stdout/
    stderr aren't real `TextIOWrapper`s (e.g. under pytest's capsys).
    """
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="replace")


def load_dataset_or_exit(dataset: str, paths: Sequence[Path]) -> DatasetLoadResult | None:
    """Load `dataset` from one or more `paths`, merging them into one `DatasetLoadResult`.

    CICIDS2017 ships as 8 separate per-day CSVs, each with its own header —
    each file is loaded independently through the adapter (never hand-merged
    as raw CSV rows) and the resulting labeled flows/skip-counts are
    concatenated. Never raises — every failure mode (missing file, missing
    required column, zero usable rows) is reported to stderr so a human
    running this from the command line gets a clear, actionable error (spec
    §12/§13), not a stack trace.
    """
    loader = load_cicids2017 if dataset == "cicids" else load_unsw_nb15
    combined = DatasetLoadResult()
    for path in paths:
        try:
            result = loader(path)
        except DatasetError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return None
        combined.labeled_flows.extend(result.labeled_flows)
        combined.skipped_rows += result.skipped_rows
        combined.skip_reasons.update(result.skip_reasons)

    if combined.skipped_rows:
        print(
            f"warning: skipped {combined.skipped_rows} row(s): {dict(combined.skip_reasons)}",
            file=sys.stderr,
        )
    if not combined.labeled_flows:
        print(f"error: no usable rows were loaded from {list(paths)}", file=sys.stderr)
        return None

    return combined
