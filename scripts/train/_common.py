"""Shared CLI plumbing for the `scripts/train/` entry points."""

import io
import sys
from collections import Counter
from collections.abc import Iterator, Sequence
from pathlib import Path

import numpy as np
import numpy.typing as npt

from pirewall.core.exceptions import DatasetError
from pirewall.ml.preprocessing.cicids_adapter import iter_cicids2017, load_cicids2017
from pirewall.ml.preprocessing.common import DatasetLoadResult, LabeledFlow
from pirewall.ml.preprocessing.unsw_adapter import load_unsw_nb15
from pirewall.ml.training.common import build_feature_matrix_streaming

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


def stream_feature_matrix_or_exit(
    dataset: str, paths: Sequence[Path]
) -> tuple[npt.NDArray[np.float64], list[str]] | None:
    """Build the feature array without ever holding every flow in memory.

    The memory-safe alternative to `load_dataset_or_exit` for a full-size
    corpus. Measured on the 8 CICIDS2017 CSVs (2,830,628 rows), holding the
    `LabeledFlow` objects costs ~10.2 GB and peaks near 12.2 GB alongside
    the feature lists — more than an 8 GB machine has, which is why the
    earlier full-corpus retrain had to be abandoned mid-run. Streaming keeps
    only the growing `float64` array (~0.61 GB) plus one chunk of flows.

    Same error contract as `load_dataset_or_exit`: never raises, reports
    every failure to stderr and returns `None`.
    """
    skips = DatasetLoadResult()

    def flows() -> Iterator[LabeledFlow]:
        for path in paths:
            if dataset == "cicids":
                yield from iter_cicids2017(path, skips=skips)
            else:
                # UNSW-NB15 has no streaming adapter yet; it is a single
                # much smaller partition file, so the list path is fine.
                result = load_unsw_nb15(path)
                skips.skipped_rows += result.skipped_rows
                skips.skip_reasons.update(result.skip_reasons)
                yield from result.labeled_flows

    try:
        features, labels = build_feature_matrix_streaming(flows())
    except DatasetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None

    if skips.skipped_rows:
        print(_summarise_skips(skips), file=sys.stderr)
    if not labels:
        print(f"error: no usable rows were loaded from {list(paths)}", file=sys.stderr)
        return None
    return features, labels


def _summarise_skips(skips: DatasetLoadResult, limit: int = 3) -> str:
    """Condense skip reasons into a few lines instead of dumping every message.

    A Pydantic `ValidationError` stringifies to a multi-line message that
    embeds the offending row, so every skipped row produces a *distinct*
    reason key. Printing `dict(skip_reasons)` for CICIDS2017's 115 skips
    emitted ~30 KB of stderr and buried the number that actually matters.
    Group by the first line of each message and show the commonest few.
    """
    grouped: Counter[str] = Counter()
    for reason, count in skips.skip_reasons.items():
        grouped[reason.splitlines()[0].strip()] += count
    lines = [f"warning: skipped {skips.skipped_rows} row(s):"]
    for reason, count in grouped.most_common(limit):
        lines.append(f"  {count:>7} x {reason[:100]}")
    if len(grouped) > limit:
        lines.append(f"  ... and {len(grouped) - limit} further distinct reason(s)")
    return "\n".join(lines)
