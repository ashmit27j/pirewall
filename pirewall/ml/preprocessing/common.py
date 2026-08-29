"""Shared types and helpers for dataset adapters (spec §12, §13).

Each adapter's job is to turn one dataset's raw CSV rows into
`pirewall.core.models.Flow` objects the *same* way real traffic produces
them — so that training calls `pirewall.features.extractor.extract_features`
on those `Flow`s, never reimplementing feature math for training data
(CLAUDE.md "one canonical feature-extraction module").
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from pirewall.core.models.flow import Flow

# A fixed anchor for `Flow.first_seen`. Neither dataset's row-level "start
# time" is needed for anything downstream — only the *duration* (last_seen -
# first_seen) feeds feature extraction — so every row is anchored to the
# same synthetic timestamp rather than trying to parse each dataset's own
# (inconsistent, sometimes ambiguous) timestamp format.
SYNTHETIC_EPOCH = datetime(2000, 1, 1, tzinfo=UTC)


class SkipCounter(Protocol):
    """Anything that can record a skipped row, so streaming loaders can report.

    `DatasetLoadResult` satisfies this. Streaming loaders take one of these
    rather than returning a result object, because the whole point of
    streaming is not to accumulate anything per-row.
    """

    def record_skip(self, reason: str) -> None: ...


@dataclass(frozen=True, slots=True)
class LabeledFlow:
    """One canonical training example: a `Flow` plus its ground-truth label."""

    flow: Flow
    label: str


@dataclass(slots=True)
class DatasetLoadResult:
    """Everything one adapter run produced, including what it had to skip.

    `skipped_rows`/`skip_reasons` make missing/invalid-value handling
    visible rather than silent (spec §13) — a caller (or a test) can assert
    on them instead of the drop simply vanishing.
    """

    labeled_flows: list[LabeledFlow] = field(default_factory=list[LabeledFlow])
    skipped_rows: int = 0
    skip_reasons: Counter[str] = field(default_factory=Counter[str])

    def record_skip(self, reason: str) -> None:
        self.skipped_rows += 1
        self.skip_reasons[reason] += 1


def combine_weighted_stats(
    mean_a: float, std_a: float, count_a: float, mean_b: float, std_b: float, count_b: float
) -> tuple[float, float]:
    """Pool two groups' (mean, std, count) into one overall (mean, std).

    Used when a dataset reports a statistic split by direction (e.g.
    forward/backward packet size) but our canonical `Flow` only stores one
    overall value — a standard pooled-variance combination, not an
    invented number.
    """
    total = count_a + count_b
    if total <= 0:
        return 0.0, 0.0
    combined_mean = (count_a * mean_a + count_b * mean_b) / total
    combined_var = (
        count_a * (std_a**2 + (mean_a - combined_mean) ** 2)
        + count_b * (std_b**2 + (mean_b - combined_mean) ** 2)
    ) / total
    return combined_mean, combined_var**0.5


def parse_float(row: dict[str, str], column: str) -> float:
    """Parse `row[column]` as a float, raising `ValueError` on any failure.

    Callers catch `ValueError` per-row to implement the "skip and count"
    strategy for missing/invalid values (spec §13) without letting one bad
    row silently corrupt the training set with a NaN/garbage feature.
    """
    raw = row.get(column)
    if raw is None or raw.strip() == "":
        raise ValueError(f"missing value for column {column!r}")
    return float(raw)
