"""Evaluation primitives for phase-19 reports (critique_ml §5, §10).

Pure-Python so the report script does not depend on pandas, and so the
arithmetic behind Table V / Figs 3-5 can be pinned by tests. Nothing here
knows about files, env tags or model artifacts: callers pass score/label
arrays and get numbers back. The score direction matters and is explicit:

* D2 (Isolation Forest) fires *below* its threshold (`lower_is_attack=True`).
* D3 (calibrated LightGBM probability) fires *at or above* (`False`).
"""

import math
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
import numpy.typing as npt

from pirewall.ml.calibration import ThresholdChoice, threshold_for_fpr

__all__ = [
    "AveragePrecision",
    "ReliabilityBin",
    "ScoreSummary",
    "average_precision",
    "expected_alerts_per_day",
    "psi",
    "recall_at_fpr",
    "reliability_bins",
    "roc_auc",
    "score_summary",
]


def _as_float(values: Sequence[float]) -> npt.NDArray[np.float64]:
    return np.asarray(values, dtype=np.float64)


def _as_bool(labels: Sequence[bool]) -> npt.NDArray[np.bool_]:
    return np.asarray(labels, dtype=np.bool_)


def roc_auc(scores: Sequence[float], labels: Sequence[bool]) -> float:
    """Tie-aware area under the ROC curve; 0.5 when one class is absent."""
    values = _as_float(scores)
    positives = _as_bool(labels)
    if len(values) != len(positives):
        raise ValueError("scores and labels must have the same length")
    positive_count = int(positives.sum())
    negative_count = len(values) - positive_count
    if positive_count == 0 or negative_count == 0:
        return 0.5

    order = np.argsort(values, kind="mergesort")
    sorted_values = values[order]
    ranks = np.empty(len(values), dtype=np.float64)
    index = 0
    while index < len(values):
        end = index + 1
        while end < len(values) and sorted_values[end] == sorted_values[index]:
            end += 1
        # Average rank (1-based) for every tied score.
        ranks[order[index:end]] = (index + 1 + end) / 2.0
        index = end
    positive_rank_sum = float(ranks[positives].sum())
    return (positive_rank_sum - positive_count * (positive_count + 1) / 2.0) / (
        positive_count * negative_count
    )


@dataclass(frozen=True, slots=True)
class AveragePrecision:
    """Average precision plus the prevalence it is measured against."""

    value: float
    prevalence: float
    positives: int
    rows: int


def average_precision(scores: Sequence[float], labels: Sequence[bool]) -> AveragePrecision:
    """Step-wise average precision (the PR-AUC used in Table V)."""
    values = _as_float(scores)
    positives = _as_bool(labels)
    if len(values) != len(positives):
        raise ValueError("scores and labels must have the same length")
    positive_count = int(positives.sum())
    if positive_count == 0:
        return AveragePrecision(0.0, 0.0, 0, len(values))

    order = np.argsort(-values, kind="mergesort")
    sorted_positives = positives[order]
    cumulative_true = np.cumsum(sorted_positives)
    cumulative_false = np.cumsum(~sorted_positives)
    precision = cumulative_true / np.maximum(cumulative_true + cumulative_false, 1)
    recall = cumulative_true / positive_count
    # Sum precision over each newly-reached positive; ties contribute once.
    previous_recall = np.concatenate(([0.0], recall[:-1]))
    weights = recall - previous_recall
    return AveragePrecision(
        value=float(np.sum(precision * weights)),
        prevalence=positive_count / len(values),
        positives=positive_count,
        rows=len(values),
    )


@dataclass(frozen=True, slots=True)
class RecallAtFpr:
    """Recall at an operating point chosen on benign scores, plus its resolution."""

    target_fpr: float
    achieved_fpr: float
    threshold: float
    recall: float
    benign_rows: int
    benign_flagged: int
    attack_rows: int
    attack_flagged: int
    resolution: float

    @property
    def resolvable(self) -> bool:
        return self.target_fpr >= self.resolution


def recall_at_fpr(
    benign_scores: Sequence[float],
    attack_scores: Sequence[float],
    target_fpr: float,
    *,
    lower_is_attack: bool,
) -> RecallAtFpr:
    """Threshold on benign scores, then measure attack recall at that threshold."""
    choice = threshold_for_fpr(benign_scores, target_fpr, lower_is_attack=lower_is_attack)
    attack_values = _as_float(attack_scores)
    if lower_is_attack:
        flagged = int(np.sum(attack_values < choice.threshold))
    else:
        flagged = int(np.sum(attack_values >= choice.threshold))
    return RecallAtFpr(
        target_fpr=target_fpr,
        achieved_fpr=choice.achieved_fpr,
        threshold=choice.threshold,
        recall=flagged / len(attack_values) if len(attack_values) else 0.0,
        benign_rows=choice.benign_rows,
        benign_flagged=choice.benign_flagged,
        attack_rows=len(attack_values),
        attack_flagged=flagged,
        resolution=choice.resolution,
    )


def expected_alerts_per_day(choice: ThresholdChoice, benign_flows_per_day: float) -> float:
    """Observed validation FPR (not the target) times the benign flow rate."""
    return choice.achieved_fpr * benign_flows_per_day


@dataclass(frozen=True, slots=True)
class ReliabilityBin:
    lower: float
    upper: float
    rows: int
    positives: int
    mean_score: float
    observed_rate: float


def reliability_bins(
    scores: Sequence[float], labels: Sequence[bool], *, bins: int = 10
) -> tuple[ReliabilityBin, ...]:
    """Equal-width calibration bins in [0, 1] for the D3 reliability diagram.

    Empty bins are omitted rather than drawn as zero, so a sparse validation
    block cannot look perfectly calibrated by accident.
    """
    if bins <= 0:
        raise ValueError("bins must be positive")
    values = np.clip(_as_float(scores), 0.0, 1.0)
    positives = _as_bool(labels)
    if len(values) != len(positives):
        raise ValueError("scores and labels must have the same length")
    result: list[ReliabilityBin] = []
    edges = np.linspace(0.0, 1.0, bins + 1)
    for index in range(bins):
        lower, upper = float(edges[index]), float(edges[index + 1])
        if index + 1 == bins:
            mask = (values >= lower) & (values <= upper)
        else:
            mask = (values >= lower) & (values < upper)
        count = int(mask.sum())
        if count == 0:
            continue
        positives_in_bin = int(positives[mask].sum())
        result.append(
            ReliabilityBin(
                lower=lower,
                upper=upper,
                rows=count,
                positives=positives_in_bin,
                mean_score=float(values[mask].mean()),
                observed_rate=positives_in_bin / count,
            )
        )
    return tuple(result)


def psi(reference: Sequence[float], current: Sequence[float], *, bins: int = 10) -> float:
    """Population stability index between two feature samples.

    Bin edges come from the reference quantiles (ties collapsed); a zero
    share is smoothed with a count-level epsilon so one empty bin cannot
    produce an infinite PSI. PSI > 0.25 is the usual "major shift" line.
    """
    if bins <= 0:
        raise ValueError("bins must be positive")
    reference_values = _as_float(reference)
    current_values = _as_float(current)
    if len(reference_values) == 0 or len(current_values) == 0:
        raise ValueError("PSI needs two non-empty samples")
    quantiles = np.linspace(0.0, 1.0, bins + 1)
    edges = np.unique(np.quantile(reference_values, quantiles))
    if len(edges) < 2:
        return 0.0
    edges[0] = float("-inf")
    edges[-1] = float("inf")
    reference_counts, _ = np.histogram(reference_values, bins=edges)
    current_counts, _ = np.histogram(current_values, bins=edges)
    epsilon = 1.0 / max(len(reference_values), len(current_values), 1)
    reference_share = np.maximum(reference_counts / len(reference_values), epsilon)
    current_share = np.maximum(current_counts / len(current_values), epsilon)
    return float(np.sum((current_share - reference_share) * np.log(current_share / reference_share)))


@dataclass(frozen=True, slots=True)
class ScoreSummary:
    rows: int
    mean: float
    std: float
    minimum: float
    p50: float
    p90: float
    p99: float
    maximum: float


def score_summary(scores: Sequence[float]) -> ScoreSummary:
    values = _as_float(scores)
    if len(values) == 0:
        return ScoreSummary(0, math.nan, math.nan, math.nan, math.nan, math.nan, math.nan, math.nan)
    return ScoreSummary(
        rows=len(values),
        mean=float(values.mean()),
        std=float(values.std(ddof=1)) if len(values) > 1 else 0.0,
        minimum=float(values.min()),
        p50=float(np.quantile(values, 0.5)),
        p90=float(np.quantile(values, 0.9)),
        p99=float(np.quantile(values, 0.99)),
        maximum=float(values.max()),
    )
