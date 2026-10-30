"""Isotonic calibration and benign-FPR operating points (phase 19, critique_ml §5).

Both D3's probabilities and every model's operating threshold are chosen on
the validation block by *benign false-positive rate*, never by accuracy,
F1 or a probability of 0.5 (critique_ml P5/P7/P8). The functions here are
pure so tests can pin the arithmetic without training a model.
"""

import math
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
import numpy.typing as npt

__all__ = [
    "IsotonicCalibration",
    "ThresholdChoice",
    "expected_alerts_per_day",
    "fit_isotonic",
    "threshold_for_fpr",
]


@dataclass(frozen=True, slots=True)
class IsotonicCalibration:
    """A fitted isotonic map, stored as knots so it survives a JSON sidecar.

    `apply` reproduces `sklearn.isotonic.IsotonicRegression.predict` for
    in-range scores (isotonic prediction is linear between adjacent fitted
    points) and clips out-of-range scores to the end values, exactly like
    `out_of_bounds="clip"`.
    """

    x: tuple[float, ...]
    y: tuple[float, ...]

    def __post_init__(self) -> None:
        if len(self.x) != len(self.y):
            raise ValueError("calibration x and y must have the same length")
        if not self.x:
            raise ValueError("calibration needs at least one knot")
        if tuple(sorted(self.x)) != self.x:
            raise ValueError("calibration knots must be sorted by x")

    def apply(self, score: float) -> float:
        if len(self.x) == 1:
            return min(max(self.y[0], 0.0), 1.0)
        value = float(
            np.interp(
                score,
                np.asarray(self.x, dtype=np.float64),
                np.asarray(self.y, dtype=np.float64),
            )
        )
        return min(max(value, 0.0), 1.0)

    def apply_many(self, scores: npt.ArrayLike) -> npt.NDArray[np.float64]:
        values = np.asarray(scores, dtype=np.float64)
        if len(self.x) == 1:
            return np.clip(np.full(values.shape, self.y[0]), 0.0, 1.0)
        calibrated = np.interp(
            values, np.asarray(self.x, dtype=np.float64), np.asarray(self.y, dtype=np.float64)
        )
        return np.clip(np.asarray(calibrated, dtype=np.float64), 0.0, 1.0)


def fit_isotonic(scores: Sequence[float], labels: Sequence[bool]) -> IsotonicCalibration:
    """Fit an isotonic map from scores to empirical attack frequency.

    Both classes must be present: with one class there is nothing to
    calibrate, and silently returning a constant would hide a broken
    validation block. A caller with a one-class block should skip D3
    calibration instead.
    """
    if len(scores) != len(labels):
        raise ValueError("scores and labels must have the same length")
    if not scores:
        raise ValueError("cannot fit calibration on an empty validation block")
    if len(set(labels)) != 2:
        raise ValueError("calibration needs both benign and attack validation rows")

    from sklearn.isotonic import IsotonicRegression

    unique = sorted({float(score) for score in scores})
    regression = IsotonicRegression(y_min=0.0, y_max=1.0, increasing=True, out_of_bounds="clip")
    regression.fit(np.asarray(scores, dtype=np.float64), np.asarray(labels, dtype=np.int8))
    fitted = regression.predict(np.asarray(unique, dtype=np.float64))
    return IsotonicCalibration(
        x=tuple(float(value) for value in unique),
        y=tuple(float(value) for value in np.clip(fitted, 0.0, 1.0)),
    )


@dataclass(frozen=True, slots=True)
class ThresholdChoice:
    """One operating point and exactly how it was obtained."""

    threshold: float
    target_fpr: float
    achieved_fpr: float
    benign_rows: int
    benign_flagged: int

    @property
    def resolution(self) -> float:
        """Smallest non-zero FPR this validation block can resolve."""
        return 1.0 / self.benign_rows if self.benign_rows else math.inf

    def rationale(self, *, lower_is_attack: bool) -> str:
        direction = "below" if lower_is_attack else "at or above"
        return (
            f"validation benign block: {self.benign_flagged}/{self.benign_rows} flagged "
            f"({self.achieved_fpr:.6g}) {direction} threshold {self.threshold:.6g} "
            f"for target FPR {self.target_fpr:.6g}; one validation row = "
            f"{self.resolution:.6g} FPR"
        )


def threshold_for_fpr(
    benign_scores: Sequence[float], target_fpr: float, *, lower_is_attack: bool
) -> ThresholdChoice:
    """Pick the most permissive threshold that flags at most `target_fpr` of benign rows.

    `lower_is_attack=True` is Isolation Forest's convention (`score <
    threshold` fires); `False` is a calibrated attack probability (`score
    >= threshold` fires). When the target is finer than one validation row
    can resolve, the threshold is placed beyond the most extreme benign
    score, so the achieved FPR is exactly zero and the caller can report the
    block's resolution instead of pretending 1e-3 was measured.
    """
    if not benign_scores:
        raise ValueError("cannot choose an operating point without benign validation rows")
    if not 0.0 <= target_fpr < 1.0:
        raise ValueError("target_fpr must be in [0, 1)")

    ordered = sorted(float(score) for score in benign_scores)
    count = len(ordered)
    allowed = math.floor(target_fpr * count + 1e-12)
    if lower_is_attack:
        threshold = (
            math.nextafter(ordered[0], -math.inf)
            if allowed <= 0
            else ordered[allowed]
        )
        flagged = sum(score < threshold for score in ordered)
    else:
        threshold = (
            math.nextafter(ordered[-1], math.inf) if allowed <= 0 else ordered[count - allowed]
        )
        flagged = sum(score >= threshold for score in ordered)
    return ThresholdChoice(
        threshold=float(threshold),
        target_fpr=target_fpr,
        achieved_fpr=flagged / count,
        benign_rows=count,
        benign_flagged=flagged,
    )


def expected_alerts_per_day(target_fpr: float, benign_flows_per_day: float) -> float:
    """Flow-level FPR translated into the alert volume it implies at this base rate."""
    return target_fpr * benign_flows_per_day
