"""Small, exact statistics for the harness, stdlib only (no scipy: CLAUDE.md dependency list).

* `rate_interval(count, exposure)`: events per unit exposure (per
  device-hour) with a 95% interval. Zero events report the **rule-of-three**
  upper bound `3 / T` (critique_safety_eval.md "Metric definitions");
  otherwise the exact (Garwood) Poisson interval, found by bisection on the
  Poisson CDF.
* `summarise(values)`: median, mean, SD, min, max and a distribution-free
  confidence interval for the median from order statistics (binomial), with
  its actual coverage, because N = 3..5 runs cannot reach 95% exactly.
"""

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

__all__ = ["RULE_OF_THREE", "RateInterval", "Summary", "poisson_interval", "rate_interval", "summarise"]

RULE_OF_THREE: Final = 3.0
_CONFIDENCE: Final = 0.95


def _poisson_cdf(k: int, mean: float) -> float:
    """P(X <= k) for X ~ Poisson(mean), summed in log space."""
    if mean <= 0:
        return 1.0
    log_term = -mean  # log P(X = 0)
    total = math.exp(log_term)
    for i in range(1, k + 1):
        log_term += math.log(mean) - math.log(i)
        total += math.exp(log_term)
    return min(total, 1.0)


def _bisect(target: float, k: int, low: float, high: float) -> float:
    """The mean at which P(X <= k) equals `target` (the CDF falls as the mean grows)."""
    for _ in range(200):
        middle = (low + high) / 2
        if _poisson_cdf(k, middle) > target:
            low = middle
        else:
            high = middle
    return (low + high) / 2


def poisson_interval(count: int, confidence: float = _CONFIDENCE) -> tuple[float, float]:
    """Exact (Garwood) two-sided interval for a Poisson mean, given `count` observed events."""
    if count < 0:
        raise ValueError("count must be non-negative")
    alpha = 1.0 - confidence
    upper_bound = max(10.0, count * 4.0 + 20.0)
    upper = _bisect(alpha / 2, count, 0.0, upper_bound)
    lower = 0.0 if count == 0 else _bisect(1.0 - alpha / 2, count - 1, 0.0, upper_bound)
    return lower, upper


@dataclass(frozen=True, slots=True)
class RateInterval:
    """`count` events over `exposure` units, as a rate with a 95% interval."""

    count: int
    exposure: float
    rate: float | None
    lower: float | None
    upper: float | None
    method: str

    def as_json(self) -> dict[str, float | int | str | None]:
        """For reports."""
        return {
            "count": self.count,
            "exposure": self.exposure,
            "rate": self.rate,
            "ci95_lower": self.lower,
            "ci95_upper": self.upper,
            "method": self.method,
        }


def rate_interval(count: int, exposure: float) -> RateInterval:
    """Rule of three (`3/T`) for zero events, else the exact Poisson 95% interval divided by T."""
    if exposure <= 0:
        return RateInterval(count, exposure, None, None, None, "no exposure")
    if count == 0:
        return RateInterval(0, exposure, 0.0, 0.0, RULE_OF_THREE / exposure, "rule of three (3/T)")
    lower, upper = poisson_interval(count)
    return RateInterval(
        count, exposure, count / exposure, lower / exposure, upper / exposure, "exact Poisson"
    )


@dataclass(frozen=True, slots=True)
class Summary:
    """Descriptive statistics over repeated runs of one (attack, metric)."""

    n: int
    median: float | None
    mean: float | None
    sd: float | None
    minimum: float | None
    maximum: float | None
    median_ci_lower: float | None
    median_ci_upper: float | None
    median_ci_coverage: float | None

    def as_json(self) -> dict[str, float | int | None]:
        """For reports."""
        return {
            "n": self.n,
            "median": self.median,
            "mean": self.mean,
            "sd": self.sd,
            "min": self.minimum,
            "max": self.maximum,
            "median_ci_lower": self.median_ci_lower,
            "median_ci_upper": self.median_ci_upper,
            "median_ci_coverage": self.median_ci_coverage,
        }


def _binomial_cdf(k: int, n: int) -> float:
    return sum(math.comb(n, i) for i in range(k + 1)) / 2**n


def _median_interval(ordered: Sequence[float]) -> tuple[float, float, float]:
    """The narrowest symmetric order-statistic interval with coverage >= 95%, else the full range."""
    n = len(ordered)
    best = (ordered[0], ordered[-1], 1.0 - 2 * _binomial_cdf(0, n) if n > 0 else 0.0)
    for j in range(1, n // 2):
        coverage = 1.0 - 2 * _binomial_cdf(j, n)
        if coverage < _CONFIDENCE:
            break
        best = (ordered[j], ordered[n - 1 - j], coverage)
    return best


def summarise(values: Sequence[float]) -> Summary:
    """Median, mean, SD (n - 1), range and the order-statistic median interval."""
    n = len(values)
    if n == 0:
        return Summary(0, None, None, None, None, None, None, None, None)
    ordered = sorted(values)
    middle = n // 2
    median = ordered[middle] if n % 2 else (ordered[middle - 1] + ordered[middle]) / 2
    mean = sum(ordered) / n
    sd = math.sqrt(sum((value - mean) ** 2 for value in ordered) / (n - 1)) if n > 1 else None
    lower, upper, coverage = _median_interval(ordered)
    return Summary(n, median, mean, sd, ordered[0], ordered[-1], lower, upper, coverage)
