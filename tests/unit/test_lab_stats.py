"""`lab/stats.py`: rule of three, exact Poisson intervals, median summaries (phase 18)."""

import pytest

from lab.stats import poisson_interval, rate_interval, summarise


def test_zero_events_report_the_rule_of_three_bound() -> None:
    result = rate_interval(0, 120.0)
    assert result.rate == 0.0
    assert result.upper == pytest.approx(3.0 / 120.0)
    assert result.method == "rule of three (3/T)"


def test_counts_get_the_exact_poisson_interval() -> None:
    # Garwood 95% bounds, from the chi-square tables: k=1 -> [0.0253, 5.5716], k=10 -> [4.7954, 18.3904].
    assert poisson_interval(1) == pytest.approx((0.02532, 5.57164), abs=1e-4)
    assert poisson_interval(10) == pytest.approx((4.79539, 18.39036), abs=1e-4)
    result = rate_interval(10, 50.0)
    assert result.rate == pytest.approx(0.2)
    assert (result.lower, result.upper) == pytest.approx((4.79539 / 50, 18.39036 / 50), abs=1e-5)
    assert result.method == "exact Poisson"


def test_no_exposure_has_no_rate() -> None:
    assert rate_interval(3, 0.0).rate is None


def test_a_negative_count_is_refused() -> None:
    with pytest.raises(ValueError):
        poisson_interval(-1)


def test_summaries_of_few_runs_report_the_full_range_and_its_real_coverage() -> None:
    summary = summarise([3.0, 1.0, 2.0, 5.0, 4.0])
    assert (summary.n, summary.median, summary.minimum, summary.maximum) == (5, 3.0, 1.0, 5.0)
    assert summary.sd == pytest.approx(1.5811, abs=1e-4)
    # n = 5 cannot reach 95% with an inner pair: the interval is the range, coverage 1 - 2/32.
    assert (summary.median_ci_lower, summary.median_ci_upper) == (1.0, 5.0)
    assert summary.median_ci_coverage == pytest.approx(0.9375)
    assert summarise([]).median is None
    assert summarise([2.0, 4.0]).median == 3.0
