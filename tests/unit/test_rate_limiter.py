"""`RuleCreationRateLimiter`: bounded, config-driven rate cap (ADDENDUM.md A3)."""

from datetime import UTC, datetime, timedelta

from pirewall.firewall.rate_limiter import RuleCreationRateLimiter

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def test_allows_up_to_budget() -> None:
    limiter = RuleCreationRateLimiter(max_per_window=3, window_seconds=60)
    for _ in range(3):
        assert limiter.would_allow(T0)
        limiter.record(T0)
    assert not limiter.would_allow(T0)


def test_budget_recovers_after_window_elapses() -> None:
    limiter = RuleCreationRateLimiter(max_per_window=1, window_seconds=10)
    limiter.record(T0)
    assert not limiter.would_allow(T0 + timedelta(seconds=5))
    assert limiter.would_allow(T0 + timedelta(seconds=11))


def test_would_allow_does_not_consume_budget() -> None:
    limiter = RuleCreationRateLimiter(max_per_window=1, window_seconds=60)
    assert limiter.would_allow(T0)
    assert limiter.would_allow(T0)  # peeking repeatedly doesn't consume
    limiter.record(T0)
    assert not limiter.would_allow(T0)
