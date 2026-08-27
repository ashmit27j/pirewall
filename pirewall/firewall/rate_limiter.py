"""Bounded, config-driven rule-creation rate cap (ADDENDUM.md A3).

Caps how many adaptive rules can be *created* in a sliding time window —
it never suppresses detection: `ThreatAssessment`/`SecurityEvent`
generation for a flow that trips the cap keeps happening at full fidelity
(see `pirewall.firewall.manager`), only the resulting rule is rejected.
"""

from collections import deque
from datetime import datetime, timedelta


class RuleCreationRateLimiter:
    """A fixed-window counter of adaptive-rule-creation timestamps."""

    def __init__(self, max_per_window: int, window_seconds: float) -> None:
        self._max_per_window = max_per_window
        self._window_seconds = window_seconds
        self._timestamps: deque[datetime] = deque()

    def _prune(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self._window_seconds)
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()

    def would_allow(self, now: datetime) -> bool:
        """Check the budget without consuming it (used by the validator's rate-cap stage)."""
        self._prune(now)
        return len(self._timestamps) < self._max_per_window

    def record(self, now: datetime) -> None:
        """Consume one unit of budget — call only once a candidate fully passes validation."""
        self._prune(now)
        self._timestamps.append(now)
