"""Builds a live `NetdataMetricsSnapshot` from pirewall-core's running state (spec §33, A3).

`pirewall.integration.netdata` has always known how to *shape* a snapshot
into StatsD gauges; nothing knew how to *produce* one, because no running
loop existed to poll capture statistics, the flow table, and the rate
limiter on a schedule (see `pirewall.core.models.metrics`' own docstring).
This module is that missing half.

Two honesty notes about the metrics themselves:

* **Host CPU/memory come from `/proc`**, read directly — `psutil` is not on
  `CLAUDE.md`'s allowed dependency list and is not worth adding for two
  numbers. On a non-Linux development machine `/proc` does not exist, so
  both read as `0.0`. They are host-wide figures, not this process's share.
* **`api_health` is not a measurement of the pirewall-api process.** A4
  makes pirewall-api a separate process that pirewall-core has no handle on
  and deliberately cannot inspect. What this reports is whether the RPC
  socket pirewall-api depends on is bound and being served — i.e. core's
  half of the API path. A dead pirewall-api with a healthy core still reads
  `True` here; the Admin PC notices that by the control panel not
  responding at all.
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from pirewall.core.models.capture_stats import CaptureStatistics
from pirewall.core.models.metrics import NetdataMetricsSnapshot

_logger = logging.getLogger(__name__)

_PROC_STAT = Path("/proc/stat")
_PROC_MEMINFO = Path("/proc/meminfo")


@dataclass(slots=True)
class RuntimeCounters:
    """Monotonic counters the capture/detection threads increment as work happens.

    Deliberately monotonic (never reset): `MetricsCollector` turns them into
    rates by differencing successive readings, which is both simpler to
    reason about and immune to a lost/late collection interval.

    Guarded by its own lock because the capture thread and the detection
    thread both write to it while the metrics thread reads it. The
    increments are individually trivial, so a single lock costs nothing at
    the rates involved.
    """

    flows_completed: int = 0
    flows_expired: int = 0
    inferences: int = 0
    inference_seconds_total: float = 0.0
    detections: int = 0
    blocks: int = 0
    rules_rejected: int = 0
    flows_dropped_for_backpressure: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, **deltas: float) -> None:
        """Atomically add to one or more counters by attribute name."""
        with self._lock:
            for name, delta in deltas.items():
                current = getattr(self, name)
                setattr(self, name, current + delta)

    def snapshot(self) -> "RuntimeCounters":
        """A consistent, lock-free copy for a reader to difference against."""
        with self._lock:
            return RuntimeCounters(
                flows_completed=self.flows_completed,
                flows_expired=self.flows_expired,
                inferences=self.inferences,
                inference_seconds_total=self.inference_seconds_total,
                detections=self.detections,
                blocks=self.blocks,
                rules_rejected=self.rules_rejected,
                flows_dropped_for_backpressure=self.flows_dropped_for_backpressure,
            )


def _read_cpu_times() -> tuple[float, float] | None:
    """(busy, total) jiffies from `/proc/stat`, or `None` where `/proc` isn't available."""
    try:
        first_line = _PROC_STAT.read_text(encoding="utf-8").split("\n", 1)[0]
    except OSError:
        return None
    fields = first_line.split()
    if len(fields) < 5 or fields[0] != "cpu":
        return None
    try:
        values = [float(value) for value in fields[1:]]
    except ValueError:
        return None
    total = sum(values)
    idle = values[3] + (values[4] if len(values) > 4 else 0.0)
    return total - idle, total


def _read_memory_percent() -> float:
    """Host memory in use, as a percentage, from `/proc/meminfo`. `0.0` where unavailable."""
    try:
        content = _PROC_MEMINFO.read_text(encoding="utf-8")
    except OSError:
        return 0.0
    values: dict[str, float] = {}
    for line in content.splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts:
            try:
                values[key] = float(parts[0])
            except ValueError:
                continue
    total = values.get("MemTotal", 0.0)
    available = values.get("MemAvailable")
    if total <= 0.0 or available is None:
        return 0.0
    return max(0.0, min(100.0, (total - available) / total * 100.0))


class MetricsCollector:
    """Assembles one `NetdataMetricsSnapshot` per call from live pirewall-core state."""

    def __init__(self, counters: RuntimeCounters, max_adaptive_rules_per_window: int) -> None:
        self._counters = counters
        self._max_adaptive_rules_per_window = max_adaptive_rules_per_window
        self._previous_counters = counters.snapshot()
        self._previous_capture: CaptureStatistics | None = None
        self._previous_at: datetime | None = None
        self._previous_cpu = _read_cpu_times()

    def collect(
        self,
        now: datetime,
        capture_stats: CaptureStatistics,
        active_flows: int,
        rule_count: int,
        adaptive_rules_in_window: int,
        *,
        capture_health: bool,
        firewall_health: bool,
        api_health: bool,
    ) -> NetdataMetricsSnapshot:
        """Build a snapshot, differencing against the previous call to derive rates.

        The first call has no previous reading to difference against, so all
        rate metrics are `0.0` — a deliberately conservative start rather
        than a fabricated figure derived from process uptime.
        """
        elapsed = 0.0 if self._previous_at is None else (now - self._previous_at).total_seconds()
        current = self._counters.snapshot()

        packet_rate = 0.0
        if self._previous_capture is not None and elapsed > 0.0:
            packet_delta = capture_stats.packets_seen - self._previous_capture.packets_seen
            packet_rate = max(0.0, packet_delta / elapsed)

        def rate(attribute: str) -> float:
            if elapsed <= 0.0:
                return 0.0
            delta = getattr(current, attribute) - getattr(self._previous_counters, attribute)
            return max(0.0, delta / elapsed)

        inference_latency_ms = 0.0
        if current.inferences > 0:
            inference_latency_ms = current.inference_seconds_total / current.inferences * 1000.0

        snapshot = NetdataMetricsSnapshot(
            cpu_percent=self._cpu_percent(),
            memory_percent=_read_memory_percent(),
            packet_rate_per_second=packet_rate,
            packet_drops=capture_stats.packets_dropped,
            active_flows=active_flows,
            flow_creation_rate_per_second=rate("flows_completed"),
            flow_expiration_rate_per_second=rate("flows_expired"),
            inference_count=int(current.inferences),
            inference_latency_ms=inference_latency_ms,
            detection_count=int(current.detections),
            block_count=int(current.blocks),
            rule_count=rule_count,
            rule_rejection_count=int(current.rules_rejected),
            api_health=api_health,
            capture_health=capture_health,
            firewall_health=firewall_health,
            adaptive_rule_creation_rate_per_window=adaptive_rules_in_window,
            adaptive_rule_budget_fraction=self._budget_fraction(adaptive_rules_in_window),
        )
        self._previous_counters = current
        self._previous_capture = capture_stats
        self._previous_at = now
        return snapshot

    def _budget_fraction(self, adaptive_rules_in_window: int) -> float:
        if self._max_adaptive_rules_per_window <= 0:
            return 1.0
        return min(1.0, adaptive_rules_in_window / self._max_adaptive_rules_per_window)

    def _cpu_percent(self) -> float:
        current = _read_cpu_times()
        previous = self._previous_cpu
        self._previous_cpu = current
        if current is None or previous is None:
            return 0.0
        busy_delta = current[0] - previous[0]
        total_delta = current[1] - previous[1]
        if total_delta <= 0.0:
            return 0.0
        return max(0.0, min(100.0, busy_delta / total_delta * 100.0))
