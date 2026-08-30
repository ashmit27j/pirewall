"""Deterministic behavioral analysis over bounded per-source state (spec §17).

No LLM, no ML model here — plain deterministic logic over a bounded window
of each source IP's recent connection (`Flow`) history. State is capped at
every level (`BehaviorAnalyzer` evicts the least-recently-active source
once `max_tracked_sources` is reached; each source's own destination/port/
recent-connection tracking is separately capped) so this can never be used
to exhaust memory (spec §17 "behavior state must be bounded").

**Two update points, not one (ADDENDUM_2.md B1).** The volumetric signals
(scanning/burst/repeated-connection/destination-diversity) are derived from
data that's fully known the instant a flow *opens* — source, destination,
port, protocol, timestamp. Waiting for the flow to *complete* before folding
that in is what made a scan detectable only as fast as its slowest
constituent flow timed out, not as fast as the pattern was actually visible.
So:

* `observe_new_connection` folds in everything knowable at flow creation —
  called once per new flow, from `pirewall.flow.aggregator.FlowAggregator`'s
  creation path (via a callback, not an import — the flow layer must not
  depend on detection, per `CLAUDE.md`'s dependency-direction rule).
* `observe_completion` folds in the one signal that genuinely cannot be
  known until a flow ends: whether it ever got a response
  (`failure_count`, from `backward_packet_count == 0`).
* `observe_flow` is both of the above against one already-completed `Flow`,
  kept as the single-call convenience it always was — useful for tests and
  for any caller that only ever sees flows post-completion. Production code
  (`pirewall.detection.coordinator.DetectionCoordinator`) calls
  `observe_new_connection` at creation and `observe_completion` at
  completion *separately*, never `observe_flow`, precisely so a real flow's
  connection is counted once, not twice.
"""

import statistics
from collections import OrderedDict, deque
from collections.abc import Iterable
from datetime import datetime
from ipaddress import IPv4Address
from itertools import pairwise

from pirewall.config.models import DetectionConfig
from pirewall.core.enums import BehaviorPatternType
from pirewall.core.models.behavior import BehaviorAssessment
from pirewall.core.models.flow import Flow

_TOTAL_PATTERN_TYPES = len(BehaviorPatternType)


class SourceBehaviorState:
    """Bounded, mutable behavior-tracking state for one source IP."""

    __slots__ = (
        "_max_destinations",
        "_max_ports",
        "connection_count",
        "connections_per_destination",
        "destinations",
        "failure_count",
        "first_seen",
        "last_seen",
        "ports",
        "recent_connection_times",
    )

    def __init__(self, first_seen: datetime, max_destinations: int, max_ports: int, max_recent: int) -> None:
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.connection_count = 0
        self.destinations: set[IPv4Address] = set()
        self.ports: set[int] = set()
        self.connections_per_destination: dict[tuple[IPv4Address, int | None], int] = {}
        self.failure_count = 0
        self.recent_connection_times: deque[datetime] = deque(maxlen=max_recent)
        self._max_destinations = max_destinations
        self._max_ports = max_ports

    def observe_new_connection(
        self, destination_ip: IPv4Address, destination_port: int | None, timestamp: datetime
    ) -> None:
        """Fold in one newly-opened flow (ADDENDUM_2.md B1) — everything knowable at creation."""
        if timestamp > self.last_seen:
            self.last_seen = timestamp
        self.connection_count += 1

        if len(self.destinations) < self._max_destinations:
            self.destinations.add(destination_ip)
        if destination_port is not None and len(self.ports) < self._max_ports:
            self.ports.add(destination_port)

        destination_key = (destination_ip, destination_port)
        already_tracked = destination_key in self.connections_per_destination
        if already_tracked or len(self.connections_per_destination) < self._max_destinations:
            self.connections_per_destination[destination_key] = (
                self.connections_per_destination.get(destination_key, 0) + 1
            )

        self.recent_connection_times.append(timestamp)

    def observe_completion(self, flow: Flow) -> None:
        """Fold in the one signal only knowable once a flow ends: did it ever get a response?

        Must be called at most once per flow, and only ever *after* that same
        flow's `observe_new_connection` — never on its own, or `failure_count`
        would be counted for a connection this state never opened.
        """
        if flow.last_seen > self.last_seen:
            self.last_seen = flow.last_seen
        if flow.backward_packet_count == 0:
            self.failure_count += 1

    def observe(self, flow: Flow) -> None:
        """Fold one already-completed flow into the tracked state in one call.

        Equivalent to `observe_new_connection` (keyed off `flow.first_seen`)
        followed by `observe_completion` — see the module docstring for why
        production code calls those two separately instead of this.
        """
        self.observe_new_connection(flow.destination_ip, flow.destination_port, flow.first_seen)
        self.observe_completion(flow)

    @property
    def max_connections_to_single_destination(self) -> int:
        return max(self.connections_per_destination.values(), default=0)


class BehaviorAnalyzer:
    """Bounded, LRU-evicting per-source-IP behavior tracker."""

    def __init__(self, config: DetectionConfig) -> None:
        self._config = config
        self._sources: OrderedDict[IPv4Address, SourceBehaviorState] = OrderedDict()

    def __len__(self) -> int:
        return len(self._sources)

    def observe_new_connection(
        self,
        source_ip: IPv4Address,
        destination_ip: IPv4Address,
        destination_port: int | None,
        timestamp: datetime,
    ) -> None:
        """Route one newly-opened flow into its source IP's bounded state (ADDENDUM_2.md B1).

        Called once per flow, at creation — see the module docstring for why
        this is the call that actually shortens scan/flood detection latency.
        """
        state = self._get_or_create(source_ip, timestamp)
        state.observe_new_connection(destination_ip, destination_port, timestamp)

    def observe_completion(self, flow: Flow) -> None:
        """Fold a completed flow's completion-only signal into its source's state.

        The ordinary case: this source's state already exists (created by
        `observe_new_connection` when this flow opened, or by an earlier
        flow from the same source), so this only adds the completion-only
        signal (`failure_count`) to it.

        Fallback case: no state exists for this source at all — this flow's
        creation-time signal was dropped under backpressure, its source was
        LRU-evicted before completion, or the caller never sent a
        creation-time signal in the first place (e.g. calling `analyze`
        directly without going through `pirewall.runtime.core.CoreDaemon`'s
        queue, as tests do). Rather than silently losing this flow's
        evidence, this falls back to a full `observe()` — equivalent to
        treating flow completion as this source's first-known signal, which
        is the best information available in that case.
        """
        state = self._sources.get(flow.source_ip)
        if state is None:
            state = self._get_or_create(flow.source_ip, flow.first_seen)
            state.observe(flow)
            return
        self._sources.move_to_end(flow.source_ip)
        state.observe_completion(flow)

    def observe_flow(self, flow: Flow) -> None:
        """Route one already-completed flow into its source IP's bounded behavior state.

        Convenience for callers (tests, or anything that only ever sees
        post-completion flows) that never got a creation-time signal for this
        flow — see the module docstring. Production's own detection path
        calls `observe_new_connection`/`observe_completion` separately.
        """
        state = self._get_or_create(source_ip=flow.source_ip, first_seen=flow.first_seen)
        state.observe(flow)

    def _get_or_create(self, source_ip: IPv4Address, first_seen: datetime) -> SourceBehaviorState:
        state = self._sources.get(source_ip)
        if state is None:
            if len(self._sources) >= self._config.max_tracked_sources:
                self._sources.popitem(last=False)
            state = SourceBehaviorState(
                first_seen=first_seen,
                max_destinations=self._config.max_tracked_destinations_per_source,
                max_ports=self._config.max_tracked_ports_per_source,
                max_recent=self._config.recent_connections_window,
            )
            self._sources[source_ip] = state
        else:
            self._sources.move_to_end(source_ip)
        return state

    def assess(self, source_ip: IPv4Address) -> BehaviorAssessment | None:
        """Assess `source_ip`'s currently tracked state, or `None` if nothing is tracked for it."""
        state = self._sources.get(source_ip)
        if state is None:
            return None
        return _assess_state(source_ip, state, self._config)


def _inter_arrival_seconds(times: Iterable[datetime]) -> list[float]:
    ordered = sorted(times)
    return [(later - earlier).total_seconds() for earlier, later in pairwise(ordered)]


def _assess_state(
    source_ip: IPv4Address, state: SourceBehaviorState, config: DetectionConfig
) -> BehaviorAssessment:
    patterns: list[BehaviorPatternType] = []
    reasons: list[str] = []
    window_seconds = max((state.last_seen - state.first_seen).total_seconds(), 1.0)

    if state.max_connections_to_single_destination >= config.repeated_connections_threshold:
        patterns.append(BehaviorPatternType.REPEATED_CONNECTIONS)
        reasons.append(f"{state.max_connections_to_single_destination} connections to a single destination")

    frequency = state.connection_count / window_seconds
    if frequency >= config.high_frequency_per_second_threshold:
        patterns.append(BehaviorPatternType.HIGH_FREQUENCY)
        reasons.append(f"connection frequency {frequency:.2f}/s")

    burst_count = sum(
        1
        for timestamp in state.recent_connection_times
        if (state.last_seen - timestamp).total_seconds() <= config.burst_window_seconds
    )
    if burst_count >= config.burst_count_threshold:
        patterns.append(BehaviorPatternType.BURST)
        reasons.append(f"{burst_count} connections within {config.burst_window_seconds:.0f}s")

    if window_seconds >= config.persistence_seconds_threshold and state.connection_count >= 2:
        patterns.append(BehaviorPatternType.PERSISTENCE)
        reasons.append(f"active for {window_seconds:.0f}s")

    if len(state.destinations) >= config.destination_diversity_threshold:
        patterns.append(BehaviorPatternType.DESTINATION_DIVERSITY)
        reasons.append(f"{len(state.destinations)} distinct destinations")

    if len(state.ports) >= config.scanning_port_threshold:
        patterns.append(BehaviorPatternType.SCANNING)
        reasons.append(f"{len(state.ports)} distinct destination ports")

    if state.failure_count >= config.repeated_failures_threshold:
        patterns.append(BehaviorPatternType.REPEATED_FAILURES)
        reasons.append(f"{state.failure_count} unanswered connection attempts")

    intervals = _inter_arrival_seconds(state.recent_connection_times)
    if len(intervals) >= 3:
        mean_interval = statistics.fmean(intervals)
        if mean_interval > 0:
            coefficient_of_variation = statistics.pstdev(intervals) / mean_interval
            if coefficient_of_variation <= config.temporal_pattern_cv_threshold:
                patterns.append(BehaviorPatternType.TEMPORAL_PATTERN)
                reasons.append(f"regular connection timing (cv={coefficient_of_variation:.3f})")

    confidence = min(1.0, len(patterns) / _TOTAL_PATTERN_TYPES)
    description = "; ".join(reasons) if reasons else "no notable behavioral patterns observed"

    return BehaviorAssessment(
        source_ip=source_ip,
        detected_patterns=tuple(patterns),
        confidence=confidence,
        description=description,
        window_start=state.first_seen,
        window_end=state.last_seen,
    )
