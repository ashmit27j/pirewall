"""Deterministic behavioral analysis over bounded per-source state (spec §17).

No LLM, no ML model here — plain deterministic logic over a bounded window
of each source IP's recent connection (`Flow`) history. State is capped at
every level (`BehaviorAnalyzer` evicts the least-recently-active source
once `max_tracked_sources` is reached; each source's own destination/port/
recent-connection tracking is separately capped) so this can never be used
to exhaust memory (spec §17 "behavior state must be bounded").
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

    def observe(self, flow: Flow) -> None:
        """Fold one more completed flow from this source into the tracked state."""
        if flow.last_seen > self.last_seen:
            self.last_seen = flow.last_seen
        self.connection_count += 1

        if len(self.destinations) < self._max_destinations:
            self.destinations.add(flow.destination_ip)
        if flow.destination_port is not None and len(self.ports) < self._max_ports:
            self.ports.add(flow.destination_port)

        destination_key = (flow.destination_ip, flow.destination_port)
        already_tracked = destination_key in self.connections_per_destination
        if already_tracked or len(self.connections_per_destination) < self._max_destinations:
            self.connections_per_destination[destination_key] = (
                self.connections_per_destination.get(destination_key, 0) + 1
            )

        if flow.backward_packet_count == 0:
            self.failure_count += 1

        self.recent_connection_times.append(flow.last_seen)

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

    def observe_flow(self, flow: Flow) -> None:
        """Route one completed flow into its source IP's bounded behavior state."""
        state = self._sources.get(flow.source_ip)
        if state is None:
            if len(self._sources) >= self._config.max_tracked_sources:
                self._sources.popitem(last=False)
            state = SourceBehaviorState(
                first_seen=flow.first_seen,
                max_destinations=self._config.max_tracked_destinations_per_source,
                max_ports=self._config.max_tracked_ports_per_source,
                max_recent=self._config.recent_connections_window,
            )
            self._sources[flow.source_ip] = state
        else:
            self._sources.move_to_end(flow.source_ip)
        state.observe(flow)

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
