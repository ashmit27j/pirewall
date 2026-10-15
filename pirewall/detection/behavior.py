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

import math
import statistics
from collections import OrderedDict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from itertools import pairwise

from pirewall.config.models import DetectionConfig
from pirewall.core.enums import BehaviorPatternType, Protocol
from pirewall.core.models.behavior import BehaviorAssessment
from pirewall.core.models.flow import Flow

_TOTAL_PATTERN_TYPES = len(BehaviorPatternType)


@dataclass(slots=True)
class _ConnectionEvent:
    """One newly-opened connection, as remembered inside a source's sliding window.

    The `*_tracked` flags record whether this event was admitted into each
    bounded index at insertion time, so expiring it later decrements exactly
    the counters it incremented — never one it was refused from by a cap.
    """

    timestamp: datetime
    destination_ip: IPv4Address
    destination_port: int | None
    destination_tracked: bool
    port_tracked: bool
    global_port_tracked: bool
    pair_tracked: bool


class SourceBehaviorState:
    """Bounded, mutable, **time-windowed** behavior-tracking state for one source IP.

    Every count-based signal is computed over the last
    `DetectionConfig.behavior_window_seconds` only. This used to be lifetime
    state that never decayed (the window setting existed but nothing read
    it), so any long-lived device eventually tripped DESTINATION_DIVERSITY,
    REPEATED_FAILURES and REPEATED_CONNECTIONS permanently — a phone
    browsing for an hour had simply *accumulated* its way past thresholds
    meant for a short burst (docs/KNOWN_ISSUES.md #3).

    "Now" is the newest timestamp this state has seen (packet time, not the
    wall clock), so pruning is deterministic and identical in replay,
    tests, and production.
    """

    __slots__ = (
        "_events",
        "_failures",
        "_flood_window_seconds",
        "_max_destinations",
        "_max_events",
        "_max_flood_entries",
        "_max_ports",
        "_window_seconds",
        "connections_per_destination",
        "destination_counts",
        "failures_per_destination",
        "first_seen",
        "last_seen",
        "ports",
        "ports_per_destination",
        "recent_connection_times",
        "recent_per_destination",
        "slow_connection_counts",
        "streak_started",
    )

    def __init__(
        self,
        first_seen: datetime,
        max_destinations: int,
        max_ports: int,
        max_recent: int,
        window_seconds: float = 300.0,
        max_events: int = 2_000,
        flood_window_seconds: float = 5.0,
        max_flood_entries: int = 1_000,
    ) -> None:
        self.first_seen = first_seen
        self.last_seen = first_seen
        # Start of the current uninterrupted activity streak (PERSISTENCE):
        # reset whenever the source goes quiet for longer than the window.
        self.streak_started = first_seen
        self._window_seconds = window_seconds
        self._max_events = max_events
        self._max_destinations = max_destinations
        self._max_ports = max_ports
        self._events: deque[_ConnectionEvent] = deque()
        self._failures: deque[tuple[datetime, IPv4Address, bool]] = deque()
        # Windowed indexes: each value is a count of live events, and each
        # dict is bounded by the configured caps.
        self.destination_counts: dict[IPv4Address, int] = {}
        self.ports: dict[int, int] = {}
        self.ports_per_destination: dict[IPv4Address, dict[int, int]] = {}
        self.connections_per_destination: dict[tuple[IPv4Address, int | None], int] = {}
        self.failures_per_destination: dict[IPv4Address, int] = {}
        self.recent_connection_times: deque[datetime] = deque(maxlen=max_recent)
        # ADDENDUM_2.md B2 — latest live concurrent-slow-connection snapshot
        # per destination, with when it was taken, so a cluster that has
        # since dissolved stops counting once its snapshot ages out.
        self.slow_connection_counts: dict[IPv4Address, tuple[int, datetime]] = {}
        # FLOOD: recent connection times per destination over the (short)
        # burst window, each deque capped just above the flood threshold —
        # past that, more entries cannot change the answer.
        self._flood_window_seconds = flood_window_seconds
        self._max_flood_entries = max_flood_entries
        self.recent_per_destination: dict[IPv4Address, deque[datetime]] = {}

    # ------------------------------------------------------------ properties

    @property
    def destinations(self) -> set[IPv4Address]:
        """Distinct destinations contacted within the window (capped)."""
        return set(self.destination_counts)

    @property
    def connection_count(self) -> int:
        """Connections opened within the window."""
        return len(self._events)

    @property
    def failure_count(self) -> int:
        """Unanswered connection attempts within the window, to any destination."""
        return len(self._failures)

    @property
    def max_failures_to_single_destination(self) -> int:
        """Most unanswered attempts within the window against any one destination.

        REPEATED_FAILURES reads this, not `failure_count`: a SYN flood or a
        scan of filtered ports concentrates its failures on its target,
        while a device whose traffic is being dropped (e.g. not yet signed
        in to the captive portal) fails across dozens of unrelated hosts.
        Same principle as `scanned_port_breadth` measuring per destination.
        """
        return max(self.failures_per_destination.values(), default=0)

    @property
    def scanned_port_breadth(self) -> int:
        """The most distinct ports this source contacted on any single destination.

        The discriminator between a scan and a browser. A port scan hits many
        ports on few hosts; a browser hits one or two ports (443, occasionally
        80) on many hosts. Counting distinct ports *globally* — as this used
        to — measures neither: a phone loading one shopping page reached 71
        distinct ports across 91 hosts, almost all of them ephemeral ports
        belonging to reply-direction flows, and tripped a "port scan" at a
        threshold of 10.
        """
        return max((len(ports) for ports in self.ports_per_destination.values()), default=0)

    @property
    def max_connections_to_single_destination(self) -> int:
        return max(self.connections_per_destination.values(), default=0)

    @property
    def max_concurrent_slow_connections(self) -> int:
        return max((count for count, _ in self.slow_connection_counts.values()), default=0)

    @property
    def max_recent_connections_to_single_destination(self) -> int:
        """Most connections to one destination within the flood window, as of `last_seen`."""
        horizon = self.last_seen - timedelta(seconds=self._flood_window_seconds)
        best = 0
        for times in self.recent_per_destination.values():
            best = max(best, sum(1 for moment in times if moment >= horizon))
        return best

    @property
    def streak_seconds(self) -> float:
        """Length of the current uninterrupted activity streak."""
        return (self.last_seen - self.streak_started).total_seconds()

    # ------------------------------------------------------------- updates

    def observe_new_connection(
        self, destination_ip: IPv4Address, destination_port: int | None, timestamp: datetime
    ) -> None:
        """Fold in one newly-opened flow (ADDENDUM_2.md B1) — everything knowable at creation."""
        self._advance(timestamp)
        if len(self._events) >= self._max_events:
            self._expire_event(self._events.popleft())

        destination_tracked = destination_ip in self.destination_counts or (
            len(self.destination_counts) < self._max_destinations
        )
        if destination_tracked:
            self.destination_counts[destination_ip] = self.destination_counts.get(destination_ip, 0) + 1

        port_tracked = False
        global_port_tracked = False
        if destination_port is not None:
            if destination_port in self.ports or len(self.ports) < self._max_ports:
                self.ports[destination_port] = self.ports.get(destination_port, 0) + 1
                global_port_tracked = True
            if destination_tracked:
                ports_here = self.ports_per_destination.setdefault(destination_ip, {})
                if destination_port in ports_here or len(ports_here) < self._max_ports:
                    ports_here[destination_port] = ports_here.get(destination_port, 0) + 1
                    port_tracked = True

        pair = (destination_ip, destination_port)
        pair_tracked = pair in self.connections_per_destination or (
            len(self.connections_per_destination) < self._max_destinations
        )
        if pair_tracked:
            self.connections_per_destination[pair] = self.connections_per_destination.get(pair, 0) + 1

        self._events.append(
            _ConnectionEvent(
                timestamp=timestamp,
                destination_ip=destination_ip,
                destination_port=destination_port,
                destination_tracked=destination_tracked,
                port_tracked=port_tracked,
                global_port_tracked=global_port_tracked,
                pair_tracked=pair_tracked,
            )
        )
        self.recent_connection_times.append(timestamp)

        times = self.recent_per_destination.get(destination_ip)
        if times is None and len(self.recent_per_destination) < self._max_destinations:
            times = self.recent_per_destination[destination_ip] = deque(maxlen=self._max_flood_entries)
        if times is not None:
            times.append(timestamp)

    def observe_completion(self, flow: Flow) -> None:
        """Fold in the one signal only knowable once a flow ends: did it ever get a response?

        Must be called at most once per flow, and only ever *after* that same
        flow's `observe_new_connection` — never on its own, or a failure
        would be counted for a connection this state never opened. The
        failure is timestamped when the flow *completed* (when it became
        known to be unanswered), which keeps the failure queue in arrival
        order so window expiry can pop from its oldest end.
        """
        self._advance(flow.last_seen)
        if not is_failed_connection_attempt(flow):
            return
        if len(self._failures) >= self._max_events:
            self._expire_failure(self._failures.popleft())
        destination = flow.destination_ip
        tracked = destination in self.failures_per_destination or (
            len(self.failures_per_destination) < self._max_destinations
        )
        if tracked:
            self.failures_per_destination[destination] = self.failures_per_destination.get(destination, 0) + 1
        self._failures.append((flow.last_seen, destination, tracked))

    def observe(self, flow: Flow) -> None:
        """Fold one already-completed flow into the tracked state in one call.

        Equivalent to `observe_new_connection` (keyed off `flow.first_seen`)
        followed by `observe_completion` — see the module docstring for why
        production code calls those two separately instead of this.
        """
        self.observe_new_connection(flow.destination_ip, flow.destination_port, flow.first_seen)
        self.observe_completion(flow)

    def note_slow_connections(self, destination_ip: IPv4Address, count: int, timestamp: datetime) -> None:
        """Record the current concurrent-slow-connection count to `destination_ip` (ADDENDUM_2.md B2).

        Overwrites rather than accumulates: `count` is already a live
        snapshot of how many qualifying connections are open *right now*
        (from `pirewall.flow.aggregator.FlowAggregator.
        snapshot_slow_connection_clusters`), not an event to fold in
        incrementally the way a new connection is. The snapshot expires
        with the window like everything else.
        """
        self._advance(timestamp)
        already_tracked = destination_ip in self.slow_connection_counts
        if already_tracked or len(self.slow_connection_counts) < self._max_destinations:
            self.slow_connection_counts[destination_ip] = (count, timestamp)

    def prune(self, now: datetime) -> None:
        """Expire everything older than the window as of `now` (never moves `last_seen` backwards)."""
        self._advance(now)

    # ------------------------------------------------------------ internals

    def _advance(self, timestamp: datetime) -> None:
        if timestamp > self.last_seen:
            if (timestamp - self.last_seen).total_seconds() > self._window_seconds:
                self.streak_started = timestamp
            self.last_seen = timestamp
        horizon = self.last_seen - timedelta(seconds=self._window_seconds)
        while self._events and self._events[0].timestamp < horizon:
            self._expire_event(self._events.popleft())
        while self._failures and self._failures[0][0] < horizon:
            self._expire_failure(self._failures.popleft())
        flood_horizon = self.last_seen - timedelta(seconds=self._flood_window_seconds)
        for ip in [ip for ip, times in self.recent_per_destination.items() if times[-1] < flood_horizon]:
            del self.recent_per_destination[ip]
        if self.slow_connection_counts:
            stale = [ip for ip, (_, taken) in self.slow_connection_counts.items() if taken < horizon]
            for ip in stale:
                del self.slow_connection_counts[ip]

    def _expire_event(self, event: _ConnectionEvent) -> None:
        if event.destination_tracked:
            _decrement(self.destination_counts, event.destination_ip)
        if event.destination_port is not None:
            if event.global_port_tracked:
                _decrement(self.ports, event.destination_port)
            if event.port_tracked:
                ports_here = self.ports_per_destination.get(event.destination_ip)
                if ports_here is not None:
                    _decrement(ports_here, event.destination_port)
                    if not ports_here:
                        del self.ports_per_destination[event.destination_ip]
        if event.pair_tracked:
            _decrement(self.connections_per_destination, (event.destination_ip, event.destination_port))

    def _expire_failure(self, failure: tuple[datetime, IPv4Address, bool]) -> None:
        _, destination, tracked = failure
        if tracked:
            _decrement(self.failures_per_destination, destination)


def _decrement[K](counts: dict[K, int], key: K) -> None:
    remaining = counts.get(key, 0) - 1
    if remaining > 0:
        counts[key] = remaining
    else:
        counts.pop(key, None)


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

    def note_slow_connections(
        self,
        source_ip: IPv4Address,
        destination_ip: IPv4Address,
        count: int,
        timestamp: datetime,
    ) -> None:
        """Record a live concurrent-slow-connection count for one (source, destination) pair.

        Fed periodically from `pirewall.runtime.core.CoreDaemon`'s sweep
        loop, via `pirewall.flow.aggregator.FlowAggregator.
        snapshot_slow_connection_clusters` (ADDENDUM_2.md B2) — never called
        from the detection thread's per-flow path, since this is
        source-level aggregate evidence, not a per-flow observation.
        """
        state = self._get_or_create(source_ip, timestamp)
        state.note_slow_connections(destination_ip, count, timestamp)

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
            if not flow.opened_by_initiation:
                # A responder's flow (see `Flow.opened_by_initiation`): it is
                # not a connection this source made, so it seeds nothing.
                return
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
                window_seconds=float(self._config.behavior_window_seconds),
                max_events=self._config.max_tracked_connections_per_source,
                flood_window_seconds=self._config.burst_window_seconds,
                max_flood_entries=math.ceil(
                    self._config.flood_connections_per_second_threshold * self._config.burst_window_seconds
                )
                + 1,
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

    def assess_at(self, source_ip: IPv4Address, now: datetime) -> BehaviorAssessment | None:
        """Like `assess`, but first expires anything older than the window as of `now`.

        For callers assessing on a clock tick rather than on that source's
        own traffic (the source-level fast path), where the source's newest
        event may itself be old.
        """
        state = self._sources.get(source_ip)
        if state is None:
            return None
        state.prune(now)
        return _assess_state(source_ip, state, self._config)


def _inter_arrival_seconds(times: Iterable[datetime]) -> list[float]:
    ordered = sorted(times)
    return [(later - earlier).total_seconds() for earlier, later in pairwise(ordered)]


def _recent_frequency(state: SourceBehaviorState) -> float:
    """Connections per second over the bounded recent-connection window, not the whole tracked lifetime.

    This used to be `state.connection_count / (last_seen - first_seen)` —
    a lifetime average. That formula has a first-burst bias with no
    principled justification: a source `BehaviorAnalyzer` has just started
    tracking (a genuinely new device, or any existing device re-tracked
    after `pirewall-core` restarts or its LRU state is evicted) has a tiny
    `(last_seen - first_seen)`, so its very first burst of connections —
    ordinary for a device that just joined Wi-Fi (OS update checks,
    push-notification registration, several apps syncing at once) —
    produces an inflated rate. A long-tracked source generating the exact
    same instantaneous burst gets it diluted away by its own history and
    never trips this signal at all — an inconsistency backward for
    security (an established attacker gets *more* dilution-based cover
    over time, not less), and not something `high_frequency_per_second_threshold`
    itself can fix, however it's tuned (see `KNOWN_ISSUES.md` #3, which
    already documents that threshold as too low for a busy device in
    general — this fixes *whose* bursts the threshold is actually applied
    to, not the threshold's value).

    Measuring the rate over `state.recent_connection_times` (already
    bounded by `DetectionConfig.recent_connections_window`, the same deque
    `BURST` reads) removes that asymmetry: any source's current burst is
    judged the same way regardless of how long it has been tracked.
    """
    if len(state.recent_connection_times) < 2:
        return 0.0
    span = max((state.last_seen - state.recent_connection_times[0]).total_seconds(), 1.0)
    return len(state.recent_connection_times) / span


def _assess_state(
    source_ip: IPv4Address, state: SourceBehaviorState, config: DetectionConfig
) -> BehaviorAssessment:
    patterns: list[BehaviorPatternType] = []
    reasons: list[str] = []
    streak_seconds = state.streak_seconds

    if state.max_connections_to_single_destination >= config.repeated_connections_threshold:
        patterns.append(BehaviorPatternType.REPEATED_CONNECTIONS)
        reasons.append(f"{state.max_connections_to_single_destination} connections to a single destination")

    frequency = _recent_frequency(state)
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

    if streak_seconds >= config.persistence_seconds_threshold and state.connection_count >= 2:
        patterns.append(BehaviorPatternType.PERSISTENCE)
        reasons.append(f"continuously active for {streak_seconds:.0f}s")

    if len(state.destinations) >= config.destination_diversity_threshold:
        patterns.append(BehaviorPatternType.DESTINATION_DIVERSITY)
        reasons.append(f"{len(state.destinations)} distinct destinations")

    port_breadth = state.scanned_port_breadth
    if port_breadth >= config.scanning_port_threshold:
        patterns.append(BehaviorPatternType.SCANNING)
        reasons.append(f"{port_breadth} distinct ports on a single destination")

    failures_here = state.max_failures_to_single_destination
    if failures_here >= config.repeated_failures_threshold:
        patterns.append(BehaviorPatternType.REPEATED_FAILURES)
        reasons.append(f"{failures_here} unanswered connection attempts to a single destination")

    if state.max_concurrent_slow_connections >= config.concurrent_slow_connections_threshold:
        patterns.append(BehaviorPatternType.SLOW_RATE_DOS)
        reasons.append(
            f"{state.max_concurrent_slow_connections} concurrent slow connections to one destination"
        )

    flood_count = state.max_recent_connections_to_single_destination
    if flood_count >= config.flood_connections_per_second_threshold * config.burst_window_seconds:
        patterns.append(BehaviorPatternType.FLOOD)
        reasons.append(
            f"{flood_count} new connections to a single destination within {config.burst_window_seconds:.0f}s"
        )

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
        window_start=max(
            state.first_seen, state.last_seen - timedelta(seconds=config.behavior_window_seconds)
        ),
        window_end=state.last_seen,
    )


def is_failed_connection_attempt(flow: Flow) -> bool:
    """Whether `flow` looks like a connection attempt that was never answered.

    Narrower than "no packets came back", which is what this used to be and
    which counted 38% of an ordinary browsing session as failures: a flow
    record can end with no reply for reasons that say nothing about the
    source — UDP and ICMP have no notion of an answered connection at all,
    and a flow evicted from the table after one packet is a bookkeeping
    artifact rather than a refused connection.

    So a failure requires a TCP flow that actually attempted to open a
    connection (at least one SYN) and received nothing at all in return.
    That is the shape a scan or a SYN flood produces, and the shape ordinary
    traffic does not.
    """
    if flow.protocol is not Protocol.TCP:
        return False
    if flow.backward_packet_count != 0:
        return False
    return flow.tcp_flags.syn >= 1
