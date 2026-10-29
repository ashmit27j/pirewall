"""D1: deterministic, MAC-keyed detectors over connection starts (ADDENDUM_4.md D4, PLAN_FINAL §4.5).

D1 is the only non-kernel tier whose evidence may cause an action, so it is
deliberately simple: sliding counts over 10 s and 60 s windows (1 h is
optional), compared with thresholds learned from benign traffic
(`pirewall.detection_v2.thresholds`). Evidence, never commands: everything
here returns `D1Evidence`, and the policy table decides what it means.

**What is counted.** Connection starts, as `pirewall.flow.connection_start`
defines them (V2_CONTRACTS §11) — the same class `pcap_to_flows` uses for
the training rows the thresholds are fitted from, so a threshold means the
same thing live as it did offline (critique_round2 item 12: keep-alive
records split by timeouts must not inflate the counts).

**Two feeds, one meaning** (the source fast path reused for D1 timing,
audit v1 #6). A completed record that is a connection start carries its
outcome (failed handshake, duration, bytes). A creation-time new-flow
signal arrives seconds earlier but knows only (MAC, destination, port).
Signals feed only the *cardinality* detectors — distinct ports per host,
distinct hosts per port, distinct MACs per destination — where seeing one
connection twice (signal, then record) cannot change the count. Detectors
that need an outcome (failed handshake, brute force) count records only.

**Detectors** (all per MAC unless stated):

* vertical scan: max distinct destination ports on one destination host;
* horizontal scan: max distinct destination hosts on one port;
* failed handshake: failed starts / starts, once there are
  `d1.failed_handshake_min_starts` starts;
* brute force: max short (<= `brute_force_max_duration_seconds`),
  similar-size starts to one dst:port among the brute-force ports;
* slow-rate DoS: concurrent slow connections to one destination, ported
  from v1 `SLOW_RATE_DOS` (the aggregator's slow-connection clusters);
* fan-in (per destination, no single MAC): distinct MACs opening
  connections to one destination;
* new-MAC and new-lease rate (LAN-wide): first-seen MACs in traffic and
  first-seen (IP, MAC) leases in the binding table;
* portal auth failures: per account and LAN-wide.

**Bounded state.** Every table is an LRU with its size in `[d1]`, and
every eviction is counted (`D1Counters`); nothing grows without bound
under a random-MAC flood.

Not thread-safe: one `D1State` belongs to the detection thread, which is
also where core calls it from the kernel poller's results.
"""

import math
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from statistics import median
from typing import Final

from pydantic import TypeAdapter, ValidationError

from pirewall.config.models import D1Config
from pirewall.core.enums import D1Detector, Protocol
from pirewall.core.models.common import UnicastMacAddress
from pirewall.core.models.evidence_v2 import D1Evidence
from pirewall.core.models.flow import Flow
from pirewall.core.models.identity import Binding
from pirewall.detection_v2.thresholds import D1ThresholdFile, Scope, ThresholdKey
from pirewall.features.extractor import extract_features

__all__ = [
    "ConnectionStart",
    "D1Counters",
    "D1State",
    "start_from_features",
    "start_from_record",
    "start_from_signal",
    "unicast_mac",
]

_UNICAST: Final[TypeAdapter[str]] = TypeAdapter(UnicastMacAddress)


def unicast_mac(value: str | None) -> str | None:
    """`value` normalised, or None when it is absent or not a unicast MAC (D3: never an identity)."""
    if value is None:
        return None
    try:
        return _UNICAST.validate_python(value)
    except ValidationError:
        return None


@dataclass(frozen=True, slots=True)
class ConnectionStart:
    """One connection start by one device.

    `failed`, `duration_seconds` and `byte_count` are None for a
    creation-time signal, which has not seen the connection's outcome.
    """

    mac: str
    source_ip: IPv4Address
    destination_ip: IPv4Address
    destination_port: int | None
    at: datetime
    failed: bool | None = None
    duration_seconds: float | None = None
    byte_count: int | None = None

    @property
    def has_outcome(self) -> bool:
        """True for a completed record, False for a creation-time signal."""
        return self.failed is not None


def start_from_features(
    *,
    is_start: bool,
    source_mac: str | None,
    source_ip: IPv4Address,
    destination_ip: IPv4Address,
    destination_port: int | None,
    first_seen: datetime,
    features: Mapping[str, float],
) -> ConnectionStart | None:
    """A completed record as a `ConnectionStart`, from its canonical feature values.

    The outcome comes from `pirewall.features` columns, not from the raw
    record, so the live path (`start_from_record`) and the threshold
    fitter (`pcap_to_flows` rows) derive it identically (CLAUDE.md "one
    canonical feature-extraction module"). A handshake failed when the
    responder never answered, or the exchange ended within a handshake's
    three packets without one payload byte (closed port, or a SYN scan's
    own RST after the SYN-ACK). Size similarity uses payload bytes.
    """
    mac = unicast_mac(source_mac)
    if not is_start or mac is None:
        return None
    packets = features["packet_count"]
    payload = features["payload_byte_count"]
    failed = features["backward_packet_count"] == 0 or (packets <= 3 and payload == 0)
    return ConnectionStart(
        mac=mac,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        at=first_seen,
        failed=failed,
        duration_seconds=max(features["duration_seconds"], 0.0),
        byte_count=int(payload),
    )


def start_from_record(flow: Flow, is_start: bool) -> ConnectionStart | None:
    """A completed record as a `ConnectionStart`, or None when it is not one (or has no device MAC).

    `is_start` is `ConnectionStartTracker.observe(flow)`. Features are only
    extracted for actual starts.
    """
    if not is_start or unicast_mac(flow.source_mac) is None:
        return None
    vector = extract_features(flow)
    return start_from_features(
        is_start=True,
        source_mac=flow.source_mac,
        source_ip=flow.source_ip,
        destination_ip=flow.destination_ip,
        destination_port=flow.destination_port,
        first_seen=flow.first_seen,
        features=dict(zip(vector.feature_names, vector.values, strict=True)),
    )


def start_from_signal(
    *,
    source_mac: str | None,
    source_ip: IPv4Address,
    destination_ip: IPv4Address,
    destination_port: int | None,
    protocol: Protocol,
    at: datetime,
) -> ConnectionStart | None:
    """A creation-time TCP signal as an outcome-less `ConnectionStart` (cardinality detectors only)."""
    mac = unicast_mac(source_mac)
    if protocol is not Protocol.TCP or mac is None:
        return None
    return ConnectionStart(mac, source_ip, destination_ip, destination_port, at)


@dataclass(slots=True)
class D1Counters:
    """Evictions and drops, so bounded state is visible rather than silent."""

    macs_evicted: int = 0
    destinations_evicted: int = 0
    events_dropped: int = 0
    accounts_evicted: int = 0
    known_macs_evicted: int = 0


@dataclass(slots=True)
class _Device:
    last_ip: IPv4Address
    events: deque[ConnectionStart]
    # destination -> (concurrent slow connections, when observed)
    slow: dict[IPv4Address, tuple[int, datetime]] = field(
        default_factory=dict[IPv4Address, tuple[int, datetime]]
    )


class D1State:
    """Sliding per-MAC (and per-destination, per-account, LAN-wide) state, and the detectors over it."""

    def __init__(
        self, config: D1Config, thresholds: D1ThresholdFile, extra_brute_force_ports: Iterable[int] = ()
    ) -> None:
        """`extra_brute_force_ports` adds e.g. the portal's listen port to `config.brute_force_ports`."""
        self._config = config
        self._thresholds = thresholds
        self._windows = tuple(sorted(set(config.windows_seconds)))
        self._horizon = timedelta(seconds=max(self._windows))
        self._brute_ports = frozenset((*config.brute_force_ports, *extra_brute_force_ports))
        self._devices: OrderedDict[str, _Device] = OrderedDict()
        self._destinations: OrderedDict[IPv4Address, deque[tuple[datetime, str]]] = OrderedDict()
        self._known_macs: OrderedDict[str, None] = OrderedDict()
        self._known_leases: OrderedDict[tuple[IPv4Address, str], None] = OrderedDict()
        self._new_macs: deque[datetime] = deque(maxlen=config.max_events_per_mac)
        self._new_leases: deque[datetime] = deque(maxlen=config.max_events_per_mac)
        self._accounts: OrderedDict[str, deque[tuple[datetime, str | None]]] = OrderedDict()
        self._portal_failures: deque[datetime] = deque(maxlen=config.max_events_per_mac)
        self._leases_seeded = False
        self.counters = D1Counters()

    # ------------------------------------------------------------------ input

    @property
    def thresholds(self) -> D1ThresholdFile:
        """The thresholds in force."""
        return self._thresholds

    def replace_thresholds(self, thresholds: D1ThresholdFile) -> None:
        """Hot-reload thresholds (critique_round2 item 9c); the sliding state is kept."""
        self._thresholds = thresholds

    def observe(self, start: ConnectionStart) -> None:
        """Fold one connection start into the device's and the destination's windows."""
        device = self._device(start.mac, start.source_ip)
        if len(device.events) == device.events.maxlen:
            self.counters.events_dropped += 1
        device.events.append(start)
        self._note_mac(start.mac, start.at)
        arrivals = self._destinations.get(start.destination_ip)
        if arrivals is None:
            arrivals = deque[tuple[datetime, str]](maxlen=self._config.max_events_per_mac)
            self._destinations[start.destination_ip] = arrivals
            if len(self._destinations) > self._config.max_tracked_destinations:
                self._destinations.popitem(last=False)
                self.counters.destinations_evicted += 1
        else:
            self._destinations.move_to_end(start.destination_ip)
        arrivals.append((start.at, start.mac))

    def observe_slow_cluster(
        self, mac: str | None, source_ip: IPv4Address, destination_ip: IPv4Address, count: int, at: datetime
    ) -> None:
        """Record `count` concurrent slow connections from `mac` to `destination_ip` (v1 B2 clusters)."""
        normalised = unicast_mac(mac)
        if normalised is None:
            return
        device = self._device(normalised, source_ip)
        device.slow[destination_ip] = (count, at)
        if len(device.slow) > self._config.max_tracked_destinations:
            oldest = min(device.slow, key=lambda destination: device.slow[destination][1])
            del device.slow[oldest]
            self.counters.destinations_evicted += 1

    def observe_bindings(self, bindings: Sequence[Binding], at: datetime) -> None:
        """Diff the binding table: each (IP, MAC) never seen before is one new lease.

        The first call only seeds what is known, so a restart does not read
        the whole lease file as a lease-starvation burst.
        """
        for binding in bindings:
            key = (binding.ip, str(binding.mac))
            if key in self._known_leases:
                self._known_leases.move_to_end(key)
                continue
            self._known_leases[key] = None
            if len(self._known_leases) > self._config.max_known_macs:
                self._known_leases.popitem(last=False)
            if self._leases_seeded:
                self._new_leases.append(at)
        self._leases_seeded = True

    def observe_portal_failure(self, account: str, mac: str | None, at: datetime) -> None:
        """One failed portal login for `account` (from `mac`, when its binding is known)."""
        failures = self._accounts.get(account)
        if failures is None:
            failures = deque[tuple[datetime, str | None]](maxlen=self._config.max_events_per_mac)
            self._accounts[account] = failures
            if len(self._accounts) > self._config.max_tracked_accounts:
                self._accounts.popitem(last=False)
                self.counters.accounts_evicted += 1
        else:
            self._accounts.move_to_end(account)
        failures.append((at, unicast_mac(mac)))
        self._portal_failures.append(at)

    def _device(self, mac: str, source_ip: IPv4Address) -> _Device:
        device = self._devices.get(mac)
        if device is None:
            device = _Device(source_ip, deque(maxlen=self._config.max_events_per_mac))
            self._devices[mac] = device
            if len(self._devices) > self._config.max_tracked_macs:
                self._devices.popitem(last=False)
                self.counters.macs_evicted += 1
        else:
            self._devices.move_to_end(mac)
            device.last_ip = source_ip
        return device

    def _note_mac(self, mac: str, at: datetime) -> None:
        if mac in self._known_macs:
            self._known_macs.move_to_end(mac)
            return
        self._known_macs[mac] = None
        if len(self._known_macs) > self._config.max_known_macs:
            self._known_macs.popitem(last=False)
            self.counters.known_macs_evicted += 1
        self._new_macs.append(at)

    # ----------------------------------------------------------------- queries

    def last_ip(self, mac: str) -> IPv4Address | None:
        """The source IP `mac` was last seen using, or None if it is not tracked."""
        device = self._devices.get(mac)
        return None if device is None else device.last_ip

    def tracked_macs(self) -> int:
        """Devices currently tracked."""
        return len(self._devices)

    # -------------------------------------------------------------- detectors

    def measure_device(self, mac: str, now: datetime) -> dict[ThresholdKey, float]:
        """Every per-device detector's value, every window, for `mac` at `now` (no thresholds).

        `evaluate_device` compares these with the thresholds; the fitting
        script collects them over benign traffic. One function, so a fitted
        threshold and a live comparison measure the same thing.
        """
        device = self._devices.get(mac)
        if device is None:
            return {}
        self._prune(device.events, now)
        measured: dict[ThresholdKey, float] = {}
        for window in self._windows:
            since = now - timedelta(seconds=window)
            events = [event for event in device.events if since <= event.at <= now]
            values: dict[D1Detector, float] = {
                D1Detector.VERTICAL_SCAN: _max_distinct(
                    events, lambda e: e.destination_ip, lambda e: e.destination_port
                ),
                D1Detector.HORIZONTAL_SCAN: _max_distinct(
                    events, lambda e: e.destination_port, lambda e: e.destination_ip
                ),
                D1Detector.BRUTE_FORCE: self._brute_force(events),
                D1Detector.SLOW_RATE_DOS: float(
                    max(
                        (count for count, at in device.slow.values() if since <= at <= now),
                        default=0,
                    )
                ),
            }
            ratio = self._failed_ratio(events)
            if ratio is not None:
                values[D1Detector.FAILED_HANDSHAKE] = ratio
            for detector, value in values.items():
                measured[ThresholdKey(detector, "device", window)] = value
        return measured

    def evaluate_device(self, mac: str, now: datetime) -> list[D1Evidence]:
        """Every per-device detector, every window, for `mac` at `now`."""
        found: list[D1Evidence] = []
        for key, value in self.measure_device(mac, now).items():
            evidence = self._fire(key.detector, key.scope, key.window_seconds, value, mac, mac, now)
            if evidence is not None:
                found.append(evidence)
        return found

    def measure_destination(self, destination: IPv4Address, now: datetime) -> dict[ThresholdKey, float]:
        """Fan-in toward `destination` per window: distinct MACs opening connections to it."""
        arrivals = self._destinations.get(destination)
        if arrivals is None:
            return {}
        horizon = now - self._horizon
        while arrivals and arrivals[0][0] < horizon:
            arrivals.popleft()
        measured: dict[ThresholdKey, float] = {}
        for window in self._windows:
            since = now - timedelta(seconds=window)
            macs = {mac for at, mac in arrivals if since <= at <= now}
            measured[ThresholdKey(D1Detector.FAN_IN, "destination", window)] = float(len(macs))
        return measured

    def evaluate_destination(self, destination: IPv4Address, now: datetime) -> list[D1Evidence]:
        """Fan-in toward `destination`: no single MAC, so the evidence names none."""
        found: list[D1Evidence] = []
        for key, value in self.measure_destination(destination, now).items():
            evidence = self._fire(
                key.detector, key.scope, key.window_seconds, value, None, str(destination), now
            )
            if evidence is not None:
                found.append(evidence)
        return found

    def measure_global(self, now: datetime) -> dict[ThresholdKey, float]:
        """LAN-wide new-MAC rate, new-lease rate and portal failures, per window."""
        measured: dict[ThresholdKey, float] = {}
        for window in self._windows:
            since = now - timedelta(seconds=window)
            for detector, series in (
                (D1Detector.NEW_MAC_RATE, self._new_macs),
                (D1Detector.NEW_LEASE_RATE, self._new_leases),
                (D1Detector.PORTAL_AUTH_FAILURES, self._portal_failures),
            ):
                measured[ThresholdKey(detector, "global", window)] = float(
                    sum(1 for at in series if since <= at <= now)
                )
        return measured

    def evaluate_global(self, now: datetime) -> list[D1Evidence]:
        """New-MAC rate, new-lease rate, portal failures (per account and LAN-wide)."""
        found: list[D1Evidence] = []
        for key, value in self.measure_global(now).items():
            evidence = self._fire(key.detector, key.scope, key.window_seconds, value, None, "lan", now)
            if evidence is not None:
                found.append(evidence)
        for window in self._windows:
            since = now - timedelta(seconds=window)
            for account, failures in self._accounts.items():
                recent = [mac for at, mac in failures if since <= at <= now]
                macs = set(recent)
                # One device behind every failure: the evidence can name it.
                culprit = next(iter(macs)) if len(macs) == 1 else None
                evidence = self._fire(
                    D1Detector.PORTAL_AUTH_FAILURES,
                    "account",
                    window,
                    float(len(recent)),
                    culprit,
                    f"account={account}",
                    now,
                )
                if evidence is not None:
                    found.append(evidence)
        return found

    def destinations(self) -> tuple[IPv4Address, ...]:
        """Destinations with fan-in state, most recent last."""
        return tuple(self._destinations)

    # ---------------------------------------------------------------- helpers

    def _prune(self, events: deque[ConnectionStart], now: datetime) -> None:
        horizon = now - self._horizon
        while events and events[0].at < horizon:
            events.popleft()

    def _failed_ratio(self, events: Sequence[ConnectionStart]) -> float | None:
        completed = [event for event in events if event.has_outcome]
        if len(completed) < self._config.failed_handshake_min_starts:
            return None
        return sum(1 for event in completed if event.failed) / len(completed)

    def _brute_force(self, events: Sequence[ConnectionStart]) -> float:
        groups: dict[tuple[IPv4Address, int], list[int]] = {}
        limit = self._config.brute_force_max_duration_seconds
        for event in events:
            if (
                event.destination_port in self._brute_ports
                and event.duration_seconds is not None
                and event.duration_seconds <= limit
                and event.byte_count is not None
                and not event.failed
            ):
                assert event.destination_port is not None
                groups.setdefault((event.destination_ip, event.destination_port), []).append(event.byte_count)
        tolerance = self._config.brute_force_size_tolerance
        best = 0
        for sizes in groups.values():
            centre = median(sizes)
            similar = sum(1 for size in sizes if abs(size - centre) <= tolerance * max(centre, 1.0))
            best = max(best, similar)
        return float(best)

    def _fire(
        self,
        detector: D1Detector,
        scope: Scope,
        window: int,
        value: float,
        mac: str | None,
        subject: str,
        now: datetime,
    ) -> D1Evidence | None:
        threshold = self._thresholds.value(ThresholdKey(detector, scope, window))
        if threshold is None or value <= threshold:
            return None
        bucket = math.floor(now.timestamp() / window)
        return D1Evidence(
            # Deterministic: the same detector over the same window bucket is
            # the *same* evidence, so re-evaluating cannot escalate (D4).
            id=f"d1:{detector.value}:{scope}:{window}:{subject}:{bucket}",
            detector=detector,
            window_seconds=window,
            value=value,
            threshold=threshold,
            mac=mac,
            observed_at=now,
        )


def _max_distinct[K, V](
    events: Iterable[ConnectionStart],
    group: Callable[[ConnectionStart], K],
    member: Callable[[ConnectionStart], V],
) -> float:
    buckets: dict[K, set[V]] = {}
    for event in events:
        buckets.setdefault(group(event), set()).add(member(event))
    return float(max((len(members) for members in buckets.values()), default=0))


def thresholds_by_name(thresholds: D1ThresholdFile) -> Mapping[str, float]:
    """`{name: value}` for display and the API."""
    return {name: entry.value for name, entry in thresholds.thresholds.items()}
