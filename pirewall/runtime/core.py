"""`CoreDaemon`: the pirewall-core process (ADDENDUM.md A4, A6; spec §42).

One `CoreDaemon` owns every long-lived object in the privileged process and
every thread that touches them. `pirewall.main` does nothing but load
config, set up logging, build one of these, and run it.

Threads, and why there is more than one
---------------------------------------

===================  =========================================================
`capture`            Python path: blocks in `recv()` on the `AF_PACKET`
                     socket, parses each packet, feeds `FlowAggregator`.
                     Native path (`capture.backend`, docs/ARCHITECTURE.md):
                     polls a `TPACKET_V3` ring whose packets are parsed and
                     aggregated in Rust with the GIL released, then drains
                     the engine. Either way, completed flows go to the
                     detection thread through a bounded queue.
`detection`          Drains that queue and runs `FlowPipeline` per flow. Runs
                     known-attack (LightGBM) and behavior analysis inline;
                     hands anomaly scoring off to the `anomaly-inference`
                     thread instead of calling Isolation Forest itself (see
                     below).
`anomaly-inference`  Only spawned when an Isolation Forest model is loaded.
                     Batch-scores flows handed off by the detection thread —
                     one `decision_function` call per batch instead of one
                     per flow (ADDENDUM_2 follow-up pass, section 3) — then
                     finishes each flow's pipeline processing itself.
`sweep`              Flow active/inactive timeouts and adaptive-rule TTL
                     expiry, on `flow.cleanup_interval_seconds`.
`rpc`                `UnixSocketRpcServer.serve_until_stopped` — pirewall-api's
                     only way in.
`lease-sync`         Re-reads the dnsmasq lease file (inotify + poll) into the
                     IP<->MAC `LeaseBindingTable` and writes changes to the
                     kernel binding sets (`pirewall.runtime.lease_sync`,
                     ADDENDUM_4.md D3). Never takes the RPC lock.
`v2-watch`           Once a second: checks that the v2 tables still exist
                     (CRITICAL on loss; core never recreates them, D5),
                     reads the guard modes back from the kernel, and
                     publishes them and the engine counters to
                     `V2Snapshots`, which the four v2 read RPCs serve
                     without the RPC lock. Never takes the RPC lock.
main thread          `sd_notify` watchdog heartbeats, capture-statistics
                     refresh, and Netdata export.
===================  =========================================================

Enforcement backend (phase 16)
------------------------------

With nothing injected, adaptive enforcement runs on the v2 set path:
`NftablesSetBackend` into `inet pirewall_adaptive`, plus the binding and
allowlist sets in `pirewall_static`. `pirewall-start` loads those tables
before core starts; core reconciles with their live contents at start and
never creates or deletes a table. The v1 `NftablesBackend` is still built,
because the captive portal's `authed` set lives on it (C2).
`mock_firewall=True` (`pirewall.main --data-mode mock`) swaps both for the
in-memory fakes: no root, no nft, nothing on the host changes.

Capture selection
-----------------

`capture.backend` picks the path: `replay` reads pcaps through the same
engine (`pirewall.capture.replay`), `python` forces `AFPacketCapture`, and
`auto`/`native` use the TPACKET_V3 ring when the extension is installed.
A replay sweeps flows on **its own clock** (the capture time of the last
frame fed), from the capture thread, every `flow.cleanup_interval_seconds`
of capture time: at `max` speed an hour of traffic passes in seconds, and
the wall clock would expire nothing until the replay had ended. When the
replay runs out, every flow still open is flushed to detection once.

On the native ring, a caught engine panic (ADDENDUM_4.md D6) costs the poll
or drain in flight and is reported as a `CAPTURE_ERROR` WARNING.
`capture.native_max_panics_per_minute` of them within 60 s abandons the
ring for the Python `AFPacketCapture` path, salvaging the engine's open
flows, with a CRITICAL event. A replay has no live fallback: it stops.

Capture and detection are separated because they run at wildly different
speeds. Single-flow Isolation Forest scoring was measured at ~30.7 ms/call on
a real Pi 4 — 92% of total packet-to-decision cost, and the dominant cause of
a 38.5% packet-drop rate under sustained load
(`benchmarks/2026-08-30/REPORT.md` §3-4). Detection and anomaly-inference are
separated from each other for the same reason capture and detection are: so
one slow stage cannot stall a faster one. Every cross-thread queue in this
class (`_flow_queue`, `_new_flow_queue`, `_slow_cluster_queue`,
`_anomaly_queue`) is **bounded** and drops on overflow rather than blocking
its producer — a backlog in one stage must cost that stage's own coverage,
never a faster stage's throughput. Drops are always counted and reported,
never silent.

Shutdown
--------

`SIGTERM`/`SIGINT` set one `threading.Event`. The main loop notices, tells
systemd `STOPPING=1`, stops capture (which unblocks the capture thread's
`recv()`), joins every thread with a timeout, and closes the RPC socket.

**On a clean shutdown under `failure.mode = fail_open` (the default, A6)
the adaptive ruleset is removed.** nftables rules live in the kernel and
outlive the process that created them, so leaving them behind would mean a
stopped pirewall keeps blocking traffic with nothing left running to expire
it — the opposite of failing open. Under `fail_closed` they are
deliberately left in place. This goes through
`FirewallManager.fail_open_shutdown`, not a special-cased backend call
(CLAUDE.md). With a set backend that flushes the adaptive sets and leaves
every static guard's mode alone (D5), so a crash loop does not switch
protection off (audit #17); it is not the kill switch, which would also set
every guard to observe. Without a set backend it is the v1 revert.
"""

import logging
import queue
import signal
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path
from types import FrameType
from typing import Literal

from pirewall.capture.af_packet import AFPacketCapture
from pirewall.capture.interfaces import FlowCapture, PacketCapture, TcpPayload
from pirewall.capture.native import NativePacketCapture, native_capture_available
from pirewall.capture.parser import extract_tcp_payload
from pirewall.capture.pipeline import capture_packets
from pirewall.capture.replay import ReplayCapture, ReplayPacketCapture, build_replay_capture
from pirewall.config.models import PirewallConfig
from pirewall.core import nft_names
from pirewall.core.binding_table import BindingTable
from pirewall.core.bindings import LeaseBindingTable, static_bindings
from pirewall.core.enums import (
    EnforcementMode,
    EventSeverity,
    FailureMode,
    GuardMode,
    GuardName,
    PipelineEngine,
    Protocol,
    SecurityEventType,
)
from pirewall.core.exceptions import (
    CaptureError,
    ConfigurationError,
    FirewallError,
    ModelInferenceError,
    NativeEngineError,
    PirewallError,
)
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.evidence import ProtocolSignatureEvidence
from pirewall.core.models.flow import Flow
from pirewall.core.models.packet import PacketMetadata
from pirewall.core.network_drift import check_network_drift
from pirewall.detection.anomaly import detect_batch as detect_anomaly_batch
from pirewall.detection.coordinator import DetectionCoordinator, load_models, with_anomaly_evidence
from pirewall.detection.tls_fingerprint import (
    compute_ja3,
    load_known_tool_fingerprints,
    match_known_tool,
)
from pirewall.detection.tls_heartbeat import check_heartbleed
from pirewall.detection_v2.kernel import KernelPoller
from pirewall.detection_v2.thresholds import D1ThresholdFile, floors_file, load_thresholds
from pirewall.firewall.allowlist_store import AllowlistStore
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from pirewall.firewall.backend.nftables import NftablesBackend
from pirewall.firewall.backend.nftables_sets import NftablesSetBackend
from pirewall.firewall.interface import FirewallBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.firewall.sets import SetBackend
from pirewall.flow.aggregator import FlowAggregator, NewFlowSignal, SlowConnectionCluster
from pirewall.flow.fallback import NativePanicBudget
from pirewall.flow.key import FlowKey, compute_flow_key
from pirewall.flow.native import NativeFlowAggregator, from_microseconds, native_engine_available
from pirewall.integration.netdata import NetdataExporter, StatsdNetdataTransport
from pirewall.integration.wazuh import SyslogWazuhTransport, WazuhForwarder
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.portal_dispatcher import PortalRpcDispatcher
from pirewall.ipc.portal_service import PortalService
from pirewall.ipc.protocol import RpcRequest, RpcResponse
from pirewall.ipc.protocol_v2 import EngineStats, OffenderEntry
from pirewall.ipc.server import UnixSocketRpcServer
from pirewall.ipc.snapshots import V2Snapshots
from pirewall.ipc.state import CoreStateStore
from pirewall.policy.table import load_policy_table
from pirewall.portal.store import PortalUserStore
from pirewall.runtime.forwarder import EventForwarder
from pirewall.runtime.lease_sync import LeaseSync
from pirewall.runtime.metrics import MetricsCollector, RuntimeCounters
from pirewall.runtime.pipeline import FlowPipeline, PendingAnomalyScoring
from pirewall.runtime.pipeline_v2 import V2Pipeline
from pirewall.runtime.watchdog import SystemdNotifier

_logger = logging.getLogger(__name__)
_SUBSYSTEM = "runtime.core"

# Completed flows awaiting detection. Bounded so a detection backlog costs
# bounded memory on a `MemoryMax=768M` Pi rather than growing until the OOM
# killer intervenes. At ~1 KiB per `Flow` this is a few MiB.
_FLOW_QUEUE_MAX = 10_000
# New-flow-opened signals awaiting the detection thread (ADDENDUM_2.md B1).
# Far smaller and cheaper per-item than a `Flow` (five plain fields, no
# accumulated stats), and a burst of new connections — the exact case this
# queue exists to make visible quickly — can legitimately open far more
# flows per second than complete in the same window, so this is sized well
# above `_FLOW_QUEUE_MAX`.
_NEW_FLOW_QUEUE_MAX = 50_000
# Slow-connection clusters awaiting the detection thread (ADDENDUM_2.md B2).
# One entry per distinct (source, destination) pair currently exceeding the
# concurrent-slow-connection threshold, produced at most once per sweep
# interval — orders of magnitude fewer than either flow queue.
_SLOW_CLUSTER_QUEUE_MAX = 1_000
# Bounded LRU cache of TLS structural matches awaiting the flow they belong
# to (ADDENDUM_2.md B4/B5), keyed by the same undirected `FlowKey` the flow
# table itself uses. Written by the capture thread, read/popped by the
# detection thread — see `_handle_tcp_payload`/`_pop_tls_evidence`.
_TLS_EVIDENCE_CACHE_MAX = 10_000
# Flows awaiting batched anomaly scoring (ADDENDUM_2 follow-up pass, section
# 3), written by the detection thread and drained by the dedicated
# anomaly-inference thread. Sized well above the default
# `detection.anomaly_batch_size` (50) so a burst can queue up several
# batches' worth of flows before backpressure kicks in, but still bounded —
# an unbounded queue here would just move the OOM risk `_FLOW_QUEUE_MAX`
# already exists to avoid one stage later.
_ANOMALY_QUEUE_MAX = 5_000
# How long one native ring poll may block before re-checking the stop flag
# (also bounds how long `stop()` waits for the ring to close).
_NATIVE_POLL_TIMEOUT_MS = 100
# How long the queue drain waits before re-checking the stop flag.
_QUEUE_POLL_SECONDS = 0.5
# Threads get this long to finish after `stop()` before the process gives up
# waiting on them. Every one is a daemon thread, so a wedged thread delays
# shutdown by at most this and cannot prevent it.
_THREAD_JOIN_TIMEOUT_SECONDS = 5.0
# Report dropped-flow backpressure at most this often, so a sustained
# overload produces a steady signal instead of a log flood.
_BACKPRESSURE_REPORT_INTERVAL = 1000
# ADDENDUM_4.md D5: "core checks every second that both tables exist".
_V2_WATCH_INTERVAL_SECONDS = 1.0

# The pipelines this core can run: v1 (the merged-main baseline) and,
# since phase 17, v2 (the policy engine). A config naming anything else is
# refused at startup rather than silently run as something else.
IMPLEMENTED_ENGINES: frozenset[PipelineEngine] = frozenset({PipelineEngine.V1, PipelineEngine.V2})


def check_engine_implemented(config: PirewallConfig) -> None:
    """Raise `ConfigurationError` if `pipeline.engine` names a pipeline this core does not have."""
    engine = config.pipeline.engine
    if engine not in IMPLEMENTED_ENGINES:
        available = ", ".join(sorted(item.value for item in IMPLEMENTED_ENGINES))
        raise ConfigurationError(
            f'pipeline.engine = "{engine.value}" is not implemented in this pirewall-core '
            f"(available: {available})."
        )


def load_v2_thresholds(config: PirewallConfig) -> D1ThresholdFile:
    """The D1 thresholds `engine = "v2"` runs with, or `ConfigurationError`.

    ASSISTED and ACTIVE refuse to start without a valid `d1.thresholds_path`
    (phase 17): an enforcing engine must not run on thresholds nobody
    reviewed. SHADOW falls back to the documented floors, which can only
    produce SHADOWED records.
    """
    try:
        return load_thresholds(config.d1.thresholds_path)
    except ConfigurationError as exc:
        if config.firewall.enforcement_mode is EnforcementMode.SHADOW:
            _logger.warning("%s; SHADOW mode runs on the documented D1 floors", exc)
            return floors_file(config.d1.windows_seconds, {"reason": "thresholds file unavailable"})
        raise ConfigurationError(
            f'pipeline.engine = "v2" in {config.firewall.enforcement_mode.value} mode needs the D1 '
            f"thresholds file: {exc}. Write it with scripts/train/fit_d1_thresholds.py."
        ) from exc


class _ManagerKernelReader:
    """`KernelReader` over `FirewallManager`'s read-only kernel views (phase 17's tier-K poller)."""

    def __init__(self, manager: FirewallManager) -> None:
        self._manager = manager

    def offenders(self) -> list[tuple[str, int]]:
        return self._manager.kernel_offenders()

    def counters(self, names: Iterable[str]) -> dict[str, int]:
        return self._manager.kernel_counters(names)

    def guard_modes(self) -> dict[GuardName, GuardMode]:
        modes = self._manager.guard_modes(datetime.now(UTC))
        return {GuardName.RAW: modes.raw, GuardName.INPUT: modes.input, GuardName.FORWARD: modes.forward}

    def static_table_present(self) -> bool:
        return (nft_names.INET_FAMILY, nft_names.STATIC_TABLE) not in self._manager.missing_tables()

    def set_fill(self, table: str, set_name: str) -> tuple[int, int | None]:
        fill = self._manager.kernel_set_fill(table, set_name)
        return fill.count, fill.size


def _describe_tables(tables: Iterable[tuple[str, str]]) -> str:
    return ", ".join(f"{family} {table}" for family, table in tables)


class _ReplayClockSink:
    """A `FrameSink` that runs `on_time(ts_us)` before feeding each frame to the native engine.

    `ReplayCapture.poll` feeds frames in a loop, so this is where the
    capture thread can see the replay clock cross a sweep boundary between
    two frames rather than only at the end of a poll.
    """

    def __init__(self, aggregator: NativeFlowAggregator, on_time: Callable[[int], None]) -> None:
        self._aggregator = aggregator
        self._on_time = on_time

    def feed_us(self, raw: bytes, ts_us: int) -> None:
        self._on_time(ts_us)
        self._aggregator.feed_us(raw, ts_us)

    def counters(self) -> tuple[int, int]:
        return self._aggregator.counters()


@dataclass(frozen=True, slots=True)
class _CachedTlsMatch:
    """One TLS structural match awaiting the flow it belongs to (ADDENDUM_2.md B4/B5).

    Not `ProtocolSignatureEvidence` itself: that model requires `flow_id`,
    which isn't assigned until the flow actually completes
    (`pirewall.flow.aggregator.FlowAggregator` mints it via `uuid4()` at
    finalization) — long after the packet that revealed this match was
    seen. `_pop_tls_evidence` fills in the real `flow_id` once it's known.
    """

    signature: str
    confidence: float
    detail: str
    generated_at: datetime


class _SynchronizedDispatcher(CoreRpcDispatcher):
    """`CoreRpcDispatcher` with every call serialized against the pipeline's writers.

    The RPC thread reads `CoreStateStore` and `FirewallManager` (and, for
    `disable_rule`/`approve_rule`/the kill-switch, *writes* them) while the
    detection thread is writing both. Neither class is thread-safe on its
    own, and neither should be: they are pure domain logic that has no
    business knowing a daemon runs them on several threads. Holding the
    daemon's lock around `handle()` is the smallest change that makes them
    safe here, and it keeps every RPC operation atomic with respect to the
    pipeline — a `/status` response can never observe a half-applied rule
    transition.
    """

    def __init__(
        self,
        lock: AbstractContextManager[bool],
        state: CoreStateStore,
        manager: FirewallManager,
        config: PirewallConfig,
        portal: PortalService | None = None,
        snapshots: V2Snapshots | None = None,
        on_event: Callable[[SecurityEvent], None] | None = None,
    ) -> None:
        super().__init__(state, manager, config, portal=portal, snapshots=snapshots, on_event=on_event)
        self._lock = lock

    def handle(self, request: RpcRequest) -> RpcResponse:
        # The v2 reads touch only published immutable snapshots
        # (V2_CONTRACTS §9), so they never queue behind the pipeline.
        if request.operation in self.LOCK_FREE_OPERATIONS:
            return super().handle(request)
        with self._lock:
            return super().handle(request)


class _SynchronizedPortalDispatcher(PortalRpcDispatcher):
    """`PortalRpcDispatcher` under the same daemon lock, for the same reason.

    Portal operations write `FirewallManager` (they add and remove nft set
    elements) and read its rule table, both of which the detection thread is
    also touching. Serializing on the daemon's one lock keeps a login atomic
    with respect to a rule being deployed against the same address — which
    matters, because those two racing is exactly the case where a blocked
    device could otherwise be handed a working session.
    """

    def __init__(self, lock: AbstractContextManager[bool], service: PortalService) -> None:
        super().__init__(service)
        self._lock = lock

    def handle(self, request: RpcRequest) -> RpcResponse:
        with self._lock:
            return super().handle(request)


class CoreDaemon:
    """Owns pirewall-core's subsystems, threads, and lifecycle."""

    def __init__(
        self,
        config: PirewallConfig,
        capture: PacketCapture | FlowCapture | None = None,
        backend: FirewallBackend | None = None,
        notifier: SystemdNotifier | None = None,
        flow_queue_max: int = _FLOW_QUEUE_MAX,
        anomaly_queue_max: int = _ANOMALY_QUEUE_MAX,
        native_aggregator: NativeFlowAggregator | None = None,
        set_backend: SetBackend | None = None,
        *,
        mock_firewall: bool = False,
    ) -> None:
        """Build every subsystem. `capture`/`backend`/`notifier` are injectable for testing.

        Enforcement backends, in order of precedence:

        * `mock_firewall=True`: `FakeFirewallBackend` + a `FakeSetBackend`
          loaded with the configured guard modes, unless either is injected.
          Used by `--data-mode mock`; nothing reaches the kernel.
        * Nothing injected (production): the real `NftablesBackend` for the
          portal and `NftablesSetBackend` for adaptive enforcement, the
          bindings and the allowlist copy (ADDENDUM_4.md D1).
        * `backend` injected without `set_backend`: the v1 rule path, kept
          as a test seam. Lease sync still keeps the binding table current
          (the portal, rule targets and the C4 checks read it) but writes no
          kernel sets.

        Injecting `FakePacketCapture` and `FakeFirewallBackend` is what lets
        the whole daemon run without root, without a NIC, and without
        touching a real nftables ruleset (CLAUDE.md's Protocol/Fake rule).
        An injected `FlowCapture` (e.g. `FakeFlowCapture`) runs the native
        path and must come with the `native_aggregator` whose engine it
        feeds. With nothing injected, `capture.backend` picks the path.

        Raises `ConfigurationError` when `pipeline.engine` names a pipeline
        this core does not implement (`check_engine_implemented`).
        """
        check_engine_implemented(config)
        self._config = config
        self._started_at = datetime.now(UTC)
        self._stop = threading.Event()
        # The signal that asked for shutdown, logged by `run()` (never by the handler).
        self._stop_signal: int | None = None
        # One lock for `CoreStateStore` + `FirewallManager`, shared with the
        # pipeline and the RPC dispatcher. Reentrant because the forwarder
        # can be called from inside a pipeline section that already holds it.
        self._lock = threading.RLock()
        # Separate lock: `FlowAggregator` is touched by the capture thread
        # (per packet) and the sweep thread (per interval) but never by RPC,
        # so contending it against the state lock would be pointless.
        self._flow_lock = threading.Lock()

        # Set when `capture.backend = "native"` was asked for but could not
        # be honoured; reported as a SYSTEM_WARNING at start().
        self._capture_fallback_reason: str | None = None
        # True when capture reads pcaps (`capture.backend = "replay"`, or an
        # injected replay): flows are then swept on the replay's own clock.
        self._replay = False
        self._capture: PacketCapture | FlowCapture
        self._native_aggregator: NativeFlowAggregator | None
        self._capture, self._native_aggregator = self._select_capture(config, capture, native_aggregator)
        self._replay = self._replay or isinstance(self._capture, ReplayCapture | ReplayPacketCapture)
        # D6: caught native panics, counted toward the live-ring fallback.
        self._panic_budget = NativePanicBudget(config.capture.native_max_panics_per_minute)
        self._panics_caught = 0
        # Cumulative (completed flows, new-flow signals) the native engine
        # shed at its per-drain caps; kept across a fallback to Python.
        self._native_shed: tuple[int, int] = (0, 0)
        # Replay clock bookkeeping (capture thread only).
        self._replay_last_sweep_us: int | None = None
        self._replay_flushed = False
        # Constructed here and handed straight to `FirewallManager`, which
        # is the only code path permitted to call into
        # `pirewall.firewall.backend` (CLAUDE.md). Deliberately not retained
        # on `self`: there must be no second reference through which the
        # daemon could deploy or remove a rule outside the manager's
        # validated lifecycle. `tests/security/test_backend_isolation.py`
        # asserts this file only ever *constructs* a backend.
        firewall_backend: FirewallBackend
        if mock_firewall:
            firewall_backend = backend or FakeFirewallBackend()
            if set_backend is None:
                set_backend = FakeSetBackend(
                    lambda: datetime.now(UTC),
                    adaptive_size=config.guards.adaptive_set_size,
                    binding_size=config.guards.binding_set_size,
                    guard_modes={
                        GuardName.RAW: config.guards.raw_mode,
                        GuardName.INPUT: config.guards.input_mode,
                        GuardName.FORWARD: config.guards.forward_mode,
                    },
                )
        else:
            if backend is None and set_backend is None:
                set_backend = NftablesSetBackend()
            firewall_backend = backend or NftablesBackend(config.firewall.rate_limit_per_second)

        self._state = CoreStateStore(
            max_history=config.api.history_size, started_at=self._started_at
        )
        # KNOWN_ISSUES.md #10: runtime-added allowlist entries persist here,
        # the same single-writer pattern as `PortalUserStore` (ADDENDUM_3.md
        # C3) — only pirewall-core ever opens this file.
        self._allowlist_store = AllowlistStore(config.firewall.allowlist_store_path)
        # ADDENDUM_4.md D3: IP<->MAC bindings, from `[[antispoof.static]]` now
        # and the lease file once `start()` seeds it. Shared read-only with
        # the manager, the pipeline and the portal; written only by lease sync.
        self._bindings = LeaseBindingTable(static_bindings(config.antispoof.static))
        self._manager = FirewallManager(
            config,
            firewall_backend,
            self._allowlist_store,
            set_backend=set_backend,
            mac_resolver=self._bindings.resolve_mac,
        )
        self._counters = RuntimeCounters()
        self._forwarder = EventForwarder(self._state, self._build_wazuh(), self._lock)
        # ADDENDUM_2.md B1: fed from the capture thread the instant a flow
        # opens, drained by the detection thread (the sole owner of
        # `BehaviorAnalyzer`'s mutable state) — see `_handle_new_flow` and
        # `_drain_new_flow_signals`.
        self._new_flow_queue: queue.Queue[NewFlowSignal] = queue.Queue(maxsize=_NEW_FLOW_QUEUE_MAX)
        self._new_flow_signals_dropped = 0
        # ADDENDUM_2.md B2 — same reasoning: populated by the sweep thread,
        # drained by the detection thread, so BehaviorAnalyzer stays
        # mutated from exactly one thread.
        self._slow_cluster_queue: queue.Queue[SlowConnectionCluster] = queue.Queue(
            maxsize=_SLOW_CLUSTER_QUEUE_MAX
        )
        self._slow_clusters_dropped = 0
        self._aggregator: FlowAggregator | NativeFlowAggregator = (
            self._native_aggregator
            if self._native_aggregator is not None
            else FlowAggregator(
                config.flow,
                on_new_flow=self._handle_new_flow,
                protected_network=config.network.protected_network,
            )
        )
        # ADDENDUM_2.md B4/B5 — written by the capture thread
        # (`_handle_tcp_payload`), read/popped by the detection thread
        # (`_pop_tls_evidence`) once the flow it belongs to completes.
        # Guarded by `_flow_lock`, same as the aggregator's own table.
        self._tls_evidence: OrderedDict[FlowKey, _CachedTlsMatch] = OrderedDict()
        # Source-level fast path: when each source was last assessed early
        # (monotonic seconds). Detection thread only; LRU-bounded.
        self._early_assessed_at: OrderedDict[IPv4Address, float] = OrderedDict()
        # ADDENDUM_2.md B5 — read once at startup; a missing/malformed file
        # degrades to no JA3 matches ever being reported (see
        # `load_known_tool_fingerprints`'s own docstring), never a startup
        # failure.
        self._known_tool_fingerprints = load_known_tool_fingerprints(
            Path(config.detection.known_tool_fingerprints_path)
        )
        _logger.info(
            "loaded %d known-tool JA3 fingerprint(s) from %s",
            len(self._known_tool_fingerprints),
            config.detection.known_tool_fingerprints_path,
        )

        models = load_models(config.ml)
        self._model_load_errors = models.load_errors
        if models.lightgbm is not None:
            self._state.lightgbm_metadata = models.lightgbm.metadata
        if models.isolation_forest is not None:
            self._state.isolation_forest_metadata = models.isolation_forest.metadata
        self._coordinator = DetectionCoordinator(
            config.detection, models, on_event=self._forwarder
        )

        # ADDENDUM_2 follow-up pass, section 3 — populated by the detection
        # thread (`_enqueue_anomaly_scoring`), drained by the dedicated
        # anomaly-inference thread (`_anomaly_inference_loop`), only when an
        # Isolation Forest model is actually loaded; otherwise anomaly
        # scoring stays inline/synchronous and this queue is never touched.
        self._anomaly_queue: queue.Queue[PendingAnomalyScoring] = queue.Queue(
            maxsize=anomaly_queue_max
        )
        self._anomaly_scores_dropped = 0
        self._pipeline = FlowPipeline(
            config=config,
            coordinator=self._coordinator,
            manager=self._manager,
            state=self._state,
            forwarder=self._forwarder,
            counters=self._counters,
            lock=self._lock,
            anomaly_scorer=(
                self._enqueue_anomaly_scoring if models.isolation_forest is not None else None
            ),
            resolve_mac=self._bindings.resolve_mac,
        )
        # Phase 17: `pipeline.engine = "v2"` (ADDENDUM_4.md D4). The v1
        # pipeline above stays built either way: it is the baseline, and its
        # anomaly path is idle under v2.
        self._engine = config.pipeline.engine
        self._v2: V2Pipeline | None = None
        self._kernel_poller: KernelPoller | None = None
        if self._engine is PipelineEngine.V2:
            self._v2 = V2Pipeline(
                config=config,
                thresholds=load_v2_thresholds(config),
                table=load_policy_table(config.policy.table_path),
                manager=self._manager,
                state=self._state,
                forwarder=self._forwarder,
                counters=self._counters,
                lock=self._lock,
                resolve_ip=self._resolve_bound_ip,
                coordinator=self._coordinator if models.lightgbm is not None else None,
            )
            if self._manager.uses_set_backend:
                self._kernel_poller = KernelPoller(
                    _ManagerKernelReader(self._manager),
                    sustained_polls=config.policy.sustained_polls,
                    set_fill_warning_ratio=config.d1.set_fill_warning_ratio,
                )
        self._flow_queue: queue.Queue[Flow] = queue.Queue(maxsize=flow_queue_max)
        # Captive portal (ADDENDUM_3.md C1). `None` when disabled, so a
        # deployment that does not want a portal pays nothing for it: no
        # user store is opened, no second socket is bound, no thread runs.
        self._portal: PortalService | None = None
        self._portal_rpc_server: UnixSocketRpcServer | None = None
        if config.portal.enabled:
            self._portal = PortalService(
                config=config,
                manager=self._manager,
                store=PortalUserStore(config.portal.user_store_path),
                on_event=self._forwarder.emit,
                bindings=self._bindings,
                on_login_failure=None if self._v2 is None else self._v2.submit_portal_failure,
            )
            # A *second* socket, in its own group, serving a dispatcher with
            # four operations. pirewall-portal is a member of only this
            # socket's group, so a compromise of the LAN-facing process
            # cannot reach the kill switch or mutate a rule — the structural
            # reason this is two sockets and not one.
            self._portal_rpc_server = UnixSocketRpcServer(
                config.portal.rpc_socket_path,
                _SynchronizedPortalDispatcher(self._lock, self._portal),
                socket_group=config.portal.rpc_socket_group,
            )

        # The v2 read views (V2_CONTRACTS §9). Bindings are served straight
        # from the table's own immutable snapshot; the rest is published by
        # the v2 watch thread.
        self._snapshots = V2Snapshots(self._bindings.snapshot)
        self._missing_tables: tuple[tuple[str, str], ...] = ()
        self._rpc_server = UnixSocketRpcServer(
            config.api.rpc_socket_path,
            _SynchronizedDispatcher(
                self._lock,
                self._state,
                self._manager,
                config,
                self._portal,
                snapshots=self._snapshots,
                # The forwarder records *and* sends to Wazuh, so events the
                # API reports (failed logins, allowlist additions) and every
                # guard flip or panic reach the collector too.
                on_event=self._forwarder.emit,
            ),
        )
        self._lease_sync = LeaseSync(config, self._bindings, self._manager, on_event=self._forwarder.emit)
        self._notifier = notifier or SystemdNotifier()
        self._metrics = MetricsCollector(
            self._counters, config.firewall.max_adaptive_rules_per_window
        )
        self._netdata = self._build_netdata()
        self._threads: list[threading.Thread] = []
        self._capture_started = False
        self._backpressure_drops = 0

    @property
    def bindings(self) -> BindingTable:
        """The live IP<->MAC binding table (read-only use: `snapshot`, `resolve_*`)."""
        return self._bindings

    @property
    def v2_pipeline(self) -> V2Pipeline | None:
        """The `engine = "v2"` pipeline, or None under v1."""
        return self._v2

    def _resolve_bound_ip(self, mac: str) -> IPv4Address | None:
        return self._bindings.resolve_ip(mac)

    @property
    def snapshots(self) -> V2Snapshots:
        """The published v2 read views the four lock-free RPCs serve."""
        return self._snapshots

    # ------------------------------------------------------------------ setup

    def _select_capture(
        self,
        config: PirewallConfig,
        capture: PacketCapture | FlowCapture | None,
        native_aggregator: NativeFlowAggregator | None,
    ) -> tuple[PacketCapture | FlowCapture, NativeFlowAggregator | None]:
        """Pick the capture path: injected, else `capture.backend` and what is installed."""
        if capture is not None:
            if isinstance(capture, FlowCapture) and not isinstance(capture, PacketCapture):
                if native_aggregator is None:
                    raise ValueError("an injected FlowCapture needs the native_aggregator it feeds")
                return capture, native_aggregator
            return capture, None

        wanted = config.capture.backend
        if wanted == "replay":
            # D7 mock/replay mode: pcaps through the same engine, no NIC, no root.
            self._replay = True
            capture, aggregator = build_replay_capture(config)
            if aggregator is None or config.capture.replay_path is None:
                return capture, aggregator
            # One poll can feed thousands of frames, minutes of capture time
            # at `max` speed, so the replay clock is checked between frames.
            sink = _ReplayClockSink(aggregator, self._sweep_on_replay_clock)
            return (
                ReplayCapture(config.capture.replay_path, sink, speed=config.capture.replay_speed),
                aggregator,
            )
        native_ready = native_engine_available() and native_capture_available()
        if wanted != "python" and native_ready:
            aggregator = NativeFlowAggregator(
                config.flow,
                config.network.protected_network,
                max_pending_completed=config.capture.native_max_flows_per_drain,
                max_pending_new_flows=config.capture.native_max_new_flows_per_drain,
            )
            return (
                NativePacketCapture(
                    interface=config.capture.interface,
                    engine=aggregator.engine,
                    promiscuous=config.capture.promiscuous,
                    block_size_bytes=config.capture.ring_block_size_bytes,
                    block_count=config.capture.ring_block_count,
                    block_timeout_ms=config.capture.ring_block_timeout_ms,
                ),
                aggregator,
            )
        if wanted == "native":
            self._capture_fallback_reason = (
                "capture.backend = native, but the pirewall-native extension is not installed "
                "(or has no AF_PACKET ring support on this platform); using the Python capture "
                "path, which drops packets under load. Install it with `uv sync --extra native`."
            )
        return (
            AFPacketCapture(
                interface=config.capture.interface,
                snap_len=config.capture.snap_len,
                promiscuous=config.capture.promiscuous,
                buffer_size_bytes=config.capture.buffer_size_bytes,
            ),
            None,
        )

    def _build_wazuh(self) -> WazuhForwarder | None:
        integration = self._config.integration
        if not integration.wazuh_enabled:
            return None
        if integration.wazuh_host is None or integration.wazuh_port is None:
            _logger.warning(
                "integration.wazuh_enabled is true but wazuh_host/wazuh_port are unset; "
                "event forwarding stays disabled"
            )
            return None
        transport = SyslogWazuhTransport(integration.wazuh_host, integration.wazuh_port)
        return WazuhForwarder(transport, enabled=True)

    def _build_netdata(self) -> NetdataExporter | None:
        integration = self._config.integration
        if not integration.netdata_enabled:
            return None
        if integration.netdata_host is None or integration.netdata_port is None:
            _logger.warning(
                "integration.netdata_enabled is true but netdata_host/netdata_port are unset; "
                "metrics export stays disabled"
            )
            return None
        transport = StatsdNetdataTransport(integration.netdata_host, integration.netdata_port)
        return NetdataExporter(transport, enabled=True)

    # -------------------------------------------------------------- lifecycle

    def install_signal_handlers(self) -> None:
        """Route SIGTERM/SIGINT to a clean shutdown. Main thread only (a Python restriction)."""
        for signal_number in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signal_number, self._handle_signal)

    def _handle_signal(self, signal_number: int, _frame: FrameType | None) -> None:
        # No logging in here: the handler runs on the main thread between
        # bytecodes, possibly in the middle of that thread's own write to the
        # log stream, and re-entering it raises (or deadlocks on a handler
        # lock). `run()` logs the signal once the wait has returned.
        self._stop_signal = signal_number
        self._stop.set()

    def start(self) -> None:
        """Bind the RPC socket, start capture, and launch every worker thread.

        Raises `PirewallError` if the RPC socket cannot be bound — that one
        is fatal, because a pirewall-core no process can reach is not a
        useful pirewall-core. A capture failure is *not* fatal here: it is
        reported as a `CAPTURE_ERROR` event and the process keeps serving
        RPC so the Admin PC can see why it is not filtering, which is far
        more useful than a crash-looping unit (A6).
        """
        for drift in check_network_drift(self._config):
            _logger.warning("network config drift: %s: %s", drift.field, drift.detail)
            self._forwarder.emit(
                SecurityEvent(
                    timestamp=datetime.now(UTC),
                    severity=EventSeverity.WARNING,
                    event_type=SecurityEventType.SYSTEM_WARNING,
                    subsystem=_SUBSYSTEM,
                    reason=f"{drift.field}: {drift.detail}",
                )
            )

        self._rpc_server.start()
        _logger.info("RPC socket listening at %s", self._config.api.rpc_socket_path)

        if self._portal_rpc_server is not None:
            self._portal_rpc_server.start()
            _logger.info(
                "portal RPC socket listening at %s", self._config.portal.rpc_socket_path
            )

        if self._capture_fallback_reason is not None:
            _logger.warning("%s", self._capture_fallback_reason)
            self._forwarder.emit(
                SecurityEvent(
                    timestamp=datetime.now(UTC),
                    severity=EventSeverity.WARNING,
                    event_type=SecurityEventType.SYSTEM_WARNING,
                    subsystem=_SUBSYSTEM,
                    reason=self._capture_fallback_reason,
                )
            )
        try:
            self._capture.start()
            self._capture_started = True
            _logger.info(
                "capture started on %s (%s path%s)",
                self._config.capture.replay_path if self._replay else self._config.capture.interface,
                "native" if self._native_aggregator is not None else "python",
                ", replay" if self._replay else "",
            )
        except CaptureError as exc:
            _logger.error("packet capture failed to start: %s", exc)
            self._forwarder.emit(
                SecurityEvent(
                    timestamp=datetime.now(UTC),
                    severity=EventSeverity.CRITICAL,
                    event_type=SecurityEventType.CAPTURE_ERROR,
                    subsystem=_SUBSYSTEM,
                    reason=f"capture unavailable, running without detection: {exc}",
                )
            )

        for error in self._model_load_errors:
            self._forwarder.emit(
                SecurityEvent(
                    timestamp=datetime.now(UTC),
                    severity=EventSeverity.WARNING,
                    event_type=SecurityEventType.MODEL_ERROR,
                    subsystem=_SUBSYSTEM,
                    reason=f"model unavailable, continuing without it: {error}",
                )
            )

        # Bindings before anything serves a request: the portal refuses a
        # login without one, and the raw guard must not trust an unseeded set.
        self._seed_bindings()
        # Then adopt whatever enforcement a previous run left in the kernel
        # (D5 "restart"), and publish the first v2 views before RPC serves.
        self._reconcile_sets()
        self._refresh_v2_snapshots()
        self._spawn("pirewall-rpc", lambda: self._rpc_server.serve_until_stopped(self._stop))
        if self._portal_rpc_server is not None:
            portal_server = self._portal_rpc_server
            self._spawn(
                "pirewall-portal-rpc", lambda: portal_server.serve_until_stopped(self._stop)
            )
        self._spawn("pirewall-detection", self._detection_loop)
        self._spawn("pirewall-sweep", self._sweep_loop)
        self._spawn("pirewall-lease-sync", lambda: self._lease_sync.run(self._stop))
        self._spawn("pirewall-v2-watch", self._v2_watch_loop)
        if self._coordinator.models.isolation_forest is not None:
            self._spawn("pirewall-anomaly-inference", self._anomaly_inference_loop)
        if self._capture_started:
            self._spawn("pirewall-capture", self._capture_loop)

        if self._portal is not None:
            # Sessions live in memory and portal grants live in the kernel,
            # so a restart leaves every previously-authorized address in
            # `@authed` with nothing behind it — still forwarding, while the
            # portal shows its owner a login page. Nobody is signed in after
            # a restart, so every surviving grant is revoked here.
            revoked = self._portal.reconcile()
            if revoked:
                _logger.warning(
                    "revoked %d orphaned portal authorization(s) left over from a previous run",
                    revoked,
                )
            # Emitted at startup, every startup, for as long as the
            # documented demo credentials still work (ADDENDUM_3.md C3).
            self._portal.warn_about_demo_accounts()

        self._notifier.notify_ready(self._status_line())
        _logger.info(
            "pirewall-core ready: enforcement=%s failure=%s models=%s",
            self._manager.enforcement_mode.value,
            self._config.failure.mode.value,
            "loaded" if self._coordinator.models.any_loaded else "none",
        )

    def _seed_bindings(self) -> None:
        """Startup seed of the binding sets, then the allowlist pairs (ADDENDUM_4.md D3).

        A failed seed is reported and leaves the raw guard in observe mode
        (`LeaseSync.seed`); it never stops startup (A6).
        """
        seeded = self._lease_sync.seed()
        _logger.info(
            "binding seed %s: %d binding(s)", "done" if seeded else "FAILED", len(self._bindings.snapshot())
        )
        try:
            self._manager.sync_allowlist()
        except PirewallError as exc:
            self._forwarder.emit(
                SecurityEvent(
                    timestamp=datetime.now(UTC),
                    severity=EventSeverity.ERROR,
                    event_type=SecurityEventType.FIREWALL_ERROR,
                    subsystem=_SUBSYSTEM,
                    reason=f"writing the allowlist's MAC+IP pairs to allow_bound failed: {exc}",
                )
            )

    def _reconcile_sets(self) -> None:
        """Rebuild rule state from the live adaptive sets (D5 "restart"). Set path only.

        Never creates or deletes a table: a missing one is reported CRITICAL
        and left for `pirewall-start` to reload (D1).
        """
        if not self._manager.uses_set_backend:
            return
        now = datetime.now(UTC)
        try:
            with self._lock:
                report = self._manager.reconcile(now)
        except FirewallError as exc:
            self._emit_system(
                EventSeverity.ERROR, f"reconciling with the kernel's adaptive sets failed: {exc}"
            )
            return
        if report.missing_tables:
            # The v2 watch thread raises the CRITICAL table-loss event on its
            # first pass; reporting it here too would say it twice.
            _logger.error("v2 tables missing at startup: %s", _describe_tables(report.missing_tables))
        if report.adopted or report.retired or report.unattributed:
            self._emit_system(
                EventSeverity.WARNING if report.unattributed else EventSeverity.INFO,
                f"reconciled with the kernel at startup: adopted {len(report.adopted)} element(s) left by "
                f"a previous run, retired {len(report.retired)}, left {len(report.unattributed)} "
                "unattributed MAC-keyed element(s) to expire on their own (<= 1 h)",
            )

    def _v2_watch_loop(self) -> None:
        """Once a second: table presence, guard modes and engine counters (D5, V2_CONTRACTS §9)."""
        while not self._stop.wait(_V2_WATCH_INTERVAL_SECONDS):
            try:
                self._refresh_v2_snapshots()
            except Exception:
                _logger.exception("v2 watch pass crashed; continuing")
        _logger.info("v2 watch loop exited")

    def _refresh_v2_snapshots(self) -> None:
        """Publish the engine counters, and on the set path check the tables and read the guards.

        Runs without the RPC lock: everything it calls on the manager only
        reads the set backend, which `FirewallManager` serialises itself.
        """
        now = datetime.now(UTC)
        stats = self._engine_stats(now)
        if stats is not None:
            self._snapshots.publish_engine_stats(stats)
        if not self._manager.uses_set_backend:
            self._snapshots.publish_guard_modes(None, "this pirewall-core runs without the v2 set backend")
            return
        try:
            missing = tuple(self._manager.missing_tables())
        except FirewallError as exc:
            _logger.warning("could not check the v2 tables: %s", exc)
            missing = self._missing_tables
        if missing != self._missing_tables:
            self._report_table_change(missing)
            self._missing_tables = missing
        try:
            self._snapshots.publish_guard_modes(self._manager.guard_modes(now))
        except FirewallError as exc:
            self._snapshots.publish_guard_modes(None, str(exc))
        self._poll_kernel(now)

    def _poll_kernel(self, now: datetime) -> None:
        """Tier K (phase 17): poll `@offenders`, counters and set fill; hand the result to the v2 pipeline.

        Runs on the watch thread. Table loss is reported by
        `_refresh_v2_snapshots` above, for both engines.
        """
        if self._kernel_poller is None or self._v2 is None:
            return
        result = self._kernel_poller.poll(now)
        self._snapshots.publish_offenders(
            tuple(
                OffenderEntry(
                    mac=item.mac,
                    code=item.code,
                    guard=item.guard,
                    guard_mode=item.guard_mode,
                    sustained_polls=item.sustained_polls,
                    first_seen=result.started_at.get(item.id, item.observed_at),
                    last_seen=item.observed_at,
                )
                for item in result.evidence
            )
        )
        self._v2.submit_kernel_poll(result, self._bindings.snapshot(), now)

    def _report_table_change(self, missing: tuple[tuple[str, str], ...]) -> None:
        """CRITICAL when a v2 table disappears (D5 "table loss"); INFO when they are all back."""
        if missing:
            self._emit_system(
                EventSeverity.CRITICAL,
                f"v2 table(s) missing: {_describe_tables(missing)}. The static guards and adaptive sets "
                "they hold are not enforcing. pirewall-core never recreates a table; reload them with "
                "`sudo scripts/deployment/pirewall-start` (expected after a panic).",
            )
        else:
            self._emit_system(EventSeverity.INFO, "every v2 table is loaded again")

    def _engine_stats(self, now: datetime) -> EngineStats | None:
        """The capture/flow engine counters `get_engine_stats` serves, or None if unreadable."""
        try:
            stats = self._capture.statistics()
        except PirewallError as exc:
            _logger.debug("capture statistics unavailable: %s", exc)
            return None
        backend: Literal["native", "python", "replay"] = (
            "replay" if self._replay else "native" if self._native_aggregator is not None else "python"
        )
        flows_shed, signals_shed = self._native_shed
        return EngineStats(
            backend=backend,
            has_packet_ring=native_capture_available(),
            frames_seen=stats.packets_seen,
            kernel_drops=stats.packets_dropped,
            flows_shed=flows_shed,
            new_flow_signals_shed=signals_shed,
            panics_caught=self._panics_caught,
            read_at=now,
        )

    def _emit_system(self, severity: EventSeverity, reason: str) -> None:
        self._forwarder.emit(
            SecurityEvent(
                timestamp=datetime.now(UTC),
                severity=severity,
                event_type=SecurityEventType.SYSTEM_WARNING,
                subsystem=_SUBSYSTEM,
                reason=reason,
            )
        )

    def _spawn(self, name: str, target: Callable[[], None]) -> None:
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    def run(self) -> int:
        """Run until a shutdown signal arrives. Returns the process exit code.

        The main thread deliberately does the periodic housekeeping rather
        than delegating it: the `sd_notify` watchdog is supposed to prove
        *this* process is alive and scheduling, and a heartbeat sent from a
        worker thread would keep arriving even if the main thread were
        wedged.
        """
        interval = self._heartbeat_interval_seconds()
        try:
            while not self._stop.wait(interval):
                self._tick()
            if self._stop_signal is not None:
                _logger.info("received %s, shutting down", signal.Signals(self._stop_signal).name)
        finally:
            self.stop()
        return 0

    def _heartbeat_interval_seconds(self) -> float:
        """Half of `failure.watchdog_sec`, systemd's documented recommendation.

        A heartbeat sent exactly at the deadline races it; half the window
        means one lost or late tick is survivable.
        """
        return max(1.0, self._config.failure.watchdog_sec / 2.0)

    def _tick(self) -> None:
        """One housekeeping pass: heartbeat, capture statistics, metrics export."""
        self._notifier.notify_watchdog()
        now = datetime.now(UTC)
        try:
            stats = self._capture.statistics()
        except PirewallError as exc:
            _logger.warning("could not read capture statistics: %s", exc)
            return
        with self._lock:
            self._state.record_capture_stats(stats)
            rule_count = len(self._manager.active_rules())
            adaptive_in_window = self._manager.adaptive_rules_in_window(now)
        with self._flow_lock:
            active_flows = len(self._aggregator)
        self._notifier.notify_status(self._status_line())

        if self._netdata is None:
            return
        snapshot = self._metrics.collect(
            now,
            stats,
            active_flows=active_flows,
            rule_count=rule_count,
            adaptive_rules_in_window=adaptive_in_window,
            capture_health=self._capture_started,
            firewall_health=self._manager.backend_health(),
            api_health=True,  # see pirewall.runtime.metrics' docstring
        )
        if self._v2 is not None:
            snapshot = snapshot.model_copy(update={"v2": self._v2.gauges()})
        try:
            self._netdata.export(snapshot)
        except PirewallError as exc:
            _logger.warning("Netdata export failed: %s", exc)

    def _status_line(self) -> str:
        with self._lock:
            active = len(self._manager.active_rules())
        return (
            f"mode={self._manager.enforcement_mode.value} "
            f"capture={'up' if self._capture_started else 'down'} "
            f"active_rules={active} queued_flows={self._flow_queue.qsize()}"
        )

    def stop(self) -> None:
        """Stop every thread and release every resource. Idempotent."""
        if self._stop.is_set() and not self._threads:
            return
        self._stop.set()
        self._notifier.notify_stopping("shutting down")

        if self._capture_started:
            self._capture.stop()  # unblocks the capture thread's recv()
        for thread in self._threads:
            thread.join(timeout=_THREAD_JOIN_TIMEOUT_SECONDS)
            if thread.is_alive():
                _logger.warning("thread %s did not stop within the join timeout", thread.name)
        self._threads.clear()

        self._revert_ruleset_if_failing_open()
        self._rpc_server.stop()
        if self._portal_rpc_server is not None:
            self._portal_rpc_server.stop()
        _logger.info("pirewall-core stopped")

    def _revert_ruleset_if_failing_open(self) -> None:
        if self._config.failure.mode is not FailureMode.FAIL_OPEN:
            _logger.info(
                "failure.mode=%s: leaving %d adaptive rule(s) deployed",
                self._config.failure.mode.value,
                len(self._manager.active_rules()),
            )
            return
        with self._lock:
            active = len(self._manager.active_rules())
            # The adaptive sets can hold elements from a previous run that this
            # process never tracked, so with a set backend flush regardless.
            if active == 0 and not self._manager.uses_set_backend:
                return
            event = self._manager.fail_open_shutdown(datetime.now(UTC))
        _logger.info("failure.mode=fail_open: removed %d adaptive rule(s) on shutdown", active)
        self._forwarder.emit(event)

    # ------------------------------------------------------------------ loops

    def _capture_loop(self) -> None:
        """Capture -> parse -> aggregate. Completed flows go onto the detection queue.

        The native loop returns True when it has swapped to the Python path
        (D6 fallback); the Python loop then carries on with the new capture.
        """
        try:
            capture = self._capture
            native = self._native_aggregator
            if (
                native is not None
                and isinstance(capture, FlowCapture)
                and not self._native_capture_loop(capture, native)
            ):
                return
            self._python_capture_loop()
        except CaptureError as exc:
            if self._stop.is_set():
                return
            _logger.error("capture loop stopped: %s", exc)
            self._forwarder.emit(
                SecurityEvent(
                    timestamp=datetime.now(UTC),
                    severity=EventSeverity.CRITICAL,
                    event_type=SecurityEventType.CAPTURE_ERROR,
                    subsystem=_SUBSYSTEM,
                    reason=f"capture loop stopped: {exc}",
                )
            )
        except Exception:
            if self._stop.is_set():
                return
            _logger.exception("capture loop crashed")
        finally:
            _logger.info("capture loop exited")

    def _python_capture_loop(self) -> None:
        """Python path: `AFPacketCapture` (or a pcap replay) -> parse -> `FlowAggregator`."""
        capture = self._capture
        aggregator = self._aggregator
        if not isinstance(capture, PacketCapture) or not isinstance(aggregator, FlowAggregator):
            return
        for packet in capture_packets(capture, self._forwarder, on_tcp_payload=self._handle_tcp_payload):
            if self._stop.is_set():
                return
            with self._flow_lock:
                completed = aggregator.process_packet(packet)
            self._enqueue(completed)
            if self._replay:
                self._sweep_on_replay_clock(int(packet.timestamp.timestamp() * 1_000_000))
        if self._replay and not self._stop.is_set():
            self._finish_replay()

    def _native_capture_loop(self, capture: FlowCapture, aggregator: NativeFlowAggregator) -> bool:
        """Native path: poll the ring (GIL released), then drain the engine.

        Drained output is handled in the order `NativeBatch` documents — TLS
        payloads, then new-flow signals, then completed flows — so detection
        sees evidence and behavioral signals before the completion they
        precede, exactly as the Python loop's program order guarantees.

        A caught engine panic (D6) costs the poll or drain in flight. Returns
        True only after swapping to the Python path, once too many panics
        fell within a minute; False when it stopped for any other reason.
        """
        shed_flows, shed_signals = self._native_shed
        while not self._stop.is_set():
            try:
                capture.poll(_NATIVE_POLL_TIMEOUT_MS)
                batch = aggregator.drain()
            except NativeEngineError as exc:
                if self._note_native_panic(exc):
                    return self._fall_back_to_python(capture, aggregator)
                continue
            for payload in batch.tls_payloads:
                self._inspect_tcp_payload(payload)
            for new_flow in batch.new_flows:
                self._handle_new_flow(new_flow)
            self._enqueue(batch.completed)
            try:
                total_flows, total_signals = aggregator.shed()
            except NativeEngineError as exc:
                if self._note_native_panic(exc):
                    return self._fall_back_to_python(capture, aggregator)
                continue
            if total_flows > shed_flows or total_signals > shed_signals:
                self._note_native_shedding(total_flows - shed_flows, total_signals - shed_signals)
                shed_flows, shed_signals = total_flows, total_signals
                self._native_shed = (shed_flows, shed_signals)
            if isinstance(capture, ReplayCapture):
                self._native_replay_tick(capture)
        return False

    def _native_replay_tick(self, capture: ReplayCapture) -> None:
        """Flush once the last frame has been fed.

        The sweeps themselves run between frames (`_ReplayClockSink`); an
        injected replay without that sink is swept here, once per poll.
        """
        now_us = capture.virtual_now_us
        if now_us is not None:
            self._sweep_on_replay_clock(now_us)
        if capture.finished and not self._replay_flushed:
            self._finish_replay()

    def _sweep_on_replay_clock(self, now_us: int) -> None:
        """Sweep flows at the replay's own time, every `cleanup_interval_seconds` of it. Capture thread."""
        interval_us = self._config.flow.cleanup_interval_seconds * 1_000_000
        last = self._replay_last_sweep_us
        if last is None:
            self._replay_last_sweep_us = now_us
            return
        if now_us - last < interval_us:
            return
        self._replay_last_sweep_us = now_us
        try:
            self._sweep_flows(from_microseconds(now_us))
        except NativeEngineError as exc:
            self._note_native_panic(exc)

    def _finish_replay(self) -> None:
        """Every frame has been fed: close the flows still open, as the end of a capture does."""
        self._replay_flushed = True
        try:
            with self._flow_lock:
                remaining = self._aggregator.flush()
        except NativeEngineError as exc:
            self._note_native_panic(exc)
            remaining = []
        self._counters.add(flows_expired=len(remaining))
        self._enqueue(remaining)
        self._emit_system(
            EventSeverity.INFO,
            f"replay finished: every frame of {self._config.capture.replay_path} has been fed; "
            f"{len(remaining)} open flow(s) flushed to detection",
        )

    def _note_native_panic(self, exc: NativeEngineError) -> bool:
        """Count one caught engine panic (D6). True once the budget for a minute is spent."""
        self._panics_caught += 1
        exhausted = self._panic_budget.record()
        _logger.warning("native engine panic caught (%d so far): %s", self._panics_caught, exc)
        self._forwarder.emit(
            SecurityEvent(
                timestamp=datetime.now(UTC),
                severity=EventSeverity.WARNING,
                event_type=SecurityEventType.CAPTURE_ERROR,
                subsystem=_SUBSYSTEM,
                reason=(
                    f"native engine panic caught and recovered ({self._panics_caught} so far); "
                    f"the frames or batch in flight were dropped: {exc}"
                ),
            )
        )
        return exhausted

    def _fall_back_to_python(self, capture: FlowCapture, aggregator: NativeFlowAggregator) -> bool:
        """Abandon the native ring for `AFPacketCapture` + `FlowAggregator` (D6). True if it swapped.

        The engine's open flows are salvaged (closed early) on the way out.
        A replay has no live interface to fall back to, so it stops instead.
        """
        limit = self._panic_budget.max_per_minute
        capture.stop()
        try:
            salvaged = aggregator.flush()
        except NativeEngineError:
            salvaged = []
        self._enqueue(salvaged)
        if self._replay:
            self._emit_capture_critical(
                f"the native engine panicked {limit} times within a minute during a replay; the replay "
                f"was stopped ({len(salvaged)} open flow(s) salvaged). A replay has no live fallback."
            )
            return False
        python_capture = AFPacketCapture(
            interface=self._config.capture.interface,
            snap_len=self._config.capture.snap_len,
            promiscuous=self._config.capture.promiscuous,
            buffer_size_bytes=self._config.capture.buffer_size_bytes,
        )
        try:
            python_capture.start()
        except CaptureError as exc:
            self._emit_capture_critical(
                f"the native engine panicked {limit} times within a minute and the Python capture "
                f"path could not start ({exc}); capture is down. Enforcement and the static guards "
                "keep running."
            )
            return False
        python_aggregator = FlowAggregator(
            self._config.flow,
            on_new_flow=self._handle_new_flow,
            protected_network=self._config.network.protected_network,
        )
        with self._flow_lock:
            self._capture = python_capture
            self._aggregator = python_aggregator
            self._native_aggregator = None
        self._emit_capture_critical(
            f"the native engine panicked {limit} times within a minute; switched to the Python capture "
            f"path, which drops packets under load ({len(salvaged)} open flow(s) salvaged). "
            "Restart pirewall-core to return to the native engine."
        )
        return True

    def _emit_capture_critical(self, reason: str) -> None:
        _logger.critical("%s", reason)
        self._forwarder.emit(
            SecurityEvent(
                timestamp=datetime.now(UTC),
                severity=EventSeverity.CRITICAL,
                event_type=SecurityEventType.CAPTURE_ERROR,
                subsystem=_SUBSYSTEM,
                reason=reason,
            )
        )

    def _note_native_shedding(self, flows: int, signals: int) -> None:
        """Account for work the engine shed at its per-drain caps — counted, never silent.

        A shed completed flow is the same outcome as a full detection queue
        (never assessed), so it is counted and reported exactly like one; a
        shed new-flow signal is the same outcome as a full new-flow queue.
        """
        if flows:
            self._counters.add(flows_dropped_for_backpressure=flows)
            before = self._backpressure_drops
            self._backpressure_drops += flows
            crossed = before == 0 or before // _BACKPRESSURE_REPORT_INTERVAL != (
                self._backpressure_drops // _BACKPRESSURE_REPORT_INTERVAL
            )
            if crossed:
                _logger.warning(
                    "native engine shed %d completed flow(s) at its per-drain cap (%d dropped so far)",
                    flows,
                    self._backpressure_drops,
                )
                self._forwarder.emit(
                    SecurityEvent(
                        timestamp=datetime.now(UTC),
                        severity=EventSeverity.WARNING,
                        event_type=SecurityEventType.SYSTEM_WARNING,
                        subsystem=_SUBSYSTEM,
                        reason=(
                            f"capture is completing flows faster than detection can assess them; "
                            f"{self._backpressure_drops} flow(s) dropped without analysis so far "
                            "(source-level behavior detection still sees the traffic)."
                        ),
                    )
                )
        if signals:
            self._new_flow_signals_dropped += signals

    def _enqueue(self, flows: Iterable[Flow]) -> None:
        """Hand completed flows to the detection thread, dropping rather than blocking."""
        for flow in flows:
            self._counters.add(flows_completed=1)
            try:
                self._flow_queue.put_nowait(flow)
            except queue.Full:
                self._note_backpressure_drop(flow)

    def _handle_new_flow(self, signal: NewFlowSignal) -> None:
        """`FlowAggregator`'s creation-time callback (ADDENDUM_2.md B1). Runs on the capture thread.

        Only enqueues — `BehaviorAnalyzer` is mutated exclusively from the
        detection thread (`_drain_new_flow_signals`), so this needs no lock
        of its own, same reasoning as `_enqueue` for completed flows.
        Dropping under backpressure only costs *how fast* a pattern becomes
        visible, never correctness: a dropped signal is one fewer connection
        counted at creation time, but that same flow still updates its
        source's state at completion via `observe_completion` regardless.
        """
        try:
            self._new_flow_queue.put_nowait(signal)
        except queue.Full:
            self._new_flow_signals_dropped += 1
            if self._new_flow_signals_dropped == 1 or (
                self._new_flow_signals_dropped % _BACKPRESSURE_REPORT_INTERVAL == 0
            ):
                _logger.warning(
                    "new-flow signal queue full, dropped %d so far",
                    self._new_flow_signals_dropped,
                )

    def _handle_tcp_payload(self, metadata: PacketMetadata, raw: bytes) -> None:
        """`capture_packets`'s TCP/443 callback (ADDENDUM_2.md B4/B5). Runs on the capture thread.

        Extracts the TCP payload and runs the narrow TLS structural
        detectors against it. A match is cached by flow key for
        `_pop_tls_evidence` to pick up once the flow it belongs to
        completes — this method never touches `BehaviorAnalyzer`, the flow
        queue, or anything else detection-thread-owned.

        Must never raise: a bug or a genuinely malformed/adversarial packet
        here must degrade to "no TLS evidence for this packet", never take
        the capture loop down with it (this runs inside `capture_packets`'s
        generator body, ahead of `_capture_loop`'s own try/except, which
        would otherwise treat an escaped exception as a fatal capture-loop
        crash).
        """
        if not isinstance(metadata.source_ip, IPv4Address) or not isinstance(
            metadata.destination_ip, IPv4Address
        ):
            return
        payload = extract_tcp_payload(raw)
        if not payload:
            return
        self._inspect_tcp_payload(
            TcpPayload(
                source_ip=metadata.source_ip,
                destination_ip=metadata.destination_ip,
                source_port=metadata.source_port,
                destination_port=metadata.destination_port,
                timestamp=metadata.timestamp,
                payload=payload,
            )
        )

    def _inspect_tcp_payload(self, segment: TcpPayload) -> None:
        """Run the TLS structural detectors on one payload. Capture thread; never raises.

        Shared by both capture paths: the Python loop extracts the payload
        itself (`_handle_tcp_payload`), the native engine hands it over
        pre-filtered to records these detectors can act on.
        """
        try:
            self._inspect_tcp_payload_unsafe(segment)
        except Exception:
            _logger.exception("TLS structural inspection failed for a packet; continuing")

    def _inspect_tcp_payload_unsafe(self, segment: TcpPayload) -> None:
        payload = segment.payload
        if not payload:
            return
        heartbleed = check_heartbleed(payload)
        if heartbleed is not None:
            self._cache_tls_match(
                segment,
                signature="heartbleed",
                confidence=1.0,
                detail=(
                    f"TLS heartbeat claimed payload_length={heartbleed.claimed_payload_length} "
                    f"but the record held only {heartbleed.available_bytes} bytes "
                    "(CVE-2014-0160 signature)"
                ),
            )
            return  # a single payload is either a heartbeat or a handshake record, never both

        fingerprint = compute_ja3(payload)
        if fingerprint is None:
            return
        known_tool = match_known_tool(fingerprint, self._known_tool_fingerprints)
        if known_tool is not None:
            self._cache_tls_match(
                segment,
                signature=f"ja3:{known_tool.ja3_hash}",
                # Honestly weaker than a Heartbleed length mismatch (ADDENDUM_2.md
                # B5): a JA3 match against known, *unmodified* tooling is real
                # signal, but trivially evaded by randomizing the TLS stack.
                confidence=0.6,
                detail=f"TLS ClientHello JA3 fingerprint matches known tool {known_tool.tool!r}",
            )

    def _cache_tls_match(
        self, segment: TcpPayload, *, signature: str, confidence: float, detail: str
    ) -> None:
        key = compute_flow_key(
            segment.source_ip,
            segment.destination_ip,
            segment.source_port,
            segment.destination_port,
            Protocol.TCP,
        )
        match = _CachedTlsMatch(
            signature=signature, confidence=confidence, detail=detail, generated_at=segment.timestamp
        )
        with self._flow_lock:
            if key not in self._tls_evidence and len(self._tls_evidence) >= _TLS_EVIDENCE_CACHE_MAX:
                self._tls_evidence.popitem(last=False)
            self._tls_evidence[key] = match
            self._tls_evidence.move_to_end(key)

    def _pop_tls_evidence(self, flow: Flow) -> ProtocolSignatureEvidence | None:
        """Look up and consume any cached TLS match for `flow`'s key. Detection thread only."""
        key = compute_flow_key(
            flow.source_ip, flow.destination_ip, flow.source_port, flow.destination_port, flow.protocol
        )
        with self._flow_lock:
            cached = self._tls_evidence.pop(key, None)
        if cached is None:
            return None
        return ProtocolSignatureEvidence(
            flow_id=flow.flow_id,
            signature=cached.signature,
            confidence=cached.confidence,
            detail=cached.detail,
            generated_at=cached.generated_at,
        )

    def _drain_new_flow_signals(self) -> None:
        """Fold every pending creation-time signal into `BehaviorAnalyzer`. Detection thread only.

        Then gives every source those signals touched a chance at the
        source-level fast path (`_assess_sources_early`).
        """
        touched: set[IPv4Address] = set()
        while True:
            try:
                signal = self._new_flow_queue.get_nowait()
            except queue.Empty:
                break
            if self._v2 is not None:
                # v2: the fast path feeds D1's cardinality detectors (phase 17).
                self._v2.observe_signal(signal)
                continue
            self._coordinator.behavior_analyzer.observe_new_connection(
                signal.source_ip, signal.destination_ip, signal.destination_port, signal.timestamp
            )
            touched.add(signal.source_ip)
        if touched:
            self._assess_sources_early(touched)

    def _assess_sources_early(self, sources: Iterable[IPv4Address]) -> None:
        """Source-level fast path. Detection thread only.

        A flood or scan is fully visible in its new-connection signals
        within seconds, but per-flow assessment only happens when a flow
        *completes* — for half-open SYN-flood connections, at the inactive
        timeout. So once a source's behavior alone already scores MEDIUM or
        above, it is assessed now, from a snapshot of its newest open flow,
        through the ordinary decision/validation/enforcement chain.
        Rate-limited per source by `detection.source_assessment_cooldown_seconds`;
        the cooldown map is LRU-bounded like every other per-source table.
        """
        cooldown = self._config.detection.source_assessment_cooldown_seconds
        analyzer = self._coordinator.behavior_analyzer
        for source in sources:
            now_monotonic = time.monotonic()
            last = self._early_assessed_at.get(source)
            if last is not None and now_monotonic - last < cooldown:
                continue
            assessment = analyzer.assess(source)
            if assessment is None or not self._pipeline.behavior_warrants_assessment(assessment):
                continue
            with self._flow_lock:
                snapshot = self._aggregator.snapshot_open_flow_from(source)
            if snapshot is None:
                continue
            self._early_assessed_at[source] = now_monotonic
            self._early_assessed_at.move_to_end(source)
            while len(self._early_assessed_at) > self._config.detection.max_tracked_sources:
                self._early_assessed_at.popitem(last=False)
            self._counters.add(source_snapshot_assessments=1)
            self._pipeline.process_snapshot(snapshot, datetime.now(UTC))

    def _drain_slow_clusters(self) -> None:
        """Fold every pending slow-connection cluster into `BehaviorAnalyzer` and the normal pipeline.

        ADDENDUM_2.md B2. Detection thread only, same reasoning as
        `_drain_new_flow_signals`. Recording the cluster's count *before*
        enqueueing its representative flow is what makes the SLOW_RATE_DOS
        pattern visible on that same flow's own `ThreatAssessment`, exactly
        like every other behavioral pattern.
        """
        while True:
            try:
                cluster = self._slow_cluster_queue.get_nowait()
            except queue.Empty:
                return
            now = datetime.now(UTC)
            if self._v2 is not None:
                self._v2.observe_slow_cluster(cluster, now)  # D1 slow-rate DoS (ported B2)
                continue
            self._coordinator.behavior_analyzer.note_slow_connections(
                cluster.source_ip, cluster.destination_ip, cluster.concurrent_count, now
            )
            # A still-open connection's point-in-time snapshot (see
            # `SlowConnectionCluster`'s docstring), so it takes the
            # snapshot path — behavior evidence only, no ML on a partial
            # flow, no completion signal for a flow that has not completed
            # (which previously counted it as a failure twice) — not the
            # completed-flow queue, and never `flows_completed`.
            self._pipeline.process_snapshot(cluster.representative_flow, now)

    def _note_backpressure_drop(self, flow: Flow) -> None:
        self._backpressure_drops += 1
        count = self._backpressure_drops
        self._counters.add(flows_dropped_for_backpressure=1)
        if count != 1 and count % _BACKPRESSURE_REPORT_INTERVAL != 0:
            return
        _logger.warning(
            "detection queue full, dropped flow %s (%d dropped so far)", flow.flow_id, count
        )
        self._forwarder.emit(
            SecurityEvent(
                timestamp=datetime.now(UTC),
                severity=EventSeverity.WARNING,
                event_type=SecurityEventType.SYSTEM_WARNING,
                subsystem=_SUBSYSTEM,
                flow_id=flow.flow_id,
                reason=(
                    f"detection queue full; {count} flow(s) dropped without analysis. "
                    "Detection is falling behind capture."
                ),
            )
        )

    def _enqueue_anomaly_scoring(self, pending: PendingAnomalyScoring) -> None:
        """`FlowPipeline`'s batching handoff (ADDENDUM_2 follow-up pass, section 3). Detection thread only.

        Drops rather than blocks under backpressure, same discipline as
        every other cross-thread queue here — but "dropped" here does not
        mean the flow is lost. `pending.outcome` already carries real
        known-attack and behavioral evidence; on drop this finishes the
        flow immediately with `anomaly_evidence` left `None`, so it still
        reaches a real `ThreatAssessment`, just without an Isolation Forest
        score. That is a materially different, milder failure than
        `_note_backpressure_drop`'s "never assessed at all" — tracked by
        its own counter and event for exactly that reason (section 3c).
        """
        try:
            self._anomaly_queue.put_nowait(pending)
        except queue.Full:
            self._note_anomaly_scoring_drop(pending.flow)
            self._pipeline.finish(pending.flow, pending.now, pending.outcome)

    def _note_anomaly_scoring_drop(self, flow: Flow) -> None:
        self._anomaly_scores_dropped += 1
        count = self._anomaly_scores_dropped
        self._counters.add(anomaly_scores_dropped_for_backpressure=1)
        if count != 1 and count % _BACKPRESSURE_REPORT_INTERVAL != 0:
            return
        _logger.warning(
            "anomaly-scoring queue full, flow %s finished without an anomaly score "
            "(%d dropped so far)",
            flow.flow_id,
            count,
        )
        self._forwarder.emit(
            SecurityEvent(
                timestamp=datetime.now(UTC),
                severity=EventSeverity.WARNING,
                event_type=SecurityEventType.SYSTEM_WARNING,
                subsystem=_SUBSYSTEM,
                flow_id=flow.flow_id,
                reason=(
                    f"anomaly-scoring queue full; {count} flow(s) finished without an "
                    "anomaly score. Batched Isolation Forest inference is falling behind."
                ),
            )
        )

    def _anomaly_inference_loop(self) -> None:
        """Batch-score queued flows through Isolation Forest (ADDENDUM_2 follow-up pass, section 3).

        Only spawned when a model is actually loaded (see `start()`). One
        `decision_function` call per batch instead of one per flow —
        `benchmarks/2026-08-30/REPORT.md` measured single-flow scoring as
        92% of total packet-to-decision cost on a real Pi 4. Bounds
        worst-case added latency to `detection.anomaly_batch_max_wait_seconds`
        via `_collect_anomaly_batch`, the same "flush on size or timeout"
        shape as any other micro-batcher.
        """
        while not self._stop.is_set():
            batch = self._collect_anomaly_batch()
            if batch:
                self._score_and_finish_batch(batch)
        leftover = self._drain_anomaly_queue_nowait()
        if leftover:
            self._score_and_finish_batch(leftover)
        _logger.info("anomaly inference loop exited")

    def _collect_anomaly_batch(self) -> list[PendingAnomalyScoring]:
        """Block for one item, then keep collecting up to `anomaly_batch_size` more or until
        `anomaly_batch_max_wait_seconds` has elapsed since the first item arrived, whichever
        comes first. This is what bounds worst-case per-flow latency under low load instead of
        waiting indefinitely for a full batch.
        """
        try:
            first = self._anomaly_queue.get(timeout=_QUEUE_POLL_SECONDS)
        except queue.Empty:
            return []
        batch = [first]
        batch_size = self._config.detection.anomaly_batch_size
        deadline = time.monotonic() + self._config.detection.anomaly_batch_max_wait_seconds
        while len(batch) < batch_size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                batch.append(self._anomaly_queue.get(timeout=remaining))
            except queue.Empty:
                break
        return batch

    def _drain_anomaly_queue_nowait(self) -> list[PendingAnomalyScoring]:
        items: list[PendingAnomalyScoring] = []
        while True:
            try:
                items.append(self._anomaly_queue.get_nowait())
            except queue.Empty:
                return items

    def _score_and_finish_batch(self, batch: list[PendingAnomalyScoring]) -> None:
        """Score one batch and finish every flow in it. Anomaly-inference thread only.

        A batch-level inference failure (a schema mismatch, or anything
        else `detect_anomaly_batch` raises) degrades every flow in the
        batch to no anomaly evidence, exactly like a single-flow inference
        failure degrades that one flow in the non-batched path
        (`DetectionCoordinator._detect_anomaly`) — never loses the flow.
        """
        model = self._coordinator.models.isolation_forest
        if model is None:  # pragma: no cover — this thread only runs when a model is loaded
            for pending in batch:
                self._pipeline.finish(pending.flow, pending.now, pending.outcome)
            return
        now = datetime.now(UTC)
        started = time.perf_counter()
        try:
            evidences = detect_anomaly_batch(
                model,
                [pending.features for pending in batch],
                self._config.detection.anomaly_score_threshold,
                now,
            )
        except (ModelInferenceError, ValueError) as exc:
            _logger.warning("batched anomaly inference failed for %d flow(s): %s", len(batch), exc)
            evidences = [None] * len(batch)
        elapsed_seconds = time.perf_counter() - started
        self._counters.add(inferences=len(batch), inference_seconds_total=elapsed_seconds)
        for pending, evidence in zip(batch, evidences, strict=True):
            self._pipeline.finish(
                pending.flow, pending.now, with_anomaly_evidence(pending.outcome, evidence)
            )

    def _detection_loop(self) -> None:
        """Drain the flow queue through `FlowPipeline`, one flow at a time.

        Also drains the new-flow-signal queue (ADDENDUM_2.md B1) at least
        once per `_QUEUE_POLL_SECONDS`, whether or not a completed flow
        arrived in that window — this is what bounds volumetric-pattern
        detection latency to roughly that interval instead of however long
        the constituent flows take to complete.

        **Drains again immediately before processing a completed flow, not
        just once at the top of the loop.** This closes a real race: this
        thread can be sitting inside the blocking `_flow_queue.get()` call
        with an empty `_new_flow_queue` (nothing produced yet) when the
        capture thread — a single sequential producer — pushes a burst of
        new-flow signals *and then* the very flow whose completion just
        unblocks this `get()`. Program order on the capture thread
        guarantees every signal for that burst was enqueued strictly before
        the completed flow was, so re-draining right here, right before
        `FlowPipeline.process` runs, is what actually guarantees a
        completing flow's own assessment sees everything the capture
        thread already knows about its source — not just whatever this
        thread happened to have drained on an earlier, possibly-premature
        pass through the top of the loop. Without this second drain, a
        flow that completes very early (before this thread's first
        top-of-loop drain has anything to find) can be assessed against an
        empty `BehaviorAnalyzer` state despite a whole burst of sibling
        connections already sitting in the queue, unseen.
        """
        while not self._stop.is_set():
            self._drain_new_flow_signals()
            self._drain_slow_clusters()
            try:
                flow = self._flow_queue.get(timeout=_QUEUE_POLL_SECONDS)
            except queue.Empty:
                if self._v2 is not None:
                    self._process_v2(None)
                continue
            self._drain_new_flow_signals()
            self._drain_slow_clusters()
            try:
                if self._v2 is not None:
                    self._process_v2(flow)
                else:
                    protocol_signature = self._pop_tls_evidence(flow)
                    self._pipeline.process(flow, datetime.now(UTC), protocol_signature)
            finally:
                self._flow_queue.task_done()
        self._drain_new_flow_signals()
        self._drain_slow_clusters()
        _logger.info("detection loop exited")

    def _process_v2(self, flow: Flow | None) -> None:
        """One v2 detection step: a completed record (if any), the inbox, then D1 + policy. Detection thread.

        A crash here costs one step, never the thread (the v1 pipeline's rule).
        """
        v2 = self._v2
        assert v2 is not None
        now = datetime.now(UTC)
        try:
            if flow is not None:
                self._pop_tls_evidence(flow)  # v2 drops JA3/Heartbleed (PLAN_FINAL §4.8); free the cache
                v2.observe_record(flow, now)
            v2.drain_inbox(now)
            v2.evaluate(now)
        except Exception:
            _logger.exception("v2 detection step crashed; continuing")

    def _sweep_loop(self) -> None:
        """Expire timed-out flows and TTL-elapsed rules on `flow.cleanup_interval_seconds`.

        Also snapshots slow-connection clusters (ADDENDUM_2.md B2) on the
        same cadence — cheap (a duration/byte-count check per open flow, no
        feature extraction or ML), so it costs nothing extra to piggyback on
        this loop rather than run its own.

        A replay's flows are swept from the capture thread on the replay's
        own clock instead (`_sweep_on_replay_clock`); rule and portal expiry
        stay here, on the wall clock, in every mode.
        """
        interval = float(self._config.flow.cleanup_interval_seconds)
        while not self._stop.wait(interval):
            now = datetime.now(UTC)
            try:
                if not self._replay:
                    self._sweep_flows(now)
                self._expire_rules(now)
                self._expire_portal_sessions()
            except PirewallError as exc:
                _logger.warning("sweep pass failed: %s", exc)
            except Exception:
                _logger.exception("sweep pass crashed")
        _logger.info("sweep loop exited")

    def _sweep_flows(self, now: datetime) -> None:
        """Expire timed-out flows and snapshot slow-connection clusters as of `now`."""
        detection = self._config.detection
        with self._flow_lock:
            completed = self._aggregator.sweep_timeouts(now)
            clusters = self._aggregator.snapshot_slow_connection_clusters(
                now,
                detection.slow_connection_min_duration_seconds,
                detection.slow_connection_max_bytes_per_second,
                detection.concurrent_slow_connections_threshold,
            )
        self._counters.add(flows_expired=len(completed))
        self._enqueue(completed)
        self._enqueue_slow_clusters(clusters)

    def _enqueue_slow_clusters(self, clusters: list[SlowConnectionCluster]) -> None:
        """Hand slow-connection clusters to the detection thread, dropping rather than blocking."""
        for cluster in clusters:
            try:
                self._slow_cluster_queue.put_nowait(cluster)
            except queue.Full:
                self._slow_clusters_dropped += 1
                if self._slow_clusters_dropped == 1 or (
                    self._slow_clusters_dropped % _BACKPRESSURE_REPORT_INTERVAL == 0
                ):
                    _logger.warning(
                        "slow-connection cluster queue full, dropped %d so far",
                        self._slow_clusters_dropped,
                    )

    def _expire_portal_sessions(self) -> None:
        """Retire lapsed portal sessions on the existing sweep cadence (ADDENDUM_3.md C2).

        The kernel has already dropped each one's nft set element by the
        time this runs — the element carries its own timeout, which is what
        makes portal auto-logout cost nothing. This only keeps pirewall's
        *view* honest, so the control panel does not list a session that
        stopped forwarding minutes ago. No thread of its own, deliberately.
        """
        if self._portal is None:
            return
        with self._lock:
            retired = self._portal.sweep()
        if retired:
            _logger.info("retired %d expired portal session(s)", retired)

    def _expire_rules(self, now: datetime) -> None:
        with self._lock:
            expired = self._manager.expire_rules(now)
        for rule in expired:
            self._forwarder.emit(
                SecurityEvent(
                    timestamp=now,
                    severity=EventSeverity.INFO,
                    event_type=SecurityEventType.RULE_EXPIRED,
                    subsystem=_SUBSYSTEM,
                    rule_id=rule.id,
                    decision=rule.action,
                    threat_score=rule.threat_score,
                    reason="rule TTL elapsed",
                )
            )
