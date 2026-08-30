"""`CoreDaemon`: the pirewall-core process (ADDENDUM.md A4, A6; spec §42).

One `CoreDaemon` owns every long-lived object in the privileged process and
every thread that touches them. `pirewall.main` does nothing but load
config, set up logging, build one of these, and run it.

Threads, and why there is more than one
---------------------------------------

===================  =========================================================
`capture`            Blocks in `recv()` on the `AF_PACKET` socket, parses each
                     packet, feeds `FlowAggregator`, and hands completed flows
                     to the detection thread through a bounded queue.
`detection`          Drains that queue and runs `FlowPipeline` per flow.
`sweep`              Flow active/inactive timeouts and adaptive-rule TTL
                     expiry, on `flow.cleanup_interval_seconds`.
`rpc`                `UnixSocketRpcServer.serve_until_stopped` — pirewall-api's
                     only way in.
main thread          `sd_notify` watchdog heartbeats, capture-statistics
                     refresh, and Netdata export.
===================  =========================================================

Capture and detection are separated because they run at wildly different
speeds. Isolation Forest scoring was measured at ~15.6 ms per flow on the
development machine and is expected to be slower on a Pi 4
(`docs/PROGRESS.md`); doing that work inline in the capture thread would
stall `recv()` and drop packets in the kernel. The queue between them is
**bounded** and drops on overflow rather than blocking, because blocking the
capture thread is precisely the failure this split exists to avoid — a
detection backlog must cost detection coverage, never packet capture. Drops
are counted and reported, never silent.

Shutdown
--------

`SIGTERM`/`SIGINT` set one `threading.Event`. The main loop notices, tells
systemd `STOPPING=1`, stops capture (which unblocks the capture thread's
`recv()`), joins every thread with a timeout, and closes the RPC socket.

**On a clean shutdown under `failure.mode = fail_open` (the default, A6)
the adaptive ruleset is reverted to base.** nftables rules live in the
kernel and outlive the process that created them, so leaving them behind
would mean a stopped pirewall keeps blocking traffic with nothing left
running to expire it — the opposite of failing open. Under `fail_closed`
they are deliberately left in place. Either way this goes through
`FirewallManager.revert_to_base`, the normal A8 kill-switch path, not a
special-cased backend call (CLAUDE.md).
"""

import logging
import queue
import signal
import threading
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from types import FrameType

from pirewall.capture.af_packet import AFPacketCapture
from pirewall.capture.interfaces import PacketCapture
from pirewall.capture.pipeline import capture_packets
from pirewall.config.models import PirewallConfig
from pirewall.core.enums import EventSeverity, FailureMode, SecurityEventType
from pirewall.core.exceptions import CaptureError, PirewallError
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.flow import Flow
from pirewall.detection.coordinator import DetectionCoordinator, load_models
from pirewall.firewall.backend.nftables import NftablesBackend
from pirewall.firewall.interface import FirewallBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.flow.aggregator import FlowAggregator, NewFlowSignal, SlowConnectionCluster
from pirewall.integration.netdata import NetdataExporter, StatsdNetdataTransport
from pirewall.integration.wazuh import SyslogWazuhTransport, WazuhForwarder
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.protocol import RpcRequest, RpcResponse
from pirewall.ipc.server import UnixSocketRpcServer
from pirewall.ipc.state import CoreStateStore
from pirewall.runtime.forwarder import EventForwarder
from pirewall.runtime.metrics import MetricsCollector, RuntimeCounters
from pirewall.runtime.pipeline import FlowPipeline
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
# How long the queue drain waits before re-checking the stop flag.
_QUEUE_POLL_SECONDS = 0.5
# Threads get this long to finish after `stop()` before the process gives up
# waiting on them. Every one is a daemon thread, so a wedged thread delays
# shutdown by at most this and cannot prevent it.
_THREAD_JOIN_TIMEOUT_SECONDS = 5.0
# Report dropped-flow backpressure at most this often, so a sustained
# overload produces a steady signal instead of a log flood.
_BACKPRESSURE_REPORT_INTERVAL = 1000


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
    ) -> None:
        super().__init__(state, manager, config)
        self._lock = lock

    def handle(self, request: RpcRequest) -> RpcResponse:
        with self._lock:
            return super().handle(request)


class CoreDaemon:
    """Owns pirewall-core's subsystems, threads, and lifecycle."""

    def __init__(
        self,
        config: PirewallConfig,
        capture: PacketCapture | None = None,
        backend: FirewallBackend | None = None,
        notifier: SystemdNotifier | None = None,
        flow_queue_max: int = _FLOW_QUEUE_MAX,
    ) -> None:
        """Build every subsystem. `capture`/`backend`/`notifier` are injectable for testing.

        Injecting `FakePacketCapture` and `FakeFirewallBackend` is what lets
        the whole daemon run without root, without a NIC, and without
        touching a real nftables ruleset (CLAUDE.md's Protocol/Fake rule).
        """
        self._config = config
        self._started_at = datetime.now(UTC)
        self._stop = threading.Event()
        # One lock for `CoreStateStore` + `FirewallManager`, shared with the
        # pipeline and the RPC dispatcher. Reentrant because the forwarder
        # can be called from inside a pipeline section that already holds it.
        self._lock = threading.RLock()
        # Separate lock: `FlowAggregator` is touched by the capture thread
        # (per packet) and the sweep thread (per interval) but never by RPC,
        # so contending it against the state lock would be pointless.
        self._flow_lock = threading.Lock()

        self._capture: PacketCapture = capture or AFPacketCapture(
            interface=config.capture.interface,
            snap_len=config.capture.snap_len,
            promiscuous=config.capture.promiscuous,
            buffer_size_bytes=config.capture.buffer_size_bytes,
        )
        # Constructed here and handed straight to `FirewallManager`, which
        # is the only code path permitted to call into
        # `pirewall.firewall.backend` (CLAUDE.md). Deliberately not retained
        # on `self`: there must be no second reference through which the
        # daemon could deploy or remove a rule outside the manager's
        # validated lifecycle. `tests/security/test_backend_isolation.py`
        # asserts this file only ever *constructs* a backend.
        firewall_backend: FirewallBackend = backend or NftablesBackend(
            config.firewall.rate_limit_per_second
        )

        self._state = CoreStateStore(
            max_history=config.api.history_size, started_at=self._started_at
        )
        self._manager = FirewallManager(config, firewall_backend)
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
        self._aggregator = FlowAggregator(config.flow, on_new_flow=self._handle_new_flow)

        models = load_models(config.ml)
        self._model_load_errors = models.load_errors
        if models.lightgbm is not None:
            self._state.lightgbm_metadata = models.lightgbm.metadata
        if models.isolation_forest is not None:
            self._state.isolation_forest_metadata = models.isolation_forest.metadata
        self._coordinator = DetectionCoordinator(
            config.detection, models, on_event=self._forwarder
        )

        self._pipeline = FlowPipeline(
            config=config,
            coordinator=self._coordinator,
            manager=self._manager,
            state=self._state,
            forwarder=self._forwarder,
            counters=self._counters,
            lock=self._lock,
        )
        self._flow_queue: queue.Queue[Flow] = queue.Queue(maxsize=flow_queue_max)
        self._rpc_server = UnixSocketRpcServer(
            config.api.rpc_socket_path,
            _SynchronizedDispatcher(self._lock, self._state, self._manager, config),
        )
        self._notifier = notifier or SystemdNotifier()
        self._metrics = MetricsCollector(
            self._counters, config.firewall.max_adaptive_rules_per_window
        )
        self._netdata = self._build_netdata()
        self._threads: list[threading.Thread] = []
        self._capture_started = False
        self._backpressure_drops = 0

    # ------------------------------------------------------------------ setup

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
        _logger.info("received %s, shutting down", signal.Signals(signal_number).name)
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
        self._rpc_server.start()
        _logger.info("RPC socket listening at %s", self._config.api.rpc_socket_path)

        try:
            self._capture.start()
            self._capture_started = True
            _logger.info("capture started on %s", self._config.capture.interface)
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

        self._spawn("pirewall-rpc", lambda: self._rpc_server.serve_until_stopped(self._stop))
        self._spawn("pirewall-detection", self._detection_loop)
        self._spawn("pirewall-sweep", self._sweep_loop)
        if self._capture_started:
            self._spawn("pirewall-capture", self._capture_loop)

        self._notifier.notify_ready(self._status_line())
        _logger.info(
            "pirewall-core ready: enforcement=%s failure=%s models=%s",
            self._manager.enforcement_mode.value,
            self._config.failure.mode.value,
            "loaded" if self._coordinator.models.any_loaded else "none",
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
            if active == 0:
                return
            event = self._manager.revert_to_base(datetime.now(UTC))
        _logger.info("failure.mode=fail_open: reverted %d adaptive rule(s) on shutdown", active)
        self._forwarder.emit(event)

    # ------------------------------------------------------------------ loops

    def _capture_loop(self) -> None:
        """Capture -> parse -> aggregate. Completed flows go onto the detection queue."""
        try:
            for packet in capture_packets(self._capture, self._forwarder):
                if self._stop.is_set():
                    return
                with self._flow_lock:
                    completed = self._aggregator.process_packet(packet)
                self._enqueue(completed)
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

    def _drain_new_flow_signals(self) -> None:
        """Fold every pending creation-time signal into `BehaviorAnalyzer`. Detection thread only."""
        while True:
            try:
                signal = self._new_flow_queue.get_nowait()
            except queue.Empty:
                return
            self._coordinator.behavior_analyzer.observe_new_connection(
                signal.source_ip, signal.destination_ip, signal.destination_port, signal.timestamp
            )

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
            self._coordinator.behavior_analyzer.note_slow_connections(
                cluster.source_ip, cluster.destination_ip, cluster.concurrent_count, now
            )
            # Not `_enqueue`: that increments `flows_completed`, and this
            # flow did not complete — it's a still-open connection's
            # point-in-time snapshot (see `SlowConnectionCluster`'s
            # docstring). Metrics must not conflate the two.
            try:
                self._flow_queue.put_nowait(cluster.representative_flow)
            except queue.Full:
                self._note_backpressure_drop(cluster.representative_flow)

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

    def _detection_loop(self) -> None:
        """Drain the flow queue through `FlowPipeline`, one flow at a time.

        Also drains the new-flow-signal queue (ADDENDUM_2.md B1) at least
        once per `_QUEUE_POLL_SECONDS`, whether or not a completed flow
        arrived in that window — this is what bounds volumetric-pattern
        detection latency to roughly that interval instead of however long
        the constituent flows take to complete.
        """
        while not self._stop.is_set():
            self._drain_new_flow_signals()
            self._drain_slow_clusters()
            try:
                flow = self._flow_queue.get(timeout=_QUEUE_POLL_SECONDS)
            except queue.Empty:
                continue
            try:
                self._pipeline.process(flow, datetime.now(UTC))
            finally:
                self._flow_queue.task_done()
        self._drain_new_flow_signals()
        self._drain_slow_clusters()
        _logger.info("detection loop exited")

    def _sweep_loop(self) -> None:
        """Expire timed-out flows and TTL-elapsed rules on `flow.cleanup_interval_seconds`.

        Also snapshots slow-connection clusters (ADDENDUM_2.md B2) on the
        same cadence — cheap (a duration/byte-count check per open flow, no
        feature extraction or ML), so it costs nothing extra to piggyback on
        this loop rather than run its own.
        """
        interval = float(self._config.flow.cleanup_interval_seconds)
        detection = self._config.detection
        while not self._stop.wait(interval):
            now = datetime.now(UTC)
            try:
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
                self._expire_rules(now)
            except PirewallError as exc:
                _logger.warning("sweep pass failed: %s", exc)
            except Exception:
                _logger.exception("sweep pass crashed")

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
        _logger.info("sweep loop exited")

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
