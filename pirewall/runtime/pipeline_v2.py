"""`V2Pipeline`: the `pipeline.engine = "v2"` path from evidence to the single deploy path (phase 17).

```text
completed records, new-flow signals, slow clusters, portal failures, bindings
  -> pirewall.flow.connection_start.ConnectionStartTracker   (what counts)
  -> pirewall.detection_v2.d1.D1State                         (D1 evidence)
@offenders, guard counters, set fill
  -> pirewall.detection_v2.kernel.KernelPoller                (K evidence)
optional LightGBM output
  -> ClassifierEvidence                                       (D3: corroboration only)
per-device bundles
  -> pirewall.policy.engine.PolicyEngine                      (PolicyDecision)
  -> FirewallDecision + CandidateRule
  -> FirewallManager.submit_candidate                         (validator v2 + sets)
```

Each arrow is a call into a module that knows nothing of the next. Like
`pirewall.runtime.pipeline.FlowPipeline` (v1, kept as the baseline), this
is wiring: no detection, scoring or rule logic of its own.

**Scores never choose an action.** A `CandidateRule` must carry a
`threat_score` (the schema stage) and the dashboard shows one, so each
decision gets `DISPLAY_SCORE_BY_ACTION[action]`: a number *derived from*
the action the policy table chose, the reverse of v1. Because BLOCK maps
to 100, `FirewallManager`'s A7 review rule (BLOCK at or above
`firewall.assisted_review_threshold`, at most 100) always holds a v2 BLOCK
for approval in ASSISTED, which is what `requires_approval` asks for.

**Threads.** D1 state and the policy engine belong to the detection
thread. The kernel poll runs on core's 1 s watch thread and portal
failures arrive on the portal RPC thread; both are handed over through a
bounded inbox that the detection thread drains (`drain_inbox`), so
nothing here needs a lock of its own. Manager and state-store calls take
core's shared lock, as v1's do.

**What D1 can target.** A decision needs a `RuleTarget`: the MAC, and its
IP from the binding table (or, failing that, the address the MAC was last
seen using). Aggregate evidence with no single device (fan-in, new-MAC and
new-lease rate, LAN-wide portal failures) is reported as an event and
never acted on.
"""

import logging
import queue
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
from typing import Final

from pirewall.config.models import PirewallConfig
from pirewall.core.enums import (
    EventSeverity,
    FirewallAction,
    GuardName,
    PipelineEngine,
    Protocol,
    RuleDirection,
    RuleStatus,
    SecurityEventType,
)
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.evidence_v2 import ClassifierEvidence, D1Evidence, KernelGuardEvidence
from pirewall.core.models.flow import Flow
from pirewall.core.models.identity import Binding, RuleTarget
from pirewall.core.models.metrics import V2Gauges
from pirewall.core.models.policy import PolicyDecision
from pirewall.core.models.rule import CandidateRule
from pirewall.detection.coordinator import DetectionCoordinator
from pirewall.detection_v2.d1 import D1State, start_from_record, start_from_signal, unicast_mac
from pirewall.detection_v2.kernel import KernelPollResult
from pirewall.detection_v2.thresholds import D1ThresholdFile
from pirewall.features.extractor import extract_features
from pirewall.firewall.manager import FirewallManager
from pirewall.flow.aggregator import NewFlowSignal, SlowConnectionCluster
from pirewall.flow.connection_start import ConnectionStartTracker
from pirewall.ipc.state import CoreStateStore
from pirewall.ml.labels import is_attack_label
from pirewall.policy.engine import EvidenceBundle, PolicyEngine
from pirewall.policy.table import PolicyTable
from pirewall.runtime.forwarder import EventForwarder
from pirewall.runtime.metrics import RuntimeCounters

__all__ = ["DISPLAY_SCORE_BY_ACTION", "V2Pipeline"]

_logger = logging.getLogger(__name__)
_SUBSYSTEM: Final = "policy"
_ANY: Final = IPv4Network("0.0.0.0/0")
_INBOX_MAX: Final = 4096
# Classifier evidence is corroboration for this long after its flow completed.
_ML_MEMORY: Final = timedelta(seconds=60)
_ML_PER_DEVICE: Final = 32
_AGGREGATE_SEEN_MAX: Final = 4096

DISPLAY_SCORE_BY_ACTION: Final = {
    FirewallAction.ALLOW: 0.0,
    FirewallAction.MONITOR: 40.0,
    FirewallAction.RATE_LIMIT: 70.0,
    FirewallAction.BLOCK: 100.0,
}
"""The dashboard number for a v2 decision: derived from the action, never an input to it."""

_SEVERITY_BY_ACTION: Final = {
    FirewallAction.MONITOR: EventSeverity.INFO,
    FirewallAction.RATE_LIMIT: EventSeverity.WARNING,
    FirewallAction.BLOCK: EventSeverity.CRITICAL,
}


@dataclass(frozen=True, slots=True)
class _KernelPoll:
    result: KernelPollResult
    bindings: Sequence[Binding]
    at: datetime


@dataclass(frozen=True, slots=True)
class _PortalFailure:
    account: str
    mac: str | None
    at: datetime


class V2Pipeline:
    """Feeds D1 and K evidence into the policy engine and its decisions into `FirewallManager`."""

    def __init__(
        self,
        *,
        config: PirewallConfig,
        thresholds: D1ThresholdFile,
        table: PolicyTable,
        manager: FirewallManager,
        state: CoreStateStore,
        forwarder: EventForwarder,
        counters: RuntimeCounters,
        lock: AbstractContextManager[bool],
        resolve_ip: Callable[[str], IPv4Address | None],
        coordinator: DetectionCoordinator | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        """`resolve_ip(mac)` is the binding table's MAC -> IP lookup; `coordinator` gives D3 when loaded."""
        self._config = config
        self._manager = manager
        self._state = state
        self._forwarder = forwarder
        self._counters = counters
        self._lock = lock
        self._resolve_ip = resolve_ip
        self._coordinator = coordinator
        self._monotonic = monotonic
        portal_port = config.portal.listen_port if config.portal.enabled else None
        self._d1 = D1State(config.d1, thresholds, () if portal_port is None else (portal_port,))
        self._tracker = ConnectionStartTracker(config.flow.connection_start_max_tracked)
        self._engine = PolicyEngine(table, config.policy, is_protected=self._is_protected)
        self._inbox: queue.Queue[_KernelPoll | _PortalFailure] = queue.Queue(maxsize=_INBOX_MAX)
        self._touched_macs: set[str] = set()
        self._touched_destinations: set[IPv4Address] = set()
        self._evaluated_at: OrderedDict[str, float] = OrderedDict()
        self._kernel: dict[str, tuple[KernelGuardEvidence, ...]] = {}
        self._ml: dict[str, deque[ClassifierEvidence]] = {}
        self._aggregate_seen: OrderedDict[str, None] = OrderedDict()
        self._last_global = float("-inf")
        self._gauges = V2Gauges()
        self.inbox_dropped = 0

    # ------------------------------------------------------------- properties

    @property
    def d1(self) -> D1State:
        """The detector state (read by tests and the status line)."""
        return self._d1

    @property
    def engine(self) -> PolicyEngine:
        """The policy engine."""
        return self._engine

    def gauges(self) -> V2Gauges:
        """The latest v2 gauges for the Netdata snapshot."""
        counters = self._d1.counters
        return self._gauges.model_copy(
            update={
                "d1_tracked_macs": self._d1.tracked_macs(),
                "d1_evictions": counters.macs_evicted
                + counters.destinations_evicted
                + counters.events_dropped,
            }
        )

    # ------------------------------------------- inputs (detection thread)

    def observe_signal(self, signal: NewFlowSignal) -> None:
        """A creation-time new-flow signal (the fast path): cardinality detectors only."""
        start = start_from_signal(
            source_mac=signal.source_mac,
            source_ip=signal.source_ip,
            destination_ip=signal.destination_ip,
            destination_port=signal.destination_port,
            protocol=signal.protocol,
            at=signal.timestamp,
        )
        if start is not None:
            self._d1.observe(start)
            self._touched_macs.add(start.mac)
            self._touched_destinations.add(start.destination_ip)

    def observe_record(self, flow: Flow, now: datetime) -> None:
        """A completed flow record: connection-start accounting, then optional D3 corroboration."""
        start = start_from_record(flow, self._tracker.observe(flow))
        if start is not None:
            self._d1.observe(start)
            self._touched_macs.add(start.mac)
            self._touched_destinations.add(start.destination_ip)
        self._classify(flow, now)

    def observe_slow_cluster(self, cluster: SlowConnectionCluster, now: datetime) -> None:
        """A v1 slow-connection cluster (ADDENDUM_2 B2), as the D1 slow-rate DoS input."""
        mac = unicast_mac(cluster.representative_flow.source_mac)
        if mac is None:
            return
        self._d1.observe_slow_cluster(
            mac, cluster.source_ip, cluster.destination_ip, cluster.concurrent_count, now
        )
        self._touched_macs.add(mac)

    # ----------------------------------------- inputs (other threads)

    def submit_kernel_poll(self, result: KernelPollResult, bindings: Sequence[Binding], at: datetime) -> None:
        """Hand one kernel poll (and the binding table at that moment) to the detection thread."""
        self._put(_KernelPoll(result, bindings, at))

    def submit_portal_failure(
        self, account: str, client_ip: IPv4Address, client_mac: str | None, at: datetime
    ) -> None:
        """`PortalService`'s failed-login hook. `client_ip` is not kept: the MAC is the identity (D3)."""
        del client_ip
        self._put(_PortalFailure(account, client_mac, at))

    def _put(self, item: _KernelPoll | _PortalFailure) -> None:
        try:
            self._inbox.put_nowait(item)
        except queue.Full:
            self.inbox_dropped += 1

    def drain_inbox(self, now: datetime) -> None:
        """Fold pending kernel polls and portal failures into the state. Detection thread only."""
        while True:
            try:
                item = self._inbox.get_nowait()
            except queue.Empty:
                return
            if isinstance(item, _PortalFailure):
                self._d1.observe_portal_failure(item.account, item.mac, item.at)
                if item.mac is not None:
                    self._touched_macs.add(item.mac)
                continue
            self._apply_kernel_poll(item, now)

    def _apply_kernel_poll(self, poll: _KernelPoll, now: datetime) -> None:
        result = poll.result
        self._d1.observe_bindings(poll.bindings, poll.at)
        if result.error is not None:
            _logger.warning("%s", result.error)
        for alert in result.alerts:
            self._emit_system(alert.severity, alert.reason, now)
        current: dict[str, list[KernelGuardEvidence]] = {}
        for item in result.evidence:
            current.setdefault(str(item.mac), []).append(item)
        stale = set(self._kernel) - set(current)
        self._kernel = {mac: tuple(items) for mac, items in current.items()}
        self._touched_macs.update(current)
        del stale  # an offender that expired simply stops contributing
        hits = result.guard_hits
        self._gauges = self._gauges.model_copy(
            update={
                "guard_hits_raw": hits.get(GuardName.RAW, 0),
                "guard_hits_input": hits.get(GuardName.INPUT, 0),
                "guard_hits_forward": hits.get(GuardName.FORWARD, 0),
                "offenders": result.offender_count,
                "max_set_fill_ratio": result.max_set_fill_ratio,
                "kernel_evidence": self._gauges.kernel_evidence + len(result.evidence),
            }
        )

    # -------------------------------------------------------------- decisions

    def evaluate(self, now: datetime) -> None:
        """Run the detectors for every touched device and destination, then the LAN-wide ones.

        Each MAC at most once per `d1.evaluation_cooldown_seconds`; a MAC
        skipped by the cooldown stays touched for the next pass.
        """
        cooldown = self._config.d1.evaluation_cooldown_seconds
        now_monotonic = self._monotonic()
        pending = self._touched_macs
        self._touched_macs = set()
        for mac in sorted(pending):
            last = self._evaluated_at.get(mac)
            if last is not None and now_monotonic - last < cooldown:
                self._touched_macs.add(mac)
                continue
            self._evaluated_at[mac] = now_monotonic
            self._evaluated_at.move_to_end(mac)
            while len(self._evaluated_at) > self._config.d1.max_tracked_macs:
                self._evaluated_at.popitem(last=False)
            self._decide_for(mac, now)
        destinations = self._touched_destinations
        self._touched_destinations = set()
        for destination in sorted(destinations):
            self._report_aggregate(self._d1.evaluate_destination(destination, now), now)
        if now_monotonic - self._last_global >= self._config.d1.kernel_poll_interval_seconds:
            self._last_global = now_monotonic
            aggregate: list[D1Evidence] = []
            by_device: dict[str, list[D1Evidence]] = {}
            for item in self._d1.evaluate_global(now):
                if item.mac is None:
                    aggregate.append(item)
                else:
                    by_device.setdefault(str(item.mac), []).append(item)
            # One bundle per device: every window of one burst is one decision, not an escalation.
            for mac, items in sorted(by_device.items()):
                self._decide_for(mac, now, extra=items)
            self._report_aggregate(aggregate, now)

    def _decide_for(self, mac: str, now: datetime, extra: Sequence[D1Evidence] = ()) -> None:
        d1 = [*self._d1.evaluate_device(mac, now), *extra]
        self._gauges = self._gauges.model_copy(update={"d1_evidence": self._gauges.d1_evidence + len(d1)})
        ml = self._recent_ml(mac, now)
        bundle_items = (*self._kernel.get(mac, ()), *d1, *ml)
        if not bundle_items:
            return
        ip = self._resolve_ip(mac) or self._d1.last_ip(mac)
        if ip is None:
            self._report_untargetable(mac, bundle_items, now)
            return
        bundle = EvidenceBundle(RuleTarget(ip=ip, mac=mac), bundle_items)
        mode = self._manager.enforcement_mode
        had_d1 = any(isinstance(item, D1Evidence) for item in bundle_items)
        for decision in self._engine.decide(bundle, mode, now):
            if decision.requires_approval and self._approval_pending(decision.target):
                continue  # one BLOCK per device waits in the A7 queue at a time
            self._submit(decision, had_d1, now)

    def _approval_pending(self, target: RuleTarget) -> bool:
        with self._lock:
            rules = self._manager.all_rules()
        return any(
            rule.status is RuleStatus.PENDING_APPROVAL
            and rule.action is FirewallAction.BLOCK
            and rule.target is not None
            and (rule.target.mac == target.mac if target.mac is not None else rule.target.ip == target.ip)
            for rule in rules
        )

    def _submit(self, decision: PolicyDecision, had_d1: bool, now: datetime) -> None:
        assert decision.threat_level is not None  # filled in by PolicyDecision's validator
        score = DISPLAY_SCORE_BY_ACTION[decision.action]
        reason = "; ".join(decision.reasons)
        firewall_decision = FirewallDecision(
            id=decision.id,
            threat_assessment_id=decision.id,
            action=decision.action,
            threat_score=score,
            threat_level=decision.threat_level,
            reason=reason,
            evidence=decision.evidence_ids,
            decided_at=now,
        )
        ttl = decision.ttl_seconds or self._config.policy.rate_limit_ttl_seconds
        candidate = CandidateRule(
            decision_id=decision.id,
            action=decision.action,
            direction=RuleDirection.INBOUND,
            source=IPv4Network(f"{decision.target.ip}/32"),
            destination=_ANY,  # display only: a v2 element acts on the whole device
            protocol=Protocol.ANY,
            reason=reason,
            threat_score=score,
            evidence=decision.evidence_ids,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            metadata={"engine": PipelineEngine.V2.value, "policy_decision_id": decision.id},
            target=decision.target,
        )
        self._forwarder.emit(
            SecurityEvent(
                timestamp=now,
                severity=_SEVERITY_BY_ACTION.get(decision.action, EventSeverity.INFO),
                event_type=SecurityEventType.POLICY_DECISION,
                subsystem=_SUBSYSTEM,
                source=decision.target.ip,
                threat_score=score,
                decision=decision.action,
                reason=reason,
                mac=None if decision.target.mac is None else str(decision.target.mac),
                engine=PipelineEngine.V2,
                policy_decision_id=decision.id,
                evidence_ids=decision.evidence_ids,
                requires_approval=decision.requires_approval,
            )
        )
        with self._lock:
            self._state.record_decision(firewall_decision)
            self._manager.register_decision(firewall_decision)
            result = self._manager.submit_candidate(candidate, now)
        self._counters.add(detections=1)
        self._gauges = self._gauges.model_copy(update={"policy_decisions": self._gauges.policy_decisions + 1})
        if result.rule is None:
            self._counters.add(rules_rejected=1)
        else:
            self._engine.record_enforced(decision, had_d1)
            if decision.action is FirewallAction.BLOCK:
                self._counters.add(blocks=1)
        self._forwarder.emit(result.event)

    # ------------------------------------------------------------------ ML

    def _classify(self, flow: Flow, now: datetime) -> None:
        """D3 corroboration from the loaded LightGBM model, if any (MONITOR or corroboration only)."""
        coordinator = self._coordinator
        mac = unicast_mac(flow.source_mac)
        if coordinator is None or mac is None or coordinator.models.lightgbm is None:
            return
        if not coordinator.in_model_domain(flow):
            return
        try:
            outcome = coordinator.analyze_except_anomaly(flow, extract_features(flow), now)
        except Exception:  # a model failure costs this flow's corroboration, never the pipeline
            _logger.exception("D3 corroboration failed for flow %s", flow.flow_id)
            return
        known = outcome.record.known_evidence
        if known is None:
            return
        benign = sum(p for label, p in known.class_probabilities.items() if not is_attack_label(label))
        probability = min(max(1.0 - benign if known.class_probabilities else known.confidence, 0.0), 1.0)
        operating = self._config.detection.known_attack_confidence_threshold
        evidence = ClassifierEvidence(
            flow_id=flow.flow_id,
            mac=mac,
            attack_probability=probability,
            operating_threshold=operating,
            is_attack=probability >= operating,
            family=known.predicted_class if is_attack_label(known.predicted_class) else None,
            family_probability=known.confidence if is_attack_label(known.predicted_class) else None,
            model_version=known.model_version,
            feature_schema_version=known.feature_schema_version,
            generated_at=now,
        )
        if not evidence.is_attack:
            return
        recent = self._ml.setdefault(mac, deque(maxlen=_ML_PER_DEVICE))
        recent.append(evidence)
        while len(self._ml) > self._config.d1.max_tracked_macs:
            del self._ml[next(iter(self._ml))]
        self._touched_macs.add(mac)

    def _recent_ml(self, mac: str, now: datetime) -> tuple[ClassifierEvidence, ...]:
        recent = self._ml.get(mac)
        if not recent:
            return ()
        while recent and recent[0].generated_at < now - _ML_MEMORY:
            recent.popleft()
        return tuple(recent)

    # ------------------------------------------------------------ reporting

    def _is_protected(self, target: RuleTarget) -> bool:
        config = self._config
        infrastructure = {
            config.network.pirewall_lan_ip,
            config.network.upstream_gateway,
            config.admin.admin_pc_ip,
        }
        if target.ip in infrastructure:
            return True
        if target.mac is not None and target.mac == config.admin.admin_pc_mac:
            return True
        return any(
            target.ip in entry.target or (target.mac is not None and entry.mac == target.mac)
            for entry in self._manager.allowlist
        )

    def _report_aggregate(self, evidence: Sequence[D1Evidence], now: datetime) -> None:
        for item in evidence:
            if item.id in self._aggregate_seen:
                continue
            self._aggregate_seen[item.id] = None
            while len(self._aggregate_seen) > _AGGREGATE_SEEN_MAX:
                self._aggregate_seen.popitem(last=False)
            self._forwarder.emit(
                SecurityEvent(
                    timestamp=now,
                    severity=EventSeverity.WARNING,
                    event_type=SecurityEventType.THREAT_DETECTED,
                    subsystem=_SUBSYSTEM,
                    reason=(
                        f"D1 {item.detector.value} over {item.window_seconds}s: {item.value:g} > "
                        f"{item.threshold:g} ({item.id.split(':')[4]}); no single device, reported only"
                    ),
                    engine=PipelineEngine.V2,
                    evidence_ids=(item.id,),
                )
            )

    def _report_untargetable(self, mac: str, items: Sequence[object], now: datetime) -> None:
        ids = tuple(str(getattr(item, "id", "")) for item in items if getattr(item, "id", None))
        key = "untargetable:" + ",".join(sorted(ids))
        if key in self._aggregate_seen:
            return
        self._aggregate_seen[key] = None
        self._forwarder.emit(
            SecurityEvent(
                timestamp=now,
                severity=EventSeverity.WARNING,
                event_type=SecurityEventType.THREAT_DETECTED,
                subsystem=_SUBSYSTEM,
                reason=f"evidence for {mac}, but no IP is known for it: reported, not acted on",
                mac=mac,
                engine=PipelineEngine.V2,
                evidence_ids=ids,
            )
        )

    def _emit_system(self, severity: EventSeverity, reason: str, now: datetime) -> None:
        self._forwarder.emit(
            SecurityEvent(
                timestamp=now,
                severity=severity,
                event_type=SecurityEventType.SYSTEM_WARNING,
                subsystem=_SUBSYSTEM,
                reason=reason,
                engine=PipelineEngine.V2,
            )
        )
