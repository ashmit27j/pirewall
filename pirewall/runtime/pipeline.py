"""`FlowPipeline`: one completed flow's journey from features to an enforced rule.

This is the module that actually connects pirewall's layers end to end, in
the order `CLAUDE.md` and spec §19 require them to stay separated:

```text
Flow
  -> pirewall.features.extractor.extract_features        (features)
  -> pirewall.detection.coordinator.DetectionCoordinator (detection: evidence only)
  -> pirewall.engine.threat.assess_threat                (scoring)
  -> pirewall.engine.decision.decide                     (decision)
  -> pirewall.firewall.generator.generate_candidate_rule (candidate rule)
  -> pirewall.firewall.manager.FirewallManager           (validation + enforcement)
```

Each arrow is a call into a module that knows nothing about the next one.
The pipeline holds no detection logic, no scoring logic and no rule logic of
its own — it is wiring, and every threshold it uses comes from
`PirewallConfig`.

**Nothing here can bypass validation.** The only way a rule reaches the
backend is `FirewallManager.submit_candidate`, which runs the full
ten-stage chain (schema -> network -> allowlist -> safety -> conflict ->
duplicate -> rate cap -> priority -> expiration -> authorization) every
time. `register_decision` is called with the decision the engine actually
produced, immediately before submitting the candidate derived from it, so
the authorization stage validates a real provenance link rather than being
handed a blanket exemption.

**No failure in here may lose the process.** A flow that raises anywhere in
the chain is logged, counted, reported as a `SecurityEvent`, and dropped;
capture and the rest of the pipeline keep running (spec §26, ADDENDUM.md
A6 fail-open).
"""

import logging
import time
from contextlib import AbstractContextManager
from datetime import datetime

from pirewall.config.models import PirewallConfig
from pirewall.core.enums import EventSeverity, FirewallAction, SecurityEventType, ThreatLevel
from pirewall.core.exceptions import FeatureExtractionError, PirewallError
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.flow import Flow
from pirewall.detection.coordinator import DetectionCoordinator
from pirewall.engine.decision import EvidenceMaturityTracker, decide
from pirewall.engine.threat import assess_threat
from pirewall.features.extractor import extract_features
from pirewall.firewall.generator import generate_candidate_rule
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.state import CoreStateStore
from pirewall.runtime.forwarder import EventForwarder
from pirewall.runtime.metrics import RuntimeCounters

_logger = logging.getLogger(__name__)
_SUBSYSTEM = "runtime.pipeline"

# Threat levels worth an audit-trail entry of their own. LOW is every
# ordinary flow on a home network; recording one event per benign flow
# would bury the events that matter and evict them from the bounded store.
_REPORTABLE_LEVELS = frozenset({ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL})


class FlowPipeline:
    """Runs one completed `Flow` through detection, decision, and enforcement."""

    def __init__(
        self,
        config: PirewallConfig,
        coordinator: DetectionCoordinator,
        manager: FirewallManager,
        state: CoreStateStore,
        forwarder: EventForwarder,
        counters: RuntimeCounters,
        lock: AbstractContextManager[bool],
    ) -> None:
        self._config = config
        self._coordinator = coordinator
        self._manager = manager
        self._state = state
        self._forwarder = forwarder
        self._counters = counters
        # ADDENDUM_2.md B3 — detection-thread-only, same as everything else
        # this class owns; no locking needed.
        self._maturity_tracker = EvidenceMaturityTracker.from_config(config.threat)
        # The same lock `CoreDaemon` gives the RPC dispatcher: this thread
        # mutates `CoreStateStore` and `FirewallManager` while the RPC
        # thread reads both to answer `/status`, `/rules`, `/threats`.
        self._lock = lock

    def process(self, flow: Flow, now: datetime) -> None:
        """Process one completed flow. Never raises — see the module docstring."""
        try:
            self._process(flow, now)
        except PirewallError as exc:
            self._report_failure(flow, now, exc)
        except Exception as exc:  # a bug here must not take capture down with it
            _logger.exception("unexpected error processing flow %s", flow.flow_id)
            self._report_failure(flow, now, exc)

    def _process(self, flow: Flow, now: datetime) -> None:
        with self._lock:
            self._state.record_flow(flow)

        try:
            features = extract_features(flow)
        except FeatureExtractionError as exc:
            self._report_failure(flow, now, exc)
            return

        started = time.perf_counter()
        outcome = self._coordinator.analyze(flow, features, now)
        elapsed_seconds = time.perf_counter() - started
        if self._coordinator.models.any_loaded:
            self._counters.add(inferences=1, inference_seconds_total=elapsed_seconds)

        assessment = assess_threat(
            self._config.threat,
            flow_id=flow.flow_id,
            source_ip=flow.source_ip,
            destination_ip=flow.destination_ip,
            known_evidence=outcome.record.known_evidence,
            anomaly_evidence=outcome.record.anomaly_evidence,
            behavior_assessment=outcome.behavior,
            assessed_at=now,
        )
        decision = decide(assessment, now, self._maturity_tracker)

        with self._lock:
            self._state.record_detection(outcome.record)
            self._state.record_threat(assessment)
            self._state.record_decision(decision)
        self._counters.add(detections=1)

        if assessment.threat_level in _REPORTABLE_LEVELS:
            self._forwarder.emit(
                SecurityEvent(
                    timestamp=now,
                    severity=_severity_for(assessment.threat_level),
                    event_type=SecurityEventType.THREAT_DETECTED,
                    subsystem=_SUBSYSTEM,
                    source=flow.source_ip,
                    destination=flow.destination_ip,
                    protocol=flow.protocol,
                    flow_id=flow.flow_id,
                    threat_score=assessment.threat_score,
                    decision=decision.action,
                    reason=assessment.explanation,
                )
            )

        candidate = generate_candidate_rule(
            decision, flow, now, self._config.firewall.default_rule_ttl_seconds
        )
        if candidate is None:
            # ALLOW: nothing to enforce. Not an error, and not worth an event.
            return

        with self._lock:
            self._manager.register_decision(decision)
            result = self._manager.submit_candidate(candidate, now)

        if result.rule is None:
            self._counters.add(rules_rejected=1)
        elif decision.action is FirewallAction.BLOCK:
            self._counters.add(blocks=1)
        self._forwarder.emit(result.event)

    def _report_failure(self, flow: Flow, now: datetime, exc: Exception) -> None:
        self._forwarder.emit(
            SecurityEvent(
                timestamp=now,
                severity=EventSeverity.ERROR,
                event_type=SecurityEventType.FLOW_ERROR,
                subsystem=_SUBSYSTEM,
                source=flow.source_ip,
                destination=flow.destination_ip,
                protocol=flow.protocol,
                flow_id=flow.flow_id,
                reason=f"{type(exc).__name__}: {exc}",
            )
        )


def _severity_for(level: ThreatLevel) -> EventSeverity:
    if level is ThreatLevel.CRITICAL:
        return EventSeverity.CRITICAL
    if level is ThreatLevel.HIGH:
        return EventSeverity.ERROR
    return EventSeverity.WARNING
