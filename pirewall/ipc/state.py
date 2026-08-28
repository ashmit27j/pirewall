"""`CoreStateStore`: pirewall-core's bounded, in-memory recent-history buffer.

Nothing before Phase 7 retains a rolling history of `Flow`/`DetectionRecord`/
`ThreatAssessment`/`FirewallDecision`/`SecurityEvent` objects — each earlier
phase's modules are pure transformers. This is the one place that does,
specifically so `pirewall.ipc.dispatcher` (and, through it, the API's read
endpoints) has real state to read. Every collection is a bounded `deque`
(spec §17/§26's "state must be bounded" theme applies here too) — this can
never grow without limit no matter how long pirewall-core runs.
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

from pirewall.core.models.capture_stats import CaptureStatistics
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.detection_record import DetectionRecord
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.flow import Flow
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.core.models.threat import ThreatAssessment


@dataclass(slots=True)
class CoreStateStore:
    """Bounded recent-history buffers, sized by `config.api.history_size`."""

    max_history: int
    started_at: datetime
    lightgbm_metadata: ModelMetadata | None = None
    isolation_forest_metadata: ModelMetadata | None = None
    # Latest reading from `PacketCapture.statistics()`. A single current
    # value rather than a history: the control panel's "network statistics"
    # section (spec §30) asks what capture is doing *now*, and the rate
    # metrics that need history are derived in
    # `pirewall.runtime.metrics.MetricsCollector` instead.
    capture_stats: CaptureStatistics | None = None
    flows: deque[Flow] = field(default_factory=deque[Flow])
    detections: deque[DetectionRecord] = field(default_factory=deque[DetectionRecord])
    threats: deque[ThreatAssessment] = field(default_factory=deque[ThreatAssessment])
    decisions: deque[FirewallDecision] = field(default_factory=deque[FirewallDecision])
    events: deque[SecurityEvent] = field(default_factory=deque[SecurityEvent])

    def __post_init__(self) -> None:
        self.flows = deque(self.flows, maxlen=self.max_history)
        self.detections = deque(self.detections, maxlen=self.max_history)
        self.threats = deque(self.threats, maxlen=self.max_history)
        self.decisions = deque(self.decisions, maxlen=self.max_history)
        self.events = deque(self.events, maxlen=self.max_history)

    def record_flow(self, flow: Flow) -> None:
        self.flows.append(flow)

    def record_detection(self, record: DetectionRecord) -> None:
        self.detections.append(record)

    def record_threat(self, assessment: ThreatAssessment) -> None:
        self.threats.append(assessment)

    def record_decision(self, decision: FirewallDecision) -> None:
        self.decisions.append(decision)

    def record_event(self, event: SecurityEvent) -> None:
        self.events.append(event)

    def record_capture_stats(self, stats: CaptureStatistics) -> None:
        """Replace the current capture-statistics reading (spec §6, §30)."""
        self.capture_stats = stats
