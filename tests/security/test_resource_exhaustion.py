"""Resource exhaustion under flood conditions (spec §27 "Resource exhaustion", §39).

Complements the flood tests already in earlier phases (`FlowTable` LRU
eviction to a 100-flow cap, `BehaviorAnalyzer` bounded to 5000 sources) with
the two spec §39 items those didn't cover: **event-queue exhaustion**
(`pirewall.ipc.state.CoreStateStore`, Phase 7's bounded recent-history
buffer) and **excessive rule-creation attempts**
(ADDENDUM.md A3's rate cap, exercised here as a genuine flood through the
real `FirewallManager` rather than the rate limiter in isolation — see
`tests/unit/test_rate_limiter.py`/`tests/unit/test_validator.py` for that).
Every assertion here is about *bounded state*, not just "it didn't crash"
(per this phase's own instruction).
"""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from pirewall.core.enums import EventSeverity, FirewallAction, RuleStatus, SecurityEventType, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.detection_record import DetectionRecord
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.rule import CandidateRule
from pirewall.core.models.threat import ThreatAssessment
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.state import CoreStateStore
from tests.helpers.config import make_config
from tests.helpers.flows import make_flow
from tests.helpers.rules import make_candidate

NOW = datetime(2026, 1, 1, tzinfo=UTC)
_MAX_HISTORY = 50
_FLOOD_MULTIPLE = 20  # far more than max_history, simulating a sustained flood


def test_core_state_store_event_queue_stays_bounded_under_flood() -> None:
    state = CoreStateStore(max_history=_MAX_HISTORY, started_at=NOW)

    for i in range(_MAX_HISTORY * _FLOOD_MULTIPLE):
        state.record_event(
            SecurityEvent(
                timestamp=NOW + timedelta(seconds=i),
                severity=EventSeverity.WARNING,
                event_type=SecurityEventType.THREAT_DETECTED,
                subsystem="test-flood",
                reason=f"event-{i}",
            )
        )

    assert len(state.events) == _MAX_HISTORY
    # The buffer keeps the *most recent* entries, not the first ones seen.
    assert state.events[-1].reason == f"event-{_MAX_HISTORY * _FLOOD_MULTIPLE - 1}"
    assert state.events[0].reason == f"event-{_MAX_HISTORY * _FLOOD_MULTIPLE - _MAX_HISTORY}"


def test_core_state_store_every_buffer_stays_bounded_under_flood() -> None:
    """Every one of `CoreStateStore`'s bounded buffers, not just events, flooded simultaneously."""
    state = CoreStateStore(max_history=_MAX_HISTORY, started_at=NOW)
    count = _MAX_HISTORY * _FLOOD_MULTIPLE

    for i in range(count):
        state.record_flow(make_flow(flow_id=f"flow-{i}"))
        state.record_detection(DetectionRecord(flow_id=f"flow-{i}", recorded_at=NOW))
        state.record_threat(
            ThreatAssessment(
                id=f"threat-{i}",
                flow_id=f"flow-{i}",
                source_ip=IPv4Address("10.0.0.5"),
                destination_ip=IPv4Address("10.0.0.10"),
                threat_score=10.0,
                threat_level=ThreatLevel.LOW,
                confidence=0.1,
                explanation="flood test",
                assessed_at=NOW,
            )
        )
        state.record_decision(
            FirewallDecision(
                id=f"decision-{i}",
                threat_assessment_id=f"threat-{i}",
                action=FirewallAction.ALLOW,
                threat_score=10.0,
                threat_level=ThreatLevel.LOW,
                reason="flood test",
                decided_at=NOW,
            )
        )

    assert len(state.flows) == _MAX_HISTORY
    assert len(state.detections) == _MAX_HISTORY
    assert len(state.threats) == _MAX_HISTORY
    assert len(state.decisions) == _MAX_HISTORY


def _register_decision_for(manager: FirewallManager, candidate: CandidateRule) -> None:
    manager.register_decision(
        FirewallDecision(
            id=candidate.decision_id,
            threat_assessment_id="assessment-1",
            action=candidate.action,
            threat_score=candidate.threat_score if candidate.threat_score is not None else 0.0,
            threat_level=ThreatLevel.CRITICAL,
            reason="flood test",
            decided_at=NOW,
        )
    )


def test_excessive_rule_creation_is_capped_not_unbounded() -> None:
    """ADDENDUM.md A3: hundreds of distinct malicious-looking candidates in one window.

    Only `max_adaptive_rules_per_window` may ever reach the backend or
    `ACTIVE` status — the rest are rejected `RATE_LIMITED`, and detection
    (candidate construction/decision registration) keeps happening at full
    fidelity throughout, per A3's "the cap only ever blocks rule *creation*,
    not detection" guarantee.
    """
    budget = 10
    config = make_config(
        firewall={
            "enforcement_mode": "active",
            "max_adaptive_rules_per_window": budget,
            "rate_window_seconds": 60,
        }
    )
    backend = FakeFirewallBackend()
    manager = FirewallManager(config, backend)

    flood_size = budget * 20
    active_count = 0
    rate_limited_count = 0
    for i in range(flood_size):
        candidate = make_candidate(
            decision_id=f"decision-{i}", destination=f"203.0.113.{i % 250}/32"
        )
        _register_decision_for(manager, candidate)
        result = manager.submit_candidate(candidate, NOW)
        if result.rule is not None and result.rule.status is RuleStatus.ACTIVE:
            active_count += 1
        elif result.event.reason is not None and "rate_limited" in result.event.reason:
            rate_limited_count += 1

    assert active_count == budget  # never more than the configured budget
    # every excess attempt was rejected, not silently dropped
    assert rate_limited_count == flood_size - budget
    assert len(manager.active_rules()) == budget
    assert backend.apply_calls == budget  # the backend itself never saw the excess either
