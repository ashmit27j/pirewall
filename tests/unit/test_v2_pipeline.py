"""`V2Pipeline` wiring (phase 17): K and D1 evidence through the policy table into `FirewallManager`.

Mocked: `FakeSetBackend` stands in for the kernel.
"""

import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any, Final

import pytest

from pirewall.core import nft_names
from pirewall.core.enums import (
    EnforcementMode,
    FirewallAction,
    GuardMode,
    GuardName,
    Protocol,
    RuleStatus,
    SecurityEventType,
)
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.evidence import AnomalyEvidence, KnownEvidence
from pirewall.core.models.feature_vector import FeatureVector
from pirewall.core.nft_names import OffenderCode
from pirewall.detection_v2.kernel import KernelPoller
from pirewall.detection_v2.thresholds import load_thresholds
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.integration.netdata import snapshot_to_metrics
from pirewall.integration.wazuh import format_event
from pirewall.ipc.state import CoreStateStore
from pirewall.policy.table import load_policy_table
from pirewall.runtime.core import _ManagerKernelReader  # pyright: ignore[reportPrivateUsage]
from pirewall.runtime.forwarder import EventForwarder
from pirewall.runtime.metrics import RuntimeCounters
from pirewall.runtime.pipeline_v2 import DISPLAY_SCORE_BY_ACTION, V2Pipeline
from tests.helpers.config import make_config
from tests.helpers.flows import make_flow

_REPO: Final = Path(__file__).resolve().parents[2]
MAC: Final = "02:00:00:00:00:66"
IP: Final = IPv4Address("192.168.1.66")
T0: Final = datetime.now(UTC)


class _Harness:
    def __init__(
        self,
        mode: EnforcementMode,
        forward: GuardMode = GuardMode.ENFORCE,
        coordinator: Any = None,
        **sections: dict[str, Any],
    ) -> None:
        self.now = T0
        config = make_config(firewall={"enforcement_mode": mode.value}, **sections)
        self.sets = FakeSetBackend(lambda: self.now, guard_modes={GuardName.FORWARD: forward})
        self.manager = FirewallManager(config, FakeFirewallBackend(), set_backend=self.sets)
        self.state = CoreStateStore(100, started_at=T0)
        lock = threading.RLock()
        self.events: list[SecurityEvent] = []
        forwarder = EventForwarder(self.state, None, lock)
        original = forwarder.emit

        def emit(event: SecurityEvent) -> None:
            self.events.append(event)
            original(event)

        forwarder.emit = emit  # type: ignore[method-assign]
        self.pipeline = V2Pipeline(
            config=config,
            thresholds=load_thresholds(_REPO / "config" / "d1_thresholds.toml"),
            table=load_policy_table(_REPO / "pirewall" / "policy" / "table.toml"),
            manager=self.manager,
            state=self.state,
            forwarder=forwarder,
            counters=RuntimeCounters(),
            lock=lock,
            resolve_ip=lambda mac: IP if mac == MAC else None,
            coordinator=coordinator,
            monotonic=lambda: (self.now - T0).total_seconds(),
        )
        self.poller = KernelPoller(
            _ManagerKernelReader(self.manager), sustained_polls=2, set_fill_warning_ratio=0.8
        )

    def poll(self, seconds: float = 1.0) -> None:
        self.now += timedelta(seconds=seconds)
        self.pipeline.submit_kernel_poll(self.poller.poll(self.now), (), self.now)
        self.pipeline.drain_inbox(self.now)
        self.pipeline.evaluate(self.now)

    def elements(self, set_name: str) -> list[object]:
        return [state.key for state in self.sets.list_set(set_name)]


def test_a_sustained_enforce_offender_rate_limits_the_mac() -> None:
    harness = _Harness(EnforcementMode.ACTIVE)
    harness.sets.record_offender(MAC, OffenderCode.NEWCONN)

    harness.poll()
    assert harness.elements(nft_names.SET_RATELIMIT_MAC) == []  # one poll: MONITOR only
    harness.poll()

    assert harness.elements(nft_names.SET_RATELIMIT_MAC) == [MAC]
    rule = next(rule for rule in harness.manager.active_rules() if rule.action is FirewallAction.RATE_LIMIT)
    assert rule.threat_score == DISPLAY_SCORE_BY_ACTION[FirewallAction.RATE_LIMIT]
    assert rule.metadata["engine"] == "v2"


def test_an_observe_offender_never_writes_an_element_however_long_it_lasts() -> None:
    harness = _Harness(EnforcementMode.ACTIVE, forward=GuardMode.OBSERVE)
    harness.sets.record_offender(MAC, OffenderCode.NEWCONN, timeout_seconds=600)

    for _ in range(20):
        harness.poll()

    for name in nft_names.ADAPTIVE_ENFORCEMENT_SETS:
        assert harness.elements(name) == []
    decisions = [event for event in harness.events if event.event_type is SecurityEventType.POLICY_DECISION]
    assert [event.decision for event in decisions] == [FirewallAction.MONITOR]  # one episode, one decision


def test_an_allowlisted_device_is_never_acted_on() -> None:
    harness = _Harness(EnforcementMode.ACTIVE)
    harness.manager.add_allowlist_entry(
        AllowlistEntry(
            target=IPv4Network("192.168.1.66/32"), mac=MAC, reason="test", created_at=T0, created_by="test"
        )
    )
    harness.sets.record_offender(MAC, OffenderCode.NEWCONN)

    for _ in range(5):
        harness.poll()

    assert harness.elements(nft_names.SET_RATELIMIT_MAC) == []
    assert not [event for event in harness.events if event.event_type is SecurityEventType.POLICY_DECISION]


def _scan(harness: _Harness, ports: range) -> None:
    for port in ports:
        flow = make_flow(
            flow_id=f"scan-{port}",
            source_ip=str(IP),
            destination_ip="192.168.1.10",
            source_port=51000,
            destination_port=port,
            first_seen=harness.now,
            duration_seconds=0.01,
            packet_count=2,
            forward_packet_count=1,
            backward_packet_count=1,
            byte_count=80,
            forward_byte_count=40,
            backward_byte_count=40,
            tcp_flags={"syn": 1, "rst": 1, "ack": 1},
        ).model_copy(update={"source_mac": MAC})
        harness.pipeline.observe_record(flow, harness.now)


def test_assisted_holds_the_block_and_rate_limits_meanwhile() -> None:
    harness = _Harness(EnforcementMode.ASSISTED)
    _scan(harness, range(1, 80))
    harness.pipeline.evaluate(harness.now)

    statuses = {(rule.action, rule.status) for rule in harness.manager.all_rules()}
    assert (FirewallAction.BLOCK, RuleStatus.PENDING_APPROVAL) in statuses
    assert (FirewallAction.RATE_LIMIT, RuleStatus.ACTIVE) in statuses
    pending = next(rule for rule in harness.manager.all_rules() if rule.status is RuleStatus.PENDING_APPROVAL)

    result = harness.manager.approve_pending(pending.id, harness.now)

    assert result is not None and result.rule is not None and result.rule.status is RuleStatus.ACTIVE
    assert harness.elements(nft_names.SET_BLOCK_MAC) == [MAC]
    assert harness.elements(nft_names.SET_RATELIMIT_MAC) == []  # the upgrade was one atomic delete+add


def test_a_continuing_scan_keeps_one_block_waiting_for_approval() -> None:
    harness = _Harness(EnforcementMode.ASSISTED)
    for minute in range(4):  # new window buckets: new independent evidence each time
        harness.now += timedelta(seconds=61)
        _scan(harness, range(1 + 100 * minute, 80 + 100 * minute))
        harness.pipeline.evaluate(harness.now)

    pending = [rule for rule in harness.manager.all_rules() if rule.status is RuleStatus.PENDING_APPROVAL]
    assert len(pending) == 1


def test_events_carry_the_v2_fields_to_wazuh_and_gauges_to_netdata() -> None:
    harness = _Harness(EnforcementMode.ACTIVE)
    _scan(harness, range(1, 80))
    harness.pipeline.evaluate(harness.now)

    decision = next(
        event for event in harness.events if event.event_type is SecurityEventType.POLICY_DECISION
    )
    payload = format_event(decision)
    assert payload["event_type"] == "policy_decision"
    assert payload["mac"] == MAC and payload["engine"] == "v2" and payload["decision"] == "block"
    assert payload["evidence_ids"] and payload["requires_approval"] is False
    gauges = harness.pipeline.gauges()
    assert gauges.policy_decisions >= 1 and gauges.d1_evidence >= 1 and gauges.d1_tracked_macs == 1


def test_a_scores_display_value_comes_from_the_action() -> None:
    assert (
        DISPLAY_SCORE_BY_ACTION[FirewallAction.BLOCK] == 100.0
    )  # always >= assisted_review_threshold (<= 100)
    assert sorted(DISPLAY_SCORE_BY_ACTION.values()) == list(DISPLAY_SCORE_BY_ACTION.values())


def test_the_netdata_snapshot_exports_v2_gauges() -> None:
    from pirewall.core.models.metrics import NetdataMetricsSnapshot, V2Gauges

    base: dict[str, Any] = {
        "cpu_percent": 1.0,
        "memory_percent": 1.0,
        "packet_rate_per_second": 0.0,
        "packet_drops": 0,
        "active_flows": 0,
        "flow_creation_rate_per_second": 0.0,
        "flow_expiration_rate_per_second": 0.0,
        "inference_count": 0,
        "inference_latency_ms": 0.0,
        "detection_count": 0,
        "block_count": 0,
        "rule_count": 0,
        "rule_rejection_count": 0,
        "api_health": True,
        "capture_health": True,
        "firewall_health": True,
        "adaptive_rule_creation_rate_per_window": 0,
        "adaptive_rule_budget_fraction": 0.0,
    }
    v1 = snapshot_to_metrics(NetdataMetricsSnapshot(**base))
    v2 = snapshot_to_metrics(NetdataMetricsSnapshot(**base, v2=V2Gauges(guard_hits_raw=5, offenders=2)))

    assert not [name for name in v1 if ".v2." in name]
    assert v2["pirewall.v2.guard_hits_raw"] == 5.0 and v2["pirewall.v2.offenders"] == 2.0


@pytest.mark.parametrize("clock", [lambda: None])
def test_portal_failures_cross_threads_through_the_inbox(clock: Callable[[], None]) -> None:
    del clock
    harness = _Harness(EnforcementMode.ACTIVE)
    for i in range(40):
        harness.pipeline.submit_portal_failure(
            "alice", IPv4Address("192.168.1.66"), MAC, harness.now + timedelta(seconds=i)
        )
    harness.now += timedelta(seconds=41)
    harness.pipeline.drain_inbox(harness.now)
    harness.pipeline.evaluate(harness.now)

    assert harness.elements(nft_names.SET_RATELIMIT_MAC) == [MAC]  # one account, one device: D1 standard


# --------------------------------------------------------------- ML ceiling


class _FakeV2Models:
    any_v2_loaded = True
    v2_lightgbm = object()
    v2_isolation_forest = object()
    v2_family = None


class _FakeV2Coordinator:
    """D2 + D3 evidence on every flow, with no D1 and no real model."""

    models = _FakeV2Models()

    @staticmethod
    def in_model_domain(flow: Any) -> bool:
        del flow
        return True

    @staticmethod
    def classify_known_v2(features: FeatureVector, now: datetime) -> KnownEvidence:
        return KnownEvidence(
            flow_id=features.flow_id,
            predicted_class="attack",
            confidence=0.99,
            class_probabilities={"benign": 0.01, "attack": 0.99},
            operating_threshold=0.9,
            model_version="3.0.0",
            feature_schema_version="3.0.0",
            generated_at=now,
        )

    @staticmethod
    def detect_anomaly_v2(features: FeatureVector, now: datetime) -> AnomalyEvidence:
        return AnomalyEvidence(
            flow_id=features.flow_id,
            anomaly_score=-0.9,
            threshold=-0.2,
            is_anomaly=True,
            model_version="3.0.0",
            feature_schema_version="3.0.0",
            generated_at=now,
        )


@pytest.mark.parametrize(
    "mode", [EnforcementMode.SHADOW, EnforcementMode.ASSISTED, EnforcementMode.ACTIVE]
)
def test_d2_and_d3_evidence_alone_never_exceed_monitor(mode: EnforcementMode) -> None:
    harness = _Harness(mode, coordinator=_FakeV2Coordinator())
    # UDP is never a connection start, so the bundle holds only ML evidence.
    flow = make_flow(
        flow_id="ml-only",
        source_ip=str(IP),
        destination_ip="192.168.1.10",
        destination_port=53,
        protocol=Protocol.UDP,
    ).model_copy(update={"source_mac": MAC})

    harness.pipeline.observe_record(flow, harness.now)
    harness.pipeline.evaluate(harness.now)
    harness.pipeline.evaluate(harness.now + timedelta(seconds=5))

    decisions = [
        event for event in harness.events if event.event_type is SecurityEventType.POLICY_DECISION
    ]
    assert decisions, "ML-only evidence should still be reported"
    assert {event.decision for event in decisions} == {FirewallAction.MONITOR}
    for name in nft_names.ADAPTIVE_ENFORCEMENT_SETS:
        assert harness.elements(name) == [], f"{name} must stay empty for ML-only evidence"
