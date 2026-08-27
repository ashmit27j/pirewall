"""`pirewall.integration.netdata` payload shaping (spec §33, ADDENDUM.md A3, Phase 8)."""

import pytest

from pirewall.core.exceptions import IntegrationError
from pirewall.core.models.metrics import NetdataMetricsSnapshot
from pirewall.integration.fake import FakeNetdataTransport
from pirewall.integration.netdata import NetdataExporter, snapshot_to_metrics

_SNAPSHOT = NetdataMetricsSnapshot(
    cpu_percent=12.5,
    memory_percent=40.0,
    packet_rate_per_second=1500.0,
    packet_drops=3,
    active_flows=250,
    flow_creation_rate_per_second=10.0,
    flow_expiration_rate_per_second=9.0,
    inference_count=1000,
    inference_latency_ms=2.5,
    detection_count=5,
    block_count=2,
    rule_count=8,
    rule_rejection_count=1,
    api_health=True,
    capture_health=True,
    firewall_health=False,
    adaptive_rule_creation_rate_per_window=4,
    adaptive_rule_budget_fraction=0.2,
)

# Every spec §33 metric, plus the ADDENDUM.md A3 addition.
_EXPECTED_SPEC_METRICS = {
    "cpu_percent",
    "memory_percent",
    "packet_rate_per_second",
    "packet_drops",
    "active_flows",
    "flow_creation_rate_per_second",
    "flow_expiration_rate_per_second",
    "inference_count",
    "inference_latency_ms",
    "detection_count",
    "block_count",
    "rule_count",
    "rule_rejection_count",
    "api_health",
    "capture_health",
    "firewall_health",
}
_EXPECTED_A3_METRICS = {"adaptive_rule_creation_rate_per_window", "adaptive_rule_budget_fraction"}


def test_snapshot_to_metrics_covers_every_spec_and_addendum_metric() -> None:
    metrics = snapshot_to_metrics(_SNAPSHOT)
    names = {name.removeprefix("pirewall.") for name in metrics}

    assert names >= _EXPECTED_SPEC_METRICS
    assert names >= _EXPECTED_A3_METRICS
    assert all(name.startswith("pirewall.") for name in metrics)


def test_snapshot_to_metrics_encodes_booleans_as_zero_one() -> None:
    metrics = snapshot_to_metrics(_SNAPSHOT)

    assert metrics["pirewall.api_health"] == 1.0
    assert metrics["pirewall.capture_health"] == 1.0
    assert metrics["pirewall.firewall_health"] == 0.0


def test_exporter_sends_every_metric_when_enabled() -> None:
    transport = FakeNetdataTransport()
    exporter = NetdataExporter(transport, enabled=True)

    exporter.export(_SNAPSHOT)

    sent_names = {name for name, _ in transport.sent_metrics}
    assert sent_names == set(snapshot_to_metrics(_SNAPSHOT))


def test_exporter_is_noop_when_disabled() -> None:
    transport = FakeNetdataTransport()
    exporter = NetdataExporter(transport, enabled=False)

    exporter.export(_SNAPSHOT)

    assert transport.sent_metrics == []


def test_exporter_propagates_transport_failure() -> None:
    transport = FakeNetdataTransport(fail=True)
    exporter = NetdataExporter(transport, enabled=True)

    with pytest.raises(IntegrationError):
        exporter.export(_SNAPSHOT)
