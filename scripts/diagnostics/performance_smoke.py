"""Performance smoke pass (spec §40) against Fake implementations.

Measures packet throughput, flow latency, feature-extraction latency,
inference latency, threat-assessment latency, and rule-deployment latency,
all driven through `FakePacketCapture`/`FakeFirewallBackend` at a
synthetically high rate.

**These numbers describe this dev machine and the Fake backends only.**
Per CLAUDE.md's labeling honesty rules and spec §46 ("do not fabricate
metrics"): nothing here has been run on real Raspberry Pi hardware, a real
NIC, or a real `nft` binary — see `docs/PROGRESS.md` Phase 9 for the
Environment-dependent label this earns. Real Pi 4 numbers require running
this same script (or the equivalent real workload) on the target hardware.

Run with:

    uv run python -m scripts.diagnostics.performance_smoke
"""

import sys
import tempfile
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tests.helpers.config import make_config
from tests.helpers.flows import make_flow
from tests.helpers.packets import eth, ipv4_header, tcp_header

from pirewall.capture.fake import FakePacketCapture
from pirewall.capture.pipeline import capture_packets
from pirewall.core.enums import EnforcementMode, FirewallAction, RuleStatus, ThreatLevel
from pirewall.core.models.evidence import AnomalyEvidence, KnownEvidence
from pirewall.core.models.feature_vector import FeatureVector
from pirewall.core.models.flow import Flow
from pirewall.core.models.packet import PacketMetadata
from pirewall.core.models.threat import ThreatAssessment
from pirewall.engine.decision import decide
from pirewall.engine.threat import assess_threat
from pirewall.features.extractor import extract_features
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.generator import generate_candidate_rule
from pirewall.firewall.manager import FirewallManager
from pirewall.flow.aggregator import FlowAggregator
from pirewall.ml.inference.isolation_forest_predictor import anomaly_score
from pirewall.ml.inference.lightgbm_predictor import predict_class_probabilities
from pirewall.ml.inference.loader import (
    LoadedIsolationForestModel,
    LoadedLightGBMModel,
    load_isolation_forest_model,
    load_lightgbm_model,
)
from pirewall.ml.preprocessing.common import LabeledFlow
from pirewall.ml.training.isolation_forest_trainer import (
    save_isolation_forest_artifact,
    train_isolation_forest,
)
from pirewall.ml.training.lightgbm_trainer import save_lightgbm_artifact, train_lightgbm

T0 = datetime(2026, 1, 1, tzinfo=UTC)
_FLOW_COUNT = 2000


@dataclass(frozen=True, slots=True)
class LatencyStats:
    """Wall-clock timing for one stage, over `count` operations."""

    label: str
    count: int
    total_seconds: float

    @property
    def mean_ms(self) -> float:
        return (self.total_seconds / self.count) * 1000.0 if self.count else 0.0

    @property
    def ops_per_second(self) -> float:
        return self.count / self.total_seconds if self.total_seconds > 0 else 0.0


def _time_stage[T](label: str, items: Iterable[T], fn: Callable[[T], object]) -> LatencyStats:
    materialized = list(items)
    start = time.perf_counter()
    for item in materialized:
        fn(item)
    elapsed = time.perf_counter() - start
    return LatencyStats(label=label, count=len(materialized), total_seconds=elapsed)


def _destination_for(index: int) -> str:
    """A distinct /32-worth destination per flow, so each generates an independently deployable rule."""
    return f"10.{1 + (index // 65025) % 254}.{1 + (index // 255) % 254}.{1 + index % 254}"


def _build_raw_packets(flow_count: int) -> list[bytes]:
    """`flow_count` independent two-packet (SYN, RST) TCP sessions, each to a distinct destination."""
    raw: list[bytes] = []
    for i in range(flow_count):
        client_port = 40000 + (i % 20000)
        dst = _destination_for(i)
        syn = tcp_header(client_port, 443, flags=0x02)
        ip_syn = ipv4_header(protocol=6, total_length=20 + len(syn), src="10.0.0.5", dst=dst)
        raw.append(eth(0x0800) + ip_syn + syn)

        rst = tcp_header(client_port, 443, flags=0x04)  # RST alone completes the flow (either direction)
        ip_rst = ipv4_header(protocol=6, total_length=20 + len(rst), src="10.0.0.5", dst=dst)
        raw.append(eth(0x0800) + ip_rst + rst)
    return raw


def _synthetic_labeled_flows() -> list[LabeledFlow]:
    benign = [LabeledFlow(flow=make_flow(flow_id=f"benign-{i}"), label="BENIGN") for i in range(10)]
    attack = [
        LabeledFlow(
            flow=make_flow(
                flow_id=f"attack-{i}",
                packet_count=2000,
                byte_count=200_000,
                forward_packet_count=1900,
                backward_packet_count=100,
                forward_byte_count=190_000,
                backward_byte_count=10_000,
                duration_seconds=1.0,
            ),
            label="Attack",
        )
        for i in range(10)
    ]
    return benign + attack


def _train_tiny_models() -> tuple[LoadedLightGBMModel, LoadedIsolationForestModel]:
    """A placeholder-quality LightGBM + Isolation Forest model, trained on synthetic fixtures.

    Training itself is excluded from the timed stages below — only
    inference latency is measured, matching spec §40's list.
    """
    labeled = _synthetic_labeled_flows()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        lgb_result = train_lightgbm(
            labeled,
            training_dataset_name="perf-smoke-synthetic",
            model_version="0.0.0-perf-smoke",
            is_placeholder=True,
            notes="performance smoke pass only — not a real detector",
        )
        lgb_model = load_lightgbm_model(save_lightgbm_artifact(lgb_result, tmp_path))

        iso_result = train_isolation_forest(
            labeled,
            training_dataset_name="perf-smoke-synthetic",
            model_version="0.0.0-perf-smoke",
            is_placeholder=True,
            notes="performance smoke pass only — not a real detector",
        )
        iso_model = load_isolation_forest_model(save_isolation_forest_artifact(iso_result, tmp_path))

    return lgb_model, iso_model


def _capture_and_parse(flow_count: int) -> list[PacketMetadata]:
    raw_packets = _build_raw_packets(flow_count)
    capture = FakePacketCapture("perf-smoke0", raw_packets)
    capture.start()
    return list(capture_packets(capture))


def run(flow_count: int = _FLOW_COUNT) -> list[LatencyStats]:
    """Run the full smoke pass over `flow_count` synthetic flows.

    Defaults to `_FLOW_COUNT` (2000, "meaningfully high") for a real report;
    `tests/system/test_performance_smoke.py` calls this with a smaller
    count so the regression check stays fast without changing what's
    measured or how.
    """
    stats: list[LatencyStats] = []

    # 1. Packet throughput: FakePacketCapture -> real parsing (capture_packets).
    start = time.perf_counter()
    parsed = _capture_and_parse(flow_count)
    stats.append(LatencyStats("packet capture+parse", len(parsed), time.perf_counter() - start))

    # 2. Flow latency: FlowAggregator.process_packet per packet.
    aggregator = FlowAggregator(make_config().flow)
    flows: list[Flow] = []
    start = time.perf_counter()
    for packet in parsed:
        flows.extend(aggregator.process_packet(packet))
    stats.append(LatencyStats("flow aggregation", len(parsed), time.perf_counter() - start))
    assert len(flows) == flow_count, f"expected {flow_count} completed flows, got {len(flows)}"

    # 3. Feature-extraction latency.
    stats.append(_time_stage("feature extraction", flows, extract_features))
    feature_vectors = [extract_features(flow) for flow in flows]

    # 4. Inference latency (LightGBM known-attack + Isolation Forest anomaly).
    lgb_model, iso_model = _train_tiny_models()

    def _lgb_predict(fv: FeatureVector) -> object:
        return predict_class_probabilities(lgb_model, fv)

    def _iso_score(fv: FeatureVector) -> object:
        return anomaly_score(iso_model, fv)

    stats.append(_time_stage("lightgbm inference", feature_vectors, _lgb_predict))
    stats.append(_time_stage("isolation-forest inference", feature_vectors, _iso_score))

    # 5. Threat-assessment latency (behavior omitted here — timed separately in Phase 5's own tests).
    config = make_config(firewall={"enforcement_mode": "active"})
    known = KnownEvidence(
        flow_id="x",
        predicted_class="BENIGN",
        confidence=0.5,
        class_probabilities={"BENIGN": 0.5, "Attack": 0.5},
        model_version="0.0.0-perf-smoke",
        feature_schema_version=feature_vectors[0].schema_version,
        generated_at=T0,
    )
    anomaly = AnomalyEvidence(
        flow_id="x",
        anomaly_score=0.0,
        threshold=0.0,
        is_anomaly=False,
        model_version="0.0.0-perf-smoke",
        feature_schema_version=feature_vectors[0].schema_version,
        generated_at=T0,
    )

    def _assess(flow: Flow) -> ThreatAssessment:
        return assess_threat(
            config.threat,
            flow.flow_id,
            flow.source_ip,
            flow.destination_ip,
            known_evidence=known,
            anomaly_evidence=anomaly,
            behavior_assessment=None,
            assessed_at=flow.last_seen,
        )

    stats.append(_time_stage("threat assessment", flows, _assess))

    # 6. Rule-deployment latency: decide -> generate -> validate -> deploy, forced BLOCK for timing.
    backend = FakeFirewallBackend()
    manager = FirewallManager(
        make_config(
            firewall={
                "enforcement_mode": EnforcementMode.ACTIVE.value,
                "max_adaptive_rules_per_window": flow_count * 2,
                "max_active_rules": flow_count * 2,
            }
        ),
        backend,
    )
    high_threat_assessments = [
        _assess(flow).model_copy(update={"threat_score": 95.0, "threat_level": ThreatLevel.CRITICAL})
        for flow in flows
    ]
    flow_by_id = {flow.flow_id: flow for flow in flows}

    def _deploy(assessment: ThreatAssessment) -> None:
        decision = decide(assessment, T0)
        flow = flow_by_id[decision.flow_id] if decision.flow_id is not None else None
        assert flow is not None
        candidate = generate_candidate_rule(decision, flow, T0 + timedelta(seconds=1), 3600)
        if candidate is None:
            return
        manager.register_decision(decision)
        manager.submit_candidate(candidate, T0 + timedelta(seconds=1))

    stats.append(_time_stage("rule deployment", high_threat_assessments, _deploy))
    deployed = sum(1 for rule in manager.all_rules() if rule.status is RuleStatus.ACTIVE)

    print(f"(deployed {deployed}/{len(flows)} rules with action={FirewallAction.BLOCK.value})")
    return stats


def report(stats: list[LatencyStats]) -> None:
    print("=" * 72)
    print("pirewall performance smoke pass — Fake backends, this dev machine ONLY")
    print("NOT representative of real Raspberry Pi 4 hardware (spec §40, §46).")
    print("=" * 72)
    print(f"{'stage':<28}{'count':>8}{'mean (ms)':>14}{'ops/sec':>16}")
    for stat in stats:
        print(f"{stat.label:<28}{stat.count:>8}{stat.mean_ms:>14.4f}{stat.ops_per_second:>16.1f}")
    print("=" * 72)


def main() -> int:
    stats = run()
    report(stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
