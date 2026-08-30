"""Per-stage pipeline latency on real Raspberry Pi 4 hardware, over real captured packets.

The running pirewall-core daemon exports only an *aggregate*
`inference_latency_ms`; it has no per-stage timing, and this benchmark is
forbidden from adding any (observation only). So this is an independent
observer process: it opens its **own** `AF_PACKET` socket on the same
interface -- kernel packet sockets each get their own copy, so the daemon is
unaffected apart from the CPU this process uses -- and runs the very same
canonical modules the daemon runs, in the same order as
`pirewall.runtime.pipeline.FlowPipeline`, timing each stage:

    parse -> flow aggregation -> feature extraction
          -> LightGBM (known attack) -> Isolation Forest (anomaly)
          -> behavior analysis -> threat assessment -> decision
          -> candidate-rule generation

It **stops at candidate generation**: `FirewallManager` is never imported,
so nothing here can validate, deploy, or even propose a rule to the
backend. `generate_candidate_rule` is a pure function that builds an
in-memory `CandidateRule`.

"End-to-end packet-to-decision" here means the sum of the CPU stages a
packet must pass through to yield a decision, measured on the packet that
actually completes the flow. It deliberately excludes the flow's own
lifetime (a flow is only finalized after `flow.inactive_timeout_seconds` of
silence or a TCP close), which is a configured dwell time, not latency.

Run as root (AF_PACKET needs CAP_NET_RAW):

    sudo .venv/bin/python3.12 benchmarks/<date>/stage_latency.py \
        --duration 1800 --label idle --outdir benchmarks/<date>/data
"""

import argparse
import csv
import json
import socket
import statistics
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pirewall.capture.af_packet import AFPacketCapture
from pirewall.capture.parser import parse_packet
from pirewall.config.loader import load_config
from pirewall.core.enums import AddressFamily
from pirewall.core.exceptions import PacketParseError
from pirewall.detection import anomaly, known_attack
from pirewall.detection.behavior import BehaviorAnalyzer
from pirewall.detection.coordinator import load_models
from pirewall.engine.decision import decide
from pirewall.engine.threat import assess_threat
from pirewall.features.extractor import extract_features
from pirewall.firewall.generator import generate_candidate_rule
from pirewall.flow.aggregator import FlowAggregator

FLOW_STAGES = (
    "feature_extraction", "lightgbm_inference", "isolation_forest_inference",
    "behavior_analysis", "threat_assessment", "decision", "candidate_generation",
)


def percentiles(values: list[float]) -> dict[str, float]:
    if not values:
        return {}
    ordered = sorted(values)

    def pct(p: float) -> float:
        if len(ordered) == 1:
            return ordered[0]
        idx = min(len(ordered) - 1, max(0, round(p / 100.0 * (len(ordered) - 1))))
        return ordered[idx]

    return {
        "count": len(ordered),
        "mean_ms": statistics.fmean(ordered),
        "min_ms": ordered[0],
        "p50_ms": pct(50), "p90_ms": pct(90), "p95_ms": pct(95), "p99_ms": pct(99),
        "max_ms": ordered[-1],
        "stdev_ms": statistics.stdev(ordered) if len(ordered) > 1 else 0.0,
        "ops_per_second": 1000.0 / statistics.fmean(ordered) if statistics.fmean(ordered) > 0 else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--outdir", required=True)
    parser.add_argument("--config", default="config/local_config.toml")
    args = parser.parse_args()

    config = load_config(Path(args.config))
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    models = load_models(config.ml)
    print(f"models: lightgbm={models.lightgbm is not None} "
          f"isolation_forest={models.isolation_forest is not None} errors={models.load_errors}",
          flush=True)

    aggregator = FlowAggregator(config.flow)
    behavior = BehaviorAnalyzer(config.detection)
    capture = AFPacketCapture(
        interface=config.capture.interface,
        snap_len=config.capture.snap_len,
        promiscuous=config.capture.promiscuous,
        buffer_size_bytes=config.capture.buffer_size_bytes,
    )
    capture.start()
    print(f"capturing on {config.capture.interface} for {args.duration}s (label={args.label})", flush=True)

    # `AFPacketCapture.read_packets()` blocks in `recv()`, and closing the
    # socket from another thread does not reliably wake a blocked `recv()`.
    # On an idle interface that would hang forever, so the deadline is
    # enforced by the loop itself plus this thread, which unblocks the final
    # `recv()` with broadcast datagrams once the window has closed. Only
    # public API is used; the loop breaks on the deadline before processing,
    # so these wake-up packets are never counted as measured traffic.
    finished = threading.Event()

    def wake_after_deadline() -> None:
        if finished.wait(args.duration):
            return
        waker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        waker.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        waker.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                         config.capture.interface.encode())
        while not finished.wait(0.2):
            try:
                waker.sendto(b"wakeup", ("255.255.255.255", 9))
            except OSError:
                break
        waker.close()

    waker_thread = threading.Thread(target=wake_after_deadline, daemon=True)
    waker_thread.start()

    # pirewall-core does not expose its live flow-table size over RPC:
    # `StatusResult.tracked_flow_count` is `len(CoreStateStore.flows)`, the
    # bounded ring buffer of *recently completed* flows (capped at
    # `api.history_size`), not the aggregator's table. This observer runs the
    # same `FlowAggregator` over the same packets with the same config, so
    # sampling its own table is the closest honest measurement available
    # without instrumenting the daemon (which this benchmark may not do).
    flow_table_rows: list[tuple[float, int, int]] = []

    def sample_flow_table() -> None:
        while not finished.wait(5.0):
            try:
                flow_table_rows.append(
                    (round(time.monotonic() - started, 2), len(aggregator), len(flow_rows))
                )
            except RuntimeError:
                continue

    table_thread = threading.Thread(target=sample_flow_table, daemon=True)
    table_thread.start()

    packet_rows: list[tuple[float, float, float]] = []
    flow_rows: list[dict[str, float | str]] = []
    parse_us: list[float] = []
    aggregate_us: list[float] = []
    sweep_ms: list[float] = []
    stage_samples: dict[str, list[float]] = {name: [] for name in FLOW_STAGES}
    end_to_end: list[float] = []
    malformed = 0
    packets_read = 0
    non_ipv4_skipped = 0
    started = time.monotonic()
    started_wall = datetime.now(UTC)
    last_sweep = started

    def run_flow_stages(flow, packet_ms: float, now: datetime) -> None:
        timings: dict[str, float] = {}

        t = time.perf_counter()
        features = extract_features(flow)
        timings["feature_extraction"] = (time.perf_counter() - t) * 1000.0

        known = None
        if models.lightgbm is not None:
            t = time.perf_counter()
            known = known_attack.classify(models.lightgbm, features, now)
            timings["lightgbm_inference"] = (time.perf_counter() - t) * 1000.0

        anomaly_evidence = None
        if models.isolation_forest is not None:
            t = time.perf_counter()
            anomaly_evidence = anomaly.detect(
                models.isolation_forest, features,
                config.detection.anomaly_score_threshold, now,
            )
            timings["isolation_forest_inference"] = (time.perf_counter() - t) * 1000.0

        t = time.perf_counter()
        behavior.observe_flow(flow)
        assessment_behavior = behavior.assess(flow.source_ip)
        timings["behavior_analysis"] = (time.perf_counter() - t) * 1000.0

        t = time.perf_counter()
        assessment = assess_threat(
            config.threat,
            flow_id=flow.flow_id,
            source_ip=flow.source_ip,
            destination_ip=flow.destination_ip,
            known_evidence=known,
            anomaly_evidence=anomaly_evidence,
            behavior_assessment=assessment_behavior,
            assessed_at=now,
        )
        timings["threat_assessment"] = (time.perf_counter() - t) * 1000.0

        t = time.perf_counter()
        decision = decide(assessment, now)
        timings["decision"] = (time.perf_counter() - t) * 1000.0

        t = time.perf_counter()
        candidate = generate_candidate_rule(
            decision, flow, now, config.firewall.default_rule_ttl_seconds
        )
        timings["candidate_generation"] = (time.perf_counter() - t) * 1000.0

        total = packet_ms + sum(timings.values())
        for name, value in timings.items():
            stage_samples[name].append(value)
        end_to_end.append(total)
        flow_rows.append({
            "elapsed_s": round(time.monotonic() - started, 3),
            "flow_id": flow.flow_id,
            "packet_count": flow.packet_count,
            "byte_count": flow.byte_count,
            "protocol": str(flow.protocol),
            "destination_port": flow.destination_port,
            "packet_path_ms": round(packet_ms, 4),
            **{name: round(timings.get(name, float("nan")), 4) for name in FLOW_STAGES},
            "end_to_end_ms": round(total, 4),
            "threat_score": round(assessment.threat_score, 3),
            "threat_level": str(assessment.threat_level),
            "action": str(decision.action),
            "generates_candidate": candidate is not None,
        })

    try:
        for captured in capture.read_packets():
            if time.monotonic() - started >= args.duration:
                break
            packets_read += 1
            t = time.perf_counter()
            try:
                packet = parse_packet(captured.raw, captured.captured_at)
            except PacketParseError:
                malformed += 1
                continue
            finally:
                parse_ms = (time.perf_counter() - t) * 1000.0
            parse_us.append(parse_ms * 1000.0)

            t = time.perf_counter()
            completed = aggregator.process_packet(packet)
            aggregate_ms = (time.perf_counter() - t) * 1000.0
            aggregate_us.append(aggregate_ms * 1000.0)
            packet_rows.append((round(time.monotonic() - started, 3),
                                round(parse_ms * 1000.0, 2), round(aggregate_ms * 1000.0, 2)))
            if packet.address_family is not AddressFamily.IPV4:
                non_ipv4_skipped += 1

            now = datetime.now(UTC)
            for flow in completed:
                run_flow_stages(flow, parse_ms + aggregate_ms, now)

            if time.monotonic() - last_sweep >= config.flow.cleanup_interval_seconds:
                last_sweep = time.monotonic()
                t = time.perf_counter()
                expired = aggregator.sweep_timeouts(now)
                sweep_ms.append((time.perf_counter() - t) * 1000.0)
                for flow in expired:
                    run_flow_stages(flow, 0.0, now)
    except KeyboardInterrupt:
        pass
    finally:
        finished.set()
        capture.stop()

    now = datetime.now(UTC)
    for flow in aggregator.flush():
        run_flow_stages(flow, 0.0, now)

    stats = capture.statistics()
    wall = time.monotonic() - started
    summary = {
        "label": args.label,
        "started_at": started_wall.isoformat(),
        "generated_at": datetime.now(UTC).isoformat(),
        "duration_seconds": round(wall, 2),
        "interface": stats.interface,
        "observer_packets_read": packets_read,
        "observer_packets_seen": stats.packets_seen,
        "observer_packets_dropped_kernel": stats.packets_dropped,
        "observer_packets_malformed": malformed,
        "observer_packet_rate_pps": round(packets_read / wall, 3) if wall else 0.0,
        "non_ipv4_packets": non_ipv4_skipped,
        "flows_processed": len(flow_rows),
        "flow_table_size_max": max((r[1] for r in flow_table_rows), default=0),
        "flow_table_size_final": flow_table_rows[-1][1] if flow_table_rows else 0,
        "flow_completion_rate_per_s": round(len(flow_rows) / wall, 4) if wall else 0.0,
        "models": {
            "lightgbm_loaded": models.lightgbm is not None,
            "isolation_forest_loaded": models.isolation_forest is not None,
            "lightgbm_version": models.lightgbm.metadata.model_version if models.lightgbm else None,
            "isolation_forest_version": (
                models.isolation_forest.metadata.model_version if models.isolation_forest else None
            ),
        },
        "stages": {
            "packet_parse": percentiles([v / 1000.0 for v in parse_us]),
            "flow_aggregation": percentiles([v / 1000.0 for v in aggregate_us]),
            "flow_table_sweep": percentiles(sweep_ms),
            **{name: percentiles(values) for name, values in stage_samples.items()},
            "end_to_end_packet_to_decision": percentiles(end_to_end),
        },
    }

    (outdir / f"stage_summary_{args.label}.json").write_text(json.dumps(summary, indent=2))

    with (outdir / f"packet_stages_{args.label}.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["elapsed_s", "parse_us", "flow_aggregation_us"])
        writer.writerows(packet_rows)

    with (outdir / f"flowtable_{args.label}.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["elapsed_s", "flow_table_size", "flows_completed_cumulative"])
        writer.writerows(flow_table_rows)

    if flow_rows:
        with (outdir / f"flow_stages_{args.label}.csv").open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(flow_rows[0].keys()))
            writer.writeheader()
            writer.writerows(flow_rows)

    print(json.dumps(summary["stages"], indent=2), flush=True)
    print(f"packets={packets_read} flows={len(flow_rows)} kernel_drops={stats.packets_dropped}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
