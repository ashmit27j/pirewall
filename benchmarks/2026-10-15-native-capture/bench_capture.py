"""Capture-path throughput: Python (`AFPacketCapture` + parser + `FlowAggregator`) vs native.

Runs one capture path for a fixed window on a real interface while something
else generates traffic, and reports how many frames reached the flow layer
versus how many the kernel dropped because the capture fell behind.

    uv run --extra native python benchmarks/2026-10-15-native-capture/bench_capture.py \\
        --interface veth0 --path native --seconds 10 [--contend]

`--contend` adds a CPU-bound pure-Python thread for the duration, standing in
for pirewall-core's detection/inference threads competing for the GIL — the
condition the real daemon is always in. Only reads: nothing here installs a
rule or touches network configuration. Needs CAP_NET_RAW.
"""

import argparse
import json
import threading
import time
from collections import deque
from datetime import UTC, datetime

from pirewall.capture.af_packet import AFPacketCapture
from pirewall.capture.native import NativePacketCapture
from pirewall.capture.pipeline import capture_packets
from pirewall.config.models import FlowConfig
from pirewall.flow.aggregator import FlowAggregator, NewFlowSignal
from pirewall.flow.native import NativeFlowAggregator


def _contender(stop: threading.Event) -> None:
    value = 0
    while not stop.is_set():
        for i in range(10_000):  # pure-Python work: holds the GIL like detection does
            value ^= i * i


def run_python(interface: str, seconds: float) -> dict[str, float]:
    capture = AFPacketCapture(interface, snap_len=65535, promiscuous=True, buffer_size_bytes=2 * 1024 * 1024)
    signals: deque[NewFlowSignal] = deque(maxlen=100_000)
    aggregator = FlowAggregator(FlowConfig(), on_new_flow=signals.append)
    capture.start()
    baseline = capture.statistics()
    completed = 0
    deadline = time.monotonic() + seconds
    timer = threading.Timer(seconds + 0.5, capture.stop)  # unblock recv() if traffic stops
    timer.start()
    for packet in capture_packets(capture):
        completed += len(aggregator.process_packet(packet))
        if time.monotonic() >= deadline:
            break
    stats = capture.statistics()
    capture.stop()
    timer.cancel()
    return {
        "frames_processed": stats.packets_seen - baseline.packets_seen,
        "kernel_drops": stats.packets_dropped - baseline.packets_dropped,
        "open_flows": len(aggregator),
        "new_flow_signals": len(signals),
        "completed_flows": completed,
    }


def run_native(interface: str, seconds: float) -> dict[str, float]:
    # The daemon's default per-drain caps (capture.native_max_*_per_drain).
    aggregator = NativeFlowAggregator(FlowConfig(), max_pending_completed=1_000, max_pending_new_flows=5_000)
    capture = NativePacketCapture(
        interface, aggregator.engine, promiscuous=True,
        block_size_bytes=1024 * 1024, block_count=16, block_timeout_ms=50,
    )
    capture.start()
    baseline = capture.statistics()
    signals = completed = 0
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        capture.poll(100)
        batch = aggregator.drain()  # the same per-batch Python work the daemon does
        signals += len(batch.new_flows)
        completed += len(batch.completed)
    stats = capture.statistics()
    capture.stop()
    shed_flows, shed_signals = aggregator.shed()
    return {
        "frames_processed": stats.packets_seen - baseline.packets_seen,
        "kernel_drops": stats.packets_dropped - baseline.packets_dropped,
        "open_flows": len(aggregator),
        "new_flow_signals": signals,
        "completed_flows": completed,
        "flows_shed": shed_flows,
        "signals_shed": shed_signals,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--path", choices=("python", "native"), required=True)
    parser.add_argument("--seconds", type=float, default=10.0)
    parser.add_argument("--contend", action="store_true")
    args = parser.parse_args()

    stop = threading.Event()
    if args.contend:
        threading.Thread(target=_contender, args=(stop,), daemon=True).start()
    started = datetime.now(UTC)
    result = (run_python if args.path == "python" else run_native)(args.interface, args.seconds)
    stop.set()
    offered = result["frames_processed"] + result["kernel_drops"]
    result.update(
        path=args.path,
        contend=args.contend,
        seconds=args.seconds,
        started_at=started.isoformat(),
        processed_per_second=round(result["frames_processed"] / args.seconds),
        drop_fraction=round(result["kernel_drops"] / offered, 4) if offered else 0.0,
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()
