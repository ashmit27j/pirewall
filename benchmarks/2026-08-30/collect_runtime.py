"""Observe the *running* pirewall-core daemon on real hardware. Read-only.

Samples pirewall-core's own live state over its RPC socket (ADDENDUM.md A4:
read operations only -- `get_status`, `get_capture_stats`, `list_flows`,
`list_detections`) plus `/proc` for process CPU/RSS and `/proc/net/dev` for
kernel-side interface counters, and writes one CSV row per sample.

Nothing here writes to pirewall: no rule is created, approved, disabled or
removed, the enforcement mode is never touched, and pirewall's runtime code
is not modified or imported into the daemon. The only cost imposed on the
observed process is answering read RPCs.

Run as root (the RPC socket is `pirewall-core:pirewall-ipc` 0660):

    sudo .venv/bin/python3.12 benchmarks/<date>/collect_runtime.py \
        --duration 1800 --label idle --out benchmarks/<date>/data/runtime_idle.csv
"""

import argparse
import csv
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pirewall.ipc.client import UnixSocketRpcClient

CLK_TCK = os.sysconf("SC_CLK_TCK")

# list_flows()/list_detections() serialize up to `api.history_size` models per
# call, so they are polled on a coarser cadence than the cheap counters to keep
# the observer's own load on the observed process small.
HEAVY_EVERY = 3


def main_pid(unit: str) -> int:
    out = subprocess.run(
        ["systemctl", "show", "-p", "MainPID", "--value", unit],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    return int(out or 0)


def proc_cpu_ticks(pid: int) -> float | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    except (OSError, IndexError):
        return None
    # after the ")" split, field[0] is `state`; utime/stime are fields 14/15
    # of the original line -> indices 11/12 here.
    return (float(fields[11]) + float(fields[12])) / CLK_TCK


def proc_rss_kb(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        pass
    return 0


def host_cpu_times() -> tuple[float, float] | None:
    try:
        fields = Path("/proc/stat").read_text().split("\n", 1)[0].split()
    except OSError:
        return None
    values = [float(v) for v in fields[1:]]
    idle = values[3] + values[4]
    total = sum(values)
    return total - idle, total


def host_mem() -> tuple[float, float]:
    values: dict[str, float] = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts:
            values[key] = float(parts[0])
    total = values.get("MemTotal", 0.0)
    available = values.get("MemAvailable", 0.0)
    used_pct = (total - available) / total * 100.0 if total else 0.0
    return used_pct, available / 1024.0


def netdev(interface: str) -> dict[str, int]:
    for line in Path("/proc/net/dev").read_text().splitlines():
        name, _, rest = line.partition(":")
        if name.strip() != interface:
            continue
        f = [int(v) for v in rest.split()]
        return {
            "rx_bytes": f[0], "rx_packets": f[1], "rx_errs": f[2], "rx_drop": f[3],
            "tx_bytes": f[8], "tx_packets": f[9], "tx_errs": f[10], "tx_drop": f[11],
        }
    return {}


FIELDS = [
    "timestamp", "elapsed_s", "label", "phase_note",
    "packets_seen", "packet_rate_pps", "packets_dropped", "drop_delta",
    "drop_rate_pct_cumulative", "packets_malformed", "malformed_delta",
    "state_flow_records", "flow_completion_rate_per_s", "detection_rate_per_s",
    "active_rules", "pending_approvals",
    "core_cpu_pct", "core_rss_mb", "api_cpu_pct", "api_rss_mb",
    "host_cpu_pct", "host_mem_used_pct", "host_mem_available_mb",
    "wlan0_rx_packets_delta", "wlan0_tx_packets_delta", "wlan0_rx_bytes_delta",
    "wlan0_tx_bytes_delta", "wlan0_rx_drop_delta", "wlan0_kbps",
    "rpc_poll_ms",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--label", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--socket", default="/run/pirewall/core.sock")
    parser.add_argument("--interface", default="wlan0")
    parser.add_argument("--phase-file", default="", help="optional file whose contents label each sample")
    args = parser.parse_args()

    client = UnixSocketRpcClient(args.socket, timeout_seconds=10.0)
    core_pid = main_pid("pirewall-core.service")
    api_pid = main_pid("pirewall-api.service")
    print(f"observing pirewall-core pid={core_pid} pirewall-api pid={api_pid}", flush=True)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    handle = out.open("w", newline="")
    writer = csv.DictWriter(handle, fieldnames=FIELDS)
    writer.writeheader()

    seen_flow_ids: set[str] = set()
    seen_detection_ids: set[str] = set()
    prev: dict[str, float] = {}
    prev_core = proc_cpu_ticks(core_pid)
    prev_api = proc_cpu_ticks(api_pid)
    prev_host = host_cpu_times()
    prev_net = netdev(args.interface)
    prev_t = time.monotonic()
    started = prev_t
    sample = 0

    while time.monotonic() - started < args.duration:
        time.sleep(max(0.0, args.interval - (time.monotonic() - prev_t)))
        now_m = time.monotonic()
        dt = now_m - prev_t
        prev_t = now_m
        sample += 1

        rpc_start = time.perf_counter()
        status = client.get_status()
        capture = client.get_capture_stats()
        heavy = sample % HEAVY_EVERY == 0
        new_flows = 0
        new_detections = 0
        if heavy:
            for flow in client.list_flows():
                if flow.flow_id not in seen_flow_ids:
                    seen_flow_ids.add(flow.flow_id)
                    new_flows += 1
            for record in client.list_detections():
                if record.flow_id not in seen_detection_ids:
                    seen_detection_ids.add(record.flow_id)
                    new_detections += 1
        rpc_ms = (time.perf_counter() - rpc_start) * 1000.0

        packets_seen = capture.packets_seen if capture else 0
        dropped = capture.packets_dropped if capture else 0
        malformed = capture.packets_malformed if capture else 0

        packet_rate = (packets_seen - prev.get("packets_seen", packets_seen)) / dt if dt > 0 else 0.0
        drop_delta = dropped - prev.get("dropped", dropped)
        malformed_delta = malformed - prev.get("malformed", malformed)

        # Flow *completions* are countable exactly: each finalized flow is
        # recorded once in `CoreStateStore.flows` with a fresh uuid4 flow_id,
        # so counting previously-unseen ids across polls counts completions.
        # (Undercounts only if more than `api.history_size` flows complete
        # between two heavy polls; `flow_records_saturated` flags that.)
        #
        # Flow *creations* are NOT derivable from RPC: `tracked_flow_count`
        # is `len(CoreStateStore.flows)` -- the completed-flow ring buffer --
        # not the live flow table. Live table size comes from stage_latency.py
        # instead, which runs its own FlowAggregator over the same packets.
        heavy_dt = dt * HEAVY_EVERY
        completion_rate = new_flows / heavy_dt if heavy else ""
        tracked = status.tracked_flow_count
        detection_rate = new_detections / heavy_dt if heavy else ""

        core_ticks = proc_cpu_ticks(core_pid)
        api_ticks = proc_cpu_ticks(api_pid)
        core_cpu = (core_ticks - prev_core) / dt * 100.0 if core_ticks and prev_core else 0.0
        api_cpu = (api_ticks - prev_api) / dt * 100.0 if api_ticks and prev_api else 0.0
        prev_core, prev_api = core_ticks, api_ticks

        host_now = host_cpu_times()
        host_cpu = 0.0
        if host_now and prev_host and host_now[1] > prev_host[1]:
            host_cpu = (host_now[0] - prev_host[0]) / (host_now[1] - prev_host[1]) * 100.0
        prev_host = host_now

        mem_pct, mem_avail_mb = host_mem()
        net = netdev(args.interface)
        d = {k: net.get(k, 0) - prev_net.get(k, 0) for k in net}
        prev_net = net
        kbps = (d.get("rx_bytes", 0) + d.get("tx_bytes", 0)) * 8 / dt / 1000.0 if dt > 0 else 0.0

        phase_note = ""
        if args.phase_file and Path(args.phase_file).exists():
            phase_note = Path(args.phase_file).read_text().strip()

        writer.writerow({
            "timestamp": datetime.now(UTC).isoformat(),
            "elapsed_s": round(now_m - started, 2),
            "label": args.label,
            "phase_note": phase_note,
            "packets_seen": packets_seen,
            "packet_rate_pps": round(packet_rate, 3),
            "packets_dropped": dropped,
            "drop_delta": drop_delta,
            "drop_rate_pct_cumulative": round(dropped / packets_seen * 100.0, 6) if packets_seen else 0.0,
            "packets_malformed": malformed,
            "malformed_delta": malformed_delta,
            "state_flow_records": tracked,
            "flow_completion_rate_per_s": round(completion_rate, 4) if heavy else "",
            "detection_rate_per_s": round(detection_rate, 4) if heavy else "",
            "active_rules": status.active_rule_count,
            "pending_approvals": status.pending_approval_count,
            "core_cpu_pct": round(core_cpu, 2),
            "core_rss_mb": round(proc_rss_kb(core_pid) / 1024.0, 2),
            "api_cpu_pct": round(api_cpu, 2),
            "api_rss_mb": round(proc_rss_kb(api_pid) / 1024.0, 2),
            "host_cpu_pct": round(host_cpu, 2),
            "host_mem_used_pct": round(mem_pct, 2),
            "host_mem_available_mb": round(mem_avail_mb, 1),
            "wlan0_rx_packets_delta": d.get("rx_packets", 0),
            "wlan0_tx_packets_delta": d.get("tx_packets", 0),
            "wlan0_rx_bytes_delta": d.get("rx_bytes", 0),
            "wlan0_tx_bytes_delta": d.get("tx_bytes", 0),
            "wlan0_rx_drop_delta": d.get("rx_drop", 0),
            "wlan0_kbps": round(kbps, 2),
            "rpc_poll_ms": round(rpc_ms, 2),
        })
        handle.flush()
        prev.update({
            "packets_seen": packets_seen, "dropped": dropped,
            "malformed": malformed,
        })

    handle.close()
    print(f"wrote {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
