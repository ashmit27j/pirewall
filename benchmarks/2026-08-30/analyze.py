"""Turn the collected benchmark CSV/JSON into PNG charts and printable tables.

Reads only what the collectors wrote; computes nothing it cannot show.
Run with the separate plotting virtualenv (matplotlib is a benchmark-only
tool and is deliberately NOT added to pirewall's dependency set, per
CLAUDE.md's dependency rule):

    <plotenv>/bin/python benchmarks/<date>/analyze.py --dir benchmarks/<date>
"""

import argparse
import csv
import json
import statistics
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e6e5e1"
S1, S2, S3 = "#2a78d6", "#eb6834", "#1baf7a"   # validated categorical slots 1-3
CRITICAL = "#e34948"

STAGE_ORDER = [
    ("packet_parse", "packet parse"),
    ("flow_aggregation", "flow aggregation"),
    ("feature_extraction", "feature extraction"),
    ("lightgbm_inference", "LightGBM inference"),
    ("isolation_forest_inference", "Isolation Forest inference"),
    ("behavior_analysis", "behavior analysis"),
    ("threat_assessment", "threat assessment"),
    ("decision", "decision"),
    ("candidate_generation", "candidate generation"),
    ("end_to_end_packet_to_decision", "END-TO-END packet -> decision"),
]


def style(ax, title: str = "", subtitle: str = "", xlabel: str = "", ylabel: str = "") -> None:
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK_2, labelsize=8, length=3, width=0.8)
    ax.grid(True, color=GRID, linewidth=0.7, alpha=0.9)
    ax.set_axisbelow(True)
    if title:
        ax.set_title(title, color=INK, fontsize=11, loc="left", pad=14 if subtitle else 8)
    if subtitle:
        ax.text(0.0, 1.02, subtitle, transform=ax.transAxes, color=INK_2, fontsize=8.5, va="bottom")
    if xlabel:
        ax.set_xlabel(xlabel, color=INK_2, fontsize=9)
    if ylabel:
        ax.set_ylabel(ylabel, color=INK_2, fontsize=9)


def read_runtime(path: Path) -> list[dict[str, str]]:
    """Rows of one runtime CSV, with the first heavy poll's flow-completion
    figure discarded: that poll sees the whole pre-existing
    `CoreStateStore.flows` buffer as "new" ids, which is a baseline artifact,
    not flows that completed during the run."""
    if not path.exists():
        return []
    with path.open() as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        if row.get("flow_completion_rate_per_s"):
            row["flow_completion_rate_per_s"] = ""
            break
    return rows


def fnum(row: dict[str, str], key: str) -> float:
    value = row.get(key, "")
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("nan")


RUN_SECONDS = 1800.0  # the observers' --duration; rows past it come from the final flush()


def stage_samples(data_dir: Path, label: str, subset: str = "all") -> dict[str, list[float]]:
    """Raw per-operation latencies in ms, per stage, for one run label.

    `subset` splits the flow-path stages by when they ran:

    * `during` -- flows the observer completed while the load generator, the
      pirewall-core daemon and this observer were all running. This is the
      contended figure.
    * `flush`  -- flows finalized by `FlowAggregator.flush()` after the
      capture window closed, i.e. the same code on the same real flows with
      no competing load. This is the clean per-operation cost.
    """
    samples: dict[str, list[float]] = {name: [] for name, _ in STAGE_ORDER}
    packets = data_dir / f"packet_stages_{label}.csv"
    if packets.exists() and subset in ("all", "during"):
        with packets.open() as handle:
            for row in csv.DictReader(handle):
                samples["packet_parse"].append(float(row["parse_us"]) / 1000.0)
                samples["flow_aggregation"].append(float(row["flow_aggregation_us"]) / 1000.0)
    flows = data_dir / f"flow_stages_{label}.csv"
    if flows.exists():
        with flows.open() as handle:
            for row in csv.DictReader(handle):
                elapsed = float(row["elapsed_s"])
                if subset == "during" and elapsed > RUN_SECONDS:
                    continue
                if subset == "flush" and elapsed <= RUN_SECONDS:
                    continue
                for key, _ in STAGE_ORDER:
                    if key in ("packet_parse", "flow_aggregation"):
                        continue
                    raw = row.get("end_to_end_ms" if key == "end_to_end_packet_to_decision" else key, "")
                    try:
                        value = float(raw)
                    except (TypeError, ValueError):
                        continue
                    if value == value:  # not NaN
                        samples[key].append(value)
    return samples


def load_step_bands(data_dir: Path) -> list[tuple[float, float, str]]:
    """(start_min, end_min, name) for each generated-load step, relative to the
    first sample of the loaded run, so steps line up with the plotted series."""
    steps_path = data_dir / "load_steps.json"
    runtime = data_dir / "runtime_loaded.csv"
    if not (steps_path.exists() and runtime.exists()):
        return []
    rows = read_runtime(runtime)
    if not rows:
        return []
    origin = datetime.fromisoformat(rows[0]["timestamp"]) - timedelta(
        seconds=float(rows[0]["elapsed_s"])
    )
    bands = []
    for step in json.loads(steps_path.read_text()):
        start = (datetime.fromisoformat(step["started_at"]) - origin).total_seconds() / 60.0
        end = (datetime.fromisoformat(step["ended_at"]) - origin).total_seconds() / 60.0
        bands.append((start, end, step["name"]))
    return bands


def draw_step_bands(axes, bands, label_axis=0) -> None:
    """Alternating shading + a vertical name per generated-load step."""
    target = axes[label_axis]
    for index, (start, end, name) in enumerate(bands):
        if index % 2:
            for ax in axes:
                ax.axvspan(start, end, color=GRID, alpha=0.6, zorder=0)
        target.text((start + end) / 2.0, 1.02,
                    name.split("-", 1)[1] if "-" in name else name,
                    transform=target.get_xaxis_transform(), color=INK_2, fontsize=7,
                    ha="center", va="bottom", rotation=90)


def figure_title(fig, title: str, subtitle: str) -> None:
    """Title/subtitle at figure level, so they never collide with an axes title."""
    fig.text(0.055, 0.975, title, color=INK, fontsize=12.5, ha="left", va="top")
    fig.text(0.055, 0.943, subtitle, color=INK_2, fontsize=8.5, ha="left", va="top")


def chart_latency_by_stage(data_dir: Path, charts: Path) -> None:
    """Two series, both real, deliberately separated.

    The idle phase captured 1 packet and completed 0 flows, so there is no
    idle series to plot. What there IS is the difference between flows
    processed while everything was running at once and flows processed from
    the backlog once the load stopped -- the same code on the same real
    flows, contended and uncontended.
    """
    during = stage_samples(data_dir, "loaded", "during")
    flush = stage_samples(data_dir, "loaded", "flush")
    rows = [(key, label) for key, label in STAGE_ORDER if during.get(key) or flush.get(key)]

    fig, ax = plt.subplots(figsize=(11.5, 7), facecolor=SURFACE)
    fig.subplots_adjust(left=0.23, right=0.63, top=0.80, bottom=0.16)
    positions = list(range(len(rows)))
    width = 0.36
    series = ((flush, S1, f"uncontended (n={len(flush['end_to_end_packet_to_decision']):,})"),
              (during, S2, f"under concurrent load (n={len(during['end_to_end_packet_to_decision']):,})"))
    for offset, (data_set, colour, name) in enumerate(series):
        data = [data_set.get(key) or [float("nan")] for key, _ in rows]
        pos = [p + (offset - 0.5) * width for p in positions]
        box = ax.boxplot(data, positions=pos, widths=width * 0.8,
                         orientation="horizontal", whis=(5, 95),
                         showfliers=False, patch_artist=True, manage_ticks=False)
        for patch in box["boxes"]:
            patch.set(facecolor=colour, edgecolor=colour, alpha=0.55, linewidth=1.1)
        for element in ("whiskers", "caps"):
            for artist in box[element]:
                artist.set(color=colour, linewidth=1.1)
        for median in box["medians"]:
            median.set(color=INK, linewidth=1.5)
        ax.plot([], [], color=colour, linewidth=7, alpha=0.6, label=name)

    ax.set_yticks(positions)
    ax.set_yticklabels([label for _, label in rows], color=INK, fontsize=9.5)
    ax.set_xscale("log")
    ax.set_xlim(0.001, 400)
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    style(ax, xlabel="latency per operation (ms, log scale)")
    fig.text(0.055, 0.975, "Pipeline latency per stage — Raspberry Pi 4 Model B (4 GB)",
             color=INK, fontsize=13, ha="left", va="top")
    fig.text(0.055, 0.940,
             "real AF_PACKET capture on wlan0 · real CICIDS2017-trained LightGBM v0.4.0 + "
             "Isolation Forest v0.2.0 · 4,662 completed flows",
             color=INK_2, fontsize=8.5, ha="left", va="top")
    fig.text(0.055, 0.915,
             "box = interquartile range · whiskers = 5th-95th percentile · line = median · "
             "packet-path stages are measured per packet (n=586,125), flow-path stages per flow",
             color=INK_2, fontsize=8.5, ha="left", va="top")

    ax.text(1.12, 1.02, "median", transform=ax.transAxes, color=INK_2,
            fontsize=8.5, ha="right", va="bottom", fontweight="bold")
    ax.text(1.45, 1.02, "p95", transform=ax.transAxes, color=INK_2,
            fontsize=8.5, ha="right", va="bottom", fontweight="bold")
    ax.text(1.29, 1.055, "under concurrent load", transform=ax.transAxes, color=INK_2,
            fontsize=8, ha="center", va="bottom")
    for index, (key, _) in enumerate(rows):
        values = sorted(during.get(key) or flush.get(key) or [])
        if not values:
            continue
        p95 = values[int(0.95 * (len(values) - 1))]
        ax.text(1.12, index, f"{statistics.median(values):.3f} ms",
                transform=ax.get_yaxis_transform(), color=INK, fontsize=8.5,
                ha="right", va="center")
        ax.text(1.45, index, f"{p95:.3f} ms", transform=ax.get_yaxis_transform(),
                color=INK_2, fontsize=8.5, ha="right", va="center")
    legend = ax.legend(loc="upper left", frameon=False, fontsize=9, ncol=2,
                       bbox_to_anchor=(0.0, -0.11))
    for text in legend.get_texts():
        text.set_color(INK)
    ax.invert_yaxis()
    fig.savefig(charts / "latency_by_stage.png", dpi=160, facecolor=SURFACE)
    plt.close(fig)


def chart_cpu_memory(data_dir: Path, charts: Path) -> None:
    fig, axes = plt.subplots(3, 1, figsize=(10, 9.4), sharex=True, facecolor=SURFACE)
    for label, color in (("idle", S1), ("loaded", S2)):
        rows = read_runtime(data_dir / f"runtime_{label}.csv")
        if not rows:
            continue
        base = 0.0 if label == "idle" else float(rows[0]["elapsed_s"])
        minutes = [(fnum(r, "elapsed_s") - base) / 60.0 for r in rows]
        axes[0].plot(minutes, [fnum(r, "core_cpu_pct") for r in rows],
                     color=color, linewidth=2, label=f"pirewall-core, {label}")
        axes[1].plot(minutes, [fnum(r, "core_rss_mb") for r in rows],
                     color=color, linewidth=2, label=f"pirewall-core RSS, {label}")
        axes[2].plot(minutes, [fnum(r, "host_cpu_pct") for r in rows],
                     color=color, linewidth=2, label=f"host, {label}")

    bands = load_step_bands(data_dir)
    draw_step_bands(list(axes), bands)
    style(axes[0], ylabel="core process CPU (%)")
    style(axes[1], ylabel="core process RSS (MB)")
    style(axes[2], xlabel="minutes into phase", ylabel="host CPU, all cores (%)")
    figure_title(fig, "pirewall-core CPU, memory and host CPU over time",
                 "shaded bands are generated-load steps · CPU is percent of ONE core "
                 "(400 % = all four cores) · one sample every 5 s")
    for ax in axes:
        legend = ax.legend(loc="upper left", frameon=False, fontsize=8)
        for text in legend.get_texts():
            text.set_color(INK)
    fig.tight_layout(rect=(0, 0, 1, 0.855))
    fig.savefig(charts / "cpu_memory_over_time.png", dpi=160, facecolor=SURFACE)
    plt.close(fig)


def observer_packet_rate(data_dir: Path, label: str, bucket_s: float = 5.0
                         ) -> tuple[list[float], list[float]]:
    """True packets/s from the observer's own per-packet timestamps.

    pirewall-core only refreshes its capture counters every
    `failure.watchdog_sec / 2` = 15 s, so differencing its `packets_seen`
    on a 5 s poll aliases into a sawtooth. The observer timestamps every
    packet it reads, so bucketing those gives the real rate."""
    path = data_dir / f"packet_stages_{label}.csv"
    if not path.exists():
        return [], []
    counts: dict[int, int] = {}
    with path.open() as handle:
        for row in csv.DictReader(handle):
            bucket = int(float(row["elapsed_s"]) // bucket_s)
            counts[bucket] = counts.get(bucket, 0) + 1
    if not counts:
        return [], []
    minutes = [(b * bucket_s) / 60.0 for b in sorted(counts)]
    rates = [counts[b] / bucket_s for b in sorted(counts)]
    return minutes, rates


def kernel_drop_events(rows: list[dict[str, str]]) -> list[tuple[float, int, int]]:
    """(minutes, drops_in_interval, packets_in_interval) per fresh daemon tick.

    `CaptureStatistics.packets_dropped` is NOT cumulative: `AFPacketCapture`
    reads it with `getsockopt(PACKET_STATISTICS)`, and the kernel zeroes
    tp_drops on every read. Each daemon tick therefore reports the drops
    since the previous tick. Differencing it like a counter (which is what a
    naive reading does, and what the Netdata `pirewall.packet_drops` gauge
    implies) is wrong -- see REPORT.md."""
    events: list[tuple[float, int, int]] = []
    prev_seen: int | None = None
    for row in rows:
        seen = int(row["packets_seen"])
        if seen == prev_seen:
            continue
        elapsed = fnum(row, "elapsed_s")
        interval_packets = seen - prev_seen if prev_seen is not None else 0
        if prev_seen is not None:
            events.append((elapsed / 60.0, int(row["packets_dropped"]), interval_packets))
        prev_seen = seen
    return events


def chart_drops(data_dir: Path, charts: Path) -> None:
    fig, axes = plt.subplots(2, 1, figsize=(10, 7.4), sharex=True, facecolor=SURFACE)
    for label, color in (("idle", S1), ("loaded", S2)):
        minutes, rates = observer_packet_rate(data_dir, label)
        if minutes:
            axes[0].plot(minutes, rates, color=color, linewidth=1.6, label=label)
        rows = read_runtime(data_dir / f"runtime_{label}.csv")
        if not rows:
            continue
        events = kernel_drop_events(rows)
        xs = [e[0] for e in events]
        ys = [e[1] / e[2] * 100.0 if e[2] > 0 else 0.0 for e in events]
        axes[1].plot(xs, ys, color=color, linewidth=1.8, label=label)
        for minute, drops, packets in events:
            if drops:
                axes[1].annotate(f"{drops:,} dropped\n({drops / packets * 100:.1f} % of the interval)",
                                 (minute, drops / packets * 100.0),
                                 textcoords="offset points", xytext=(-8, -6),
                                 fontsize=8, color=INK, ha="right", va="top")

    bands = load_step_bands(data_dir)
    draw_step_bands(list(axes), bands)
    style(axes[0], ylabel="packets/s captured")
    style(axes[1], xlabel="minutes into phase", ylabel="kernel drops (% of interval)")
    figure_title(fig, "Capture throughput and kernel packet-drop rate (AF_PACKET, wlan0)",
                 "shaded bands are generated-load steps · throughput from the observer's own "
                 "per-packet timestamps · drops from PACKET_STATISTICS, per 15 s daemon tick")
    axes[1].text(0.01, 0.62,
                 "zero drops everywhere except one 30 s window in max-pps-2000-flows,\n"
                 "where the flow backlog saturated a core",
                 transform=axes[1].transAxes, color=INK_2, fontsize=8.5, va="top")
    for ax in axes:
        legend = ax.legend(loc="upper left", frameon=False, fontsize=8,
                           bbox_to_anchor=(0.0, 0.86))
        for text in legend.get_texts():
            text.set_color(INK)
    fig.tight_layout(rect=(0, 0, 1, 0.855))
    fig.savefig(charts / "packet_drop_rate.png", dpi=160, facecolor=SURFACE)
    plt.close(fig)


def chart_flows(data_dir: Path, charts: Path) -> None:
    fig, axes = plt.subplots(2, 1, figsize=(10, 7.4), sharex=True, facecolor=SURFACE)
    for label, color in (("idle", S1), ("loaded", S2)):
        rows = read_runtime(data_dir / f"runtime_{label}.csv")
        if not rows:
            continue
        base = 0.0 if label == "idle" else float(rows[0]["elapsed_s"])
        minutes = [(fnum(r, "elapsed_s") - base) / 60.0 for r in rows]
        pts = [(m, fnum(r, "flow_completion_rate_per_s")) for m, r in zip(minutes, rows, strict=True)
               if r.get("flow_completion_rate_per_s")]
        if pts:
            axes[1].plot([p[0] for p in pts], [p[1] for p in pts],
                         color=color, linewidth=2,
                         label=f"completed/expired, {label} (pirewall-core)")
    for label, color in (("idle", S1), ("loaded", S2)):
        table = data_dir / f"flowtable_{label}.csv"
        if not table.exists():
            continue
        with table.open() as handle:
            rows = list(csv.DictReader(handle))
        if not rows:
            continue
        axes[0].plot([fnum(r, "elapsed_s") / 60.0 for r in rows],
                     [fnum(r, "flow_table_size") for r in rows],
                     color=color, linewidth=2, label=f"{label}")
    bands = load_step_bands(data_dir)
    draw_step_bands(list(axes), bands)
    style(axes[0], ylabel="open flows in table")
    figure_title(fig, "Live flow-table size, and flow completion rate",
                 "table size measured by the observer's own FlowAggregator over the same packets "
                 "(pirewall-core does not export it) · completions counted from pirewall-core")
    style(axes[1], xlabel="minutes into phase", ylabel="flows/s")
    for ax in axes:
        legend = ax.legend(loc="upper left", frameon=False, fontsize=8)
        for text in legend.get_texts():
            text.set_color(INK)
    fig.tight_layout(rect=(0, 0, 1, 0.855))
    fig.savefig(charts / "flow_table_over_time.png", dpi=160, facecolor=SURFACE)
    plt.close(fig)


def chart_throughput_vs_latency(data_dir: Path, charts: Path) -> None:
    steps_path = data_dir / "load_steps.json"
    summary_path = data_dir / "stage_summary_loaded.json"
    flows_path = data_dir / "flow_stages_loaded.csv"
    packets_path = data_dir / "packet_stages_loaded.csv"
    if not (steps_path.exists() and summary_path.exists()):
        return
    steps = json.loads(steps_path.read_text())
    summary = json.loads(summary_path.read_text())
    end = datetime.fromisoformat(summary["generated_at"])
    start = end - timedelta(seconds=summary["duration_seconds"])

    def window(step: dict[str, str]) -> tuple[float, float]:
        s = (datetime.fromisoformat(step["started_at"]) - start).total_seconds()
        e = (datetime.fromisoformat(step["ended_at"]) - start).total_seconds()
        return s, e

    packet_rows: list[tuple[float, float, float]] = []
    if packets_path.exists():
        with packets_path.open() as handle:
            for row in csv.DictReader(handle):
                packet_rows.append((float(row["elapsed_s"]),
                                    float(row["parse_us"]) / 1000.0,
                                    float(row["flow_aggregation_us"]) / 1000.0))
    flow_rows: list[dict[str, str]] = []
    if flows_path.exists():
        with flows_path.open() as handle:
            flow_rows = list(csv.DictReader(handle))

    points = []
    for step in steps:
        lo, hi = window(step)
        span = max(1e-9, hi - lo)
        pkts = [r for r in packet_rows if lo <= r[0] < hi]
        flows = [r for r in flow_rows if lo <= float(r["elapsed_s"]) < hi]
        if not pkts:
            continue
        points.append({
            "name": step["name"],
            "observed_pps": len(pkts) / span,
            "packet_path_ms": statistics.fmean([r[1] + r[2] for r in pkts]),
            # None, not NaN: NaN is not valid JSON, and a step in which no flow
            # completed has no end-to-end figure rather than an undefined one.
            "e2e_ms": statistics.fmean([float(r["end_to_end_ms"]) for r in flows]) if flows else None,
            "flows": len(flows),
            "flows_per_s": len(flows) / span,
        })
    if not points:
        return
    points.sort(key=lambda p: p["observed_pps"])

    fig, axes = plt.subplots(1, 2, figsize=(12, 5.4), facecolor=SURFACE)
    fig.subplots_adjust(top=0.76, bottom=0.14, wspace=0.28)

    # Packet path: every point is >=20,000 packets, and the trend really is a
    # function of packet rate, so a connecting line is warranted.
    x = [p["observed_pps"] for p in points]
    axes[0].plot(x, [p["packet_path_ms"] for p in points], color=S1,
                 linewidth=2, marker="o", markersize=8)
    for p in points:
        axes[0].annotate(f'{p["packet_path_ms"]:.3f} ms', (p["observed_pps"], p["packet_path_ms"]),
                         textcoords="offset points", xytext=(0, 10), fontsize=8,
                         color=INK, ha="center")
    axes[0].set_ylim(0.08, 0.28)
    style(axes[0], xlabel="packets/s actually captured", ylabel="ms per packet")
    axes[0].set_title("Packet path — parse + flow aggregation", color=INK,
                      fontsize=10.5, loc="left", pad=24)
    axes[0].text(0.0, 1.012, "per-packet CPU cost, mean over each load step "
                 "(each point ≥ 20,000 packets)",
                 transform=axes[0].transAxes, color=INK_2, fontsize=8, va="bottom")

    # Flow path: deliberately NOT a line. End-to-end latency is not a function
    # of packet rate -- the two ~392 pps steps differ by 3 ms purely because
    # one held 500 concurrent flows and the other 20. Connecting these points
    # in packet-rate order would draw a trend that does not exist.
    ok = [p for p in points if p["e2e_ms"] is not None]
    ok.sort(key=lambda p: p["observed_pps"])
    for index, p in enumerate(ok):
        weak = p["flows"] < 50
        axes[1].scatter([p["observed_pps"]], [p["e2e_ms"]], s=170 if not weak else 90,
                        color=S2 if not weak else SURFACE, edgecolor=S2,
                        linewidth=2, zorder=3)
        axes[1].annotate(f'{p["name"].split("-", 1)[1]}\n{p["e2e_ms"]:.1f} ms · n={p["flows"]}',
                         (p["observed_pps"], p["e2e_ms"]),
                         textcoords="offset points",
                         xytext=(0, 15) if index % 2 == 0 else (0, -34),
                         fontsize=8, color=INK, ha="center")
    axes[1].set_ylim(20, 82)
    style(axes[1], xlabel="packets/s actually captured", ylabel="ms per decision")
    axes[1].set_title("Flow path — end-to-end packet → decision", color=INK,
                      fontsize=10.5, loc="left", pad=24)
    axes[1].text(0.0, 1.012, "hollow points are weakly determined (fewer than 50 flows "
                 "completed inside the step)",
                 transform=axes[1].transAxes, color=INK_2, fontsize=8, va="bottom")

    fig.text(0.045, 0.965, "Throughput versus latency, per generated-load step",
             color=INK, fontsize=13, ha="left", va="top")
    fig.text(0.045, 0.925,
             "The packet path gets cheaper per packet as the rate rises. The flow path does not "
             "track packet rate at all: the jump to 65.8 ms is the 2,000-concurrent-flow step, where "
             "flows completed\nfaster than Isolation Forest could score them — the same step that "
             "produced the only packet drops of the whole run.",
             color=INK_2, fontsize=8.5, ha="left", va="top")

    fig.savefig(charts / "throughput_vs_latency.png", dpi=160, facecolor=SURFACE)
    plt.close(fig)

    (data_dir / "load_step_results.json").write_text(json.dumps(points, indent=2))
    print(json.dumps(points, indent=2))


def print_tables(data_dir: Path) -> None:
    for label in ("idle", "loaded"):
        rows = read_runtime(data_dir / f"runtime_{label}.csv")
        if not rows:
            continue
        print(f"\n### runtime_{label}.csv — {len(rows)} samples")
        for key in ("packet_rate_pps", "core_cpu_pct", "core_rss_mb", "api_rss_mb",
                    "host_cpu_pct", "host_mem_used_pct", "state_flow_records",
                    "flow_completion_rate_per_s", "rpc_poll_ms"):
            values = [fnum(r, key) for r in rows if fnum(r, key) == fnum(r, key)]
            if values:
                print(f"  {key:24s} mean={statistics.fmean(values):9.2f} "
                      f"min={min(values):9.2f} max={max(values):9.2f} "
                      f"p95={sorted(values)[int(0.95 * (len(values) - 1))]:9.2f}")
        events = kernel_drop_events(rows)
        print(f"  packets_seen delta: {fnum(rows[-1], 'packets_seen') - fnum(rows[0], 'packets_seen'):.0f}")
        print(f"  kernel drops total: {sum(e[1] for e in events)} "
              f"(summed per-tick, NOT differenced — the counter resets on read)")
        for minute, drops, packets in events:
            if drops:
                print(f"    drop event at {minute:.2f} min: {drops} of {packets} packets "
                      f"in that tick ({drops / packets * 100:.1f} %)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True)
    args = parser.parse_args()
    root = Path(args.dir)
    data_dir = root / "data"
    charts = root / "charts"
    charts.mkdir(parents=True, exist_ok=True)

    chart_latency_by_stage(data_dir, charts)
    chart_cpu_memory(data_dir, charts)
    chart_drops(data_dir, charts)
    chart_flows(data_dir, charts)
    chart_throughput_vs_latency(data_dir, charts)
    print_tables(data_dir)
    print(f"\ncharts written to {charts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
