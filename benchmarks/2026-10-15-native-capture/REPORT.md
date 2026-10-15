# Capture path: Python vs native engine — 2026-10-15

**Host: NOT a Raspberry Pi.** Docker Desktop's Linux VM on a development PC
(12th Gen Intel Core i7-12700F, 20 vCPUs, kernel 6.18.33.2-microsoft-standard-WSL2,
Python 3.12, pirewall-native 0.1.0 release build). Absolute numbers here say
nothing about Pi capacity; the *ratios* between the two paths, run back to
back on identical traffic, are what this measures. The Pi run is
Environment-dependent — see "What a human needs to do" below.

## Setup

`run.sh` (this directory) builds a veth pair inside a disposable privileged
container, with the far end in its own network namespace, and floods the
near end (`veth0`) with `hping3` from that namespace. `bench_capture.py`
captures on `veth0` for 10 s through one path and reports frames that
reached the flow layer and frames the kernel dropped because capture fell
behind (`PACKET_STATISTICS`):

- **python** — `AFPacketCapture` (now with kernel timestamps and
  `SO_RCVBUFFORCE`) + `parse_packet` + `FlowAggregator.process_packet`,
  i.e. the daemon's Python capture thread.
- **native** — `NativePacketCapture` (`TPACKET_V3`, 16 × 1 MiB blocks) feeding
  `FlowEngine`, then `NativeFlowAggregator.drain()` each poll — i.e. the
  daemon's native capture thread, including its Python-side conversion,
  with the daemon's default per-drain caps (1,000 flows / 5,000 signals).
- **contend** — an extra CPU-bound pure-Python thread, standing in for
  pirewall-core's detection and inference threads, which in the real daemon
  are always competing for the GIL.

Traffic: `syn` = `hping3 -S --flood -p 80` (port closed, so each SYN draws an
RST — every packet pair is a completed flow, the worst case for per-flow
work); `udp` = `hping3 --udp --flood -p 53`; `syn10k` = `hping3 -S -i u100`
(nominally 10k SYN/s; with the RSTs ~16.5k frames/s, close to the attack-lab
rate on the Pi).

## Results (raw: `results.txt`)

| traffic | path | GIL contention | frames processed/s | kernel drop rate | completed flows shed |
|---|---|---|---:|---:|---:|
| syn flood | python | no | 28,937 | 96.4% | — |
| syn flood | python | yes | 8,511 | 99.0% | — |
| syn flood | **native** | no | **656,268** | 20.6% | 3,000,301 |
| syn flood | **native** | yes | **252,468** | 70.7% | 1,153,334 |
| udp flood | python | no | 53,245 | 90.8% | — |
| udp flood | python | yes | 10,521 | 98.3% | — |
| udp flood | **native** | no | **605,311** | **0.0%** | 0 |
| udp flood | **native** | yes | **586,892** | **0.0%** | 0 |
| syn ~16.5k/s | python | no | 14,805 | 0.0% | — |
| syn ~16.5k/s | python | yes | 8,576 | **44.9%** | — |
| syn ~16.5k/s | **native** | no | 16,400 | 0.0% | 0 |
| syn ~16.5k/s | **native** | yes | 16,385 | **0.0%** | 0 |

## Reading

1. **GIL contention is what breaks the Python path, not raw parsing speed.**
   At ~16.5k frames/s the Python path keeps up *alone* but drops 45% the
   moment another Python thread competes — the daemon's normal condition.
   This reproduces the shape of the Pi attack-lab result (94% dropped) on
   much faster hardware. The native path is unaffected by contention at
   that rate: packets never take the GIL.
2. **Throughput**: 22× (SYN, uncontended), 30× (SYN, contended), 11–56×
   (UDP) more frames reach the flow layer.
3. **What still limits the native path under the SYN flood is per-flow
   Python work**, even with shedding: every SYN+RST pair completes a flow,
   and converting even the capped 1,000 flows + 5,000 signals per drain
   into Pydantic objects takes the GIL. That is the intended trade-off —
   detection cannot assess more than a few hundred flows a second on a Pi
   anyway, and the shed flows are counted and reported, never silent — and
   the source-level fast path still sees the flood through the signals it
   does receive. A first run *without* the per-drain caps processed only
   75k frames/s on the same flood (converting 37k flows/s), which is why
   the caps exist.
4. UDP flood flows never complete (hping3 reuses source ports, so the
   65,535 flows stay open), so there is almost no per-flow Python work and
   the native path runs at line rate.

## What a human needs to do to verify on the Pi

1. Install a Rust toolchain on the Pi (`curl https://sh.rustup.rs -sSf | sh`)
   and run `uv sync --extra native` in the repo (several minutes on a Pi 4).
2. `uv run python -c "import pirewall_native as n; print(n.HAS_PACKET_RING)"`
   must print `True`.
3. Re-run the attack-lab SYN flood (`benchmarks/2026-09-10-attack-lab/`)
   against the running daemon and compare `get_capture_stats()`'s
   `packets_seen`/`packets_dropped` with that report's 19,695 / 297,595.
   The startup log line `capture started on wlan0 (native path)` confirms
   which path ran.
