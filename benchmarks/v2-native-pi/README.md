# v2 native capture benchmark for the Pi (phase 15)

**Status: written, not run. Every result is Environment-dependent until it
has run on the Raspberry Pi.** Phase 15 ran nothing here; there are no
results files.

What it measures: frames per second reaching the flow layer, and kernel
drops, for the native path (`TPACKET_V3` ring + Rust `FlowEngine`) and the
Python path (`AFPacketCapture` + parser + `FlowAggregator`), each with and
without a GIL-holding contender thread, under a synthetic SYN flood and UDP
flood offered at fixed rates.

How: `gen_pcap.py` writes deterministic floods with `pirewall.capture.pcapio`;
`run.sh` replays them with `tcpreplay --pps` from a network namespace across a
veth pair and runs the existing measurement
(`benchmarks/2026-10-15-native-capture/bench_capture.py`) on the near end.
It creates and deletes its own netns and veth; it touches no real interface
and no nftables state.

To run on the Pi (needs `tcpreplay`, root, and `uv sync --extra native`):

```
sudo ENV_TAG=pi-scripted ./benchmarks/v2-native-pi/run.sh
```

`ENV_TAG` defaults to `sandbox` (ADDENDUM_4.md D7), so forgetting it can only
under-claim. Results go to `results-<UTC time>-<env tag>.jsonl` next to this
file. Only a `pi-*` tagged file is a Pi result. Never average its numbers with
the x86 figures in `benchmarks/2026-10-15-native-capture/` or
`docs/v2/audit_new_main.md`.
