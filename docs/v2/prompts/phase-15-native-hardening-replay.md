# Phase 15: Native engine hardening, the pcap reader, and a replay capture backend

**Read first:**
- `CLAUDE.md` (v2 section)
- `docs/ADDENDUM_4.md` D6 and D7
- `docs/v2/audit_new_main.md` §0 and §3
- `native/` (all of it)
- `pirewall/capture/native.py`, `pirewall/flow/native.py`, `pirewall/capture/interfaces.py`, `pirewall/capture/fake.py`
- `pirewall/ml/preprocessing/`
- `benchmarks/2026-10-15-native-capture/`

**Owns:**
- `native/**`
- New `pirewall/capture/replay.py`
- New `pirewall/capture/pcapio.py`
- New `scripts/dataset/**`
- Their tests

This phase can run in parallel with phases 12 and 13. Coordinate the MAC fields with phase 14. If phase 14 has merged first, rebase onto it. Otherwise don't add the MAC fields here.

## Goal
- **Remove the native engine's crash-to-off-switch path.**
- **Make the native engine the only flow and feature producer for training**, by replaying pcaps through `FlowEngine.feed`, so live and training features are byte-identical.
- **Give developers a no-root, no-Pi mode.**

## Deliverables
1. **Hardening.**
   - Switch to `panic = "unwind"`.
   - Wrap every PyO3 entry point (`feed`, `poll`/drain, `sweep`) in `std::panic::catch_unwind`, mapping a panic to a Python `NativeEngineError`. The Python side then counts it, drops that frame or batch, emits a MODEL_ERROR-style `CAPTURE_ERROR` event, and continues. After N panics per minute it falls back to the Python capture path, with a CRITICAL event.
   - Clamp TPACKET_V3 ring offsets and `snaplen` to `block_size` in `capture.rs`.
   - Add a `cargo-fuzz` target for `parse::parse`. If cargo-fuzz can't run, use a property test with `proptest`. Run it for at least 10 minutes and record the result.
2. **`pirewall/capture/pcapio.py`.**
   - A stdlib-only pcap and pcapng reader (DLT_EN10MB; nanosecond and microsecond timestamps; snaplen-truncated records).
   - A stdlib-only pcap writer, for the mock generator in phase 18.
   - Tests against a few tiny committed fixtures, generated in the test with the writer.
3. **`capture.backend = "replay"`.**
   - A `ReplayCapture` that feeds a pcap file or directory through the **same** `FlowEngine` (or the Python path if native is unavailable) at a configurable `speed`: `realtime`, `Nx`, or `max` with a virtual clock.
   - It plugs into `CoreDaemon` capture selection, so core runs with **no root and no nft** when the fake firewall backend is selected (phase 16 wires `--data-mode mock`).
4. **`scripts/dataset/pcap_to_flows.py`.**
   - Replays pcaps through the engine with the exact runtime flow config (timeouts, accounting) and writes Parquet if pyarrow is already present, otherwise CSV.
   - Each row holds the schema features, flow metadata (MACs, 5-tuple, times) and a `connection_start` flag, as defined in `V2_CONTRACTS`.
   - Optionally applies labels from a `ground_truth.jsonl` (attacker MAC + time window → label; everything else benign, or `unlabelled` if `--strict`).
   - It records the input pcap SHA-256s, the engine version, the config hash and the row counts in a sidecar `manifest.json`.
5. **Parity proof.** A test that replays a pcap through `pcap_to_flows.py` and through live-path feeding (`FlowEngine.feed` used the way `capture/native.py` uses it) and asserts identical feature vectors.
6. **Benchmark script for the Pi.** `benchmarks/v2-native-pi/run.sh` generates a synthetic pcap and measures frames/s and drops for the native and Python paths, with and without GIL contention. **Nothing is run here** — it's labelled Environment-dependent.

## Tests
- Rust: `cargo test`, `clippy -D warnings`, a fuzz/proptest run summary.
- Python: pcapio round-trip, replay determinism (same pcap gives same flows), the parity test, panic → fallback (inject a panic with a test-only feature flag).

## Non-goals
No detection or ML training (phase 19), no `pirewall-start` (phase 16).

## Definition of done
- All suites green.
- The fuzz result is recorded in PROGRESS.
- Audit item "native panic=abort" is fixed. v1 #4 (train/serve skew) is fixed in tooling; the retraining happens in phase 19.
