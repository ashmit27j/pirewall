# Isolation Forest batching benchmark — real Pi hardware — 2026-09-10

Script: `benchmarks/2026-08-31-anomaly-batching/quick_benchmark.py` (unmodified),
run for the first time against real Raspberry Pi 4 hardware — the original
2026-08-31 run was explicitly labeled "not a Pi run" (no Pi was reachable
that session). This closes that gap.

**Host**: Raspberry Pi 4 Model B Rev 1.5, `Linux-6.18.39+rpt-rpi-v8-aarch64`,
Python 3.13.5. Real, shipped v0.2.0 Isolation Forest artifact
(`pirewall/ml/artifacts/isolation_forest_model.joblib`), synthetic random
feature rows (isolates scikit-learn/Python per-call overhead from tree
traversal cost — see the script's own docstring).

Command: `uv run python benchmarks/2026-08-31-anomaly-batching/quick_benchmark.py`

## Results

```
host: Linux-6.18.39+rpt-rpi-v8-aarch64-with-glibc2.41 / aarch64
model_version=0.2.0 n_features=29
batch_size    ms_per_call    ms_per_flow  flows_per_sec
         1        63.7119        63.7119           15.7
        10        55.7325         5.5732          179.4
        25        57.9431         2.3177          431.5
        50        60.7222         1.2144          823.4
       100        60.4916         0.6049         1653.1
```

Raw output: `quick_benchmark_output.txt` (this directory).

## Reading

- **Per-call overhead dominates at batch size 1**: ~64ms to score a single
  flow, of which almost all is fixed scikit-learn/Python call overhead, not
  tree traversal — the per-*call* cost (`ms_per_call`) stays roughly flat
  (~56-64ms) across every batch size tested, while the per-*flow* cost
  drops by two orders of magnitude (63.7ms -> 0.6ms) simply by amortizing
  that fixed cost over more flows per call.
- **Batching is the whole point, confirmed on real hardware**: 100
  flows/call reaches ~1,650 flows/sec, vs. ~16 flows/sec unbatched — a
  ~105x throughput improvement, consistent with the shape (if not the
  exact numbers) the 2026-08-31 dev-machine run predicted before a real Pi
  was reachable.
- **Not yet done**: comparing these numbers against real captured traffic's
  actual flow arrival rate on this deployment, to pick a concrete
  `anomaly_batch_size`/flush-timeout pair from measured data rather than
  the fixed default currently in `config/default_config.toml`. This run
  only closes the "what does batching cost on real Pi hardware" question;
  picking a deployment-specific batch size is a separate step.
