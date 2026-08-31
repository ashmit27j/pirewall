"""Quick batch-size benchmark for `IsolationForest.decision_function` overhead.

Session prompt section 3a: before designing batched anomaly-scoring
inference (see `docs/PROGRESS.md`'s ADDENDUM_2 follow-up pass, section 3),
measure real call-overhead numbers at a few batch sizes against the real,
shipped v0.2.0 Isolation Forest artifact
(`pirewall/ml/artifacts/isolation_forest_model.joblib`) instead of guessing
a batch size / flush timeout.

This measures the same `decision_function` call
`pirewall.ml.inference.isolation_forest_predictor.anomaly_score` makes,
just with `n` feature rows stacked into one array instead of one, isolating
scikit-learn/Python per-call overhead from tree traversal cost — the same
framing `benchmarks/2026-08-30/REPORT.md` used comparing single-flow to
batch-of-200 scoring.

**Not a Pi run.** This runs on whatever machine executes it; no real
Raspberry Pi 4 was reachable this session (see `docs/PROGRESS.md` for the
honesty label). The featured input rows are synthetic random floats, not
real captured traffic -- fine for measuring pure call overhead, which is a
function of array shape and scikit-learn's own per-call fixed costs, not
feature *values*.

Run: uv run python benchmarks/2026-08-31-anomaly-batching/quick_benchmark.py
"""

import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import numpy as np

from pirewall.ml.inference.loader import load_isolation_forest_model

MODEL_PATH = Path(__file__).resolve().parents[2] / "pirewall/ml/artifacts/isolation_forest_model.joblib"
BATCH_SIZES = [1, 10, 25, 50, 100]
WARMUP_CALLS = 5
TIMED_CALLS = 200


def main() -> None:
    loaded = load_isolation_forest_model(MODEL_PATH)
    n_features = len(loaded.metadata.feature_ordering)
    rng = np.random.default_rng(42)

    print(f"host: {platform.platform()} / {platform.processor() or platform.machine()}")
    print(f"model_version={loaded.metadata.model_version} n_features={n_features}")
    print(f"{'batch_size':>10} {'ms_per_call':>14} {'ms_per_flow':>14} {'flows_per_sec':>14}")

    for batch_size in BATCH_SIZES:
        batch = rng.standard_normal((batch_size, n_features))

        for _ in range(WARMUP_CALLS):
            loaded.model.decision_function(batch)  # pyright: ignore[reportUnknownMemberType]

        timings: list[float] = []
        for _ in range(TIMED_CALLS):
            start = time.perf_counter()
            loaded.model.decision_function(batch)  # pyright: ignore[reportUnknownMemberType]
            timings.append(time.perf_counter() - start)

        mean_ms_per_call = statistics.mean(timings) * 1000
        mean_ms_per_flow = mean_ms_per_call / batch_size
        flows_per_sec = 1000.0 / mean_ms_per_flow
        print(
            f"{batch_size:>10} {mean_ms_per_call:>14.4f} {mean_ms_per_flow:>14.4f} {flows_per_sec:>14.1f}"
        )


if __name__ == "__main__":
    main()
