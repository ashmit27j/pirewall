#!/usr/bin/env bash
# Loaded phase: a step ladder of generated load with both observers running
# throughout, so latency can be read against actually-achieved throughput.
#
# Nothing here writes to pirewall. `loadgen.py` is an ordinary UDP sender;
# the two observers are read-only (see their module docstrings).
set -euo pipefail

B="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$B/../.." && pwd)"
SP="${SCRATCH:-/tmp}"
cd "$REPO"

PY=".venv/bin/python3.12"
STEPS_JSON="$B/data/load_steps.json"
PHASE="$SP/phase.txt"
TOTAL=1800

echo "loaded phase starting $(date -Is), total ${TOTAL}s"
sudo "$PY" "$B/collect_runtime.py" --duration "$TOTAL" --interval 5 --label loaded \
    --out "$B/data/runtime_loaded.csv" --phase-file "$PHASE" > "$SP/collect_loaded.log" 2>&1 &
sudo "$PY" "$B/stage_latency.py" --duration "$TOTAL" --label loaded \
    --outdir "$B/data" > "$SP/stage_loaded.log" 2>&1 &
sleep 5

echo "[" > "$STEPS_JSON"
FIRST=1

step() {  # name duration workers pps payload port_span
    local name="$1" dur="$2" workers="$3" pps="$4" payload="$5" span="$6"
    local start end
    start="$(date -u +%Y-%m-%dT%H:%M:%S.%6N+00:00)"
    echo "$name" > "$PHASE"
    echo ">>> step $name (${dur}s, workers=$workers pps/worker=$pps payload=${payload}B ports=$span)"
    if [ "$workers" -eq 0 ]; then
        sleep "$dur"
    else
        python3 "$B/loadgen.py" --duration "$dur" --workers "$workers" \
            --pps-per-worker "$pps" --payload "$payload" --port-span "$span"
    fi
    end="$(date -u +%Y-%m-%dT%H:%M:%S.%6N+00:00)"
    [ "$FIRST" -eq 1 ] || echo "," >> "$STEPS_JSON"
    FIRST=0
    printf '{"name":"%s","started_at":"%s","ended_at":"%s","workers":%s,"pps_per_worker":%s,"payload_bytes":%s,"port_span":%s}' \
        "$name" "$start" "$end" "$workers" "$pps" "$payload" "$span" >> "$STEPS_JSON"
}

step "00-no-load"            120 0 0   0    0
step "01-100pps"             240 1 100 200  20
step "02-250pps"             240 1 250 200  20
step "03-400pps"             240 1 400 200  20
step "04-max-pps"            240 2 0   64   20
step "05-400pps-500-flows"   240 1 400 200  500
step "06-max-pps-2000-flows" 240 2 0   64   2000
step "07-drain"              180 0 0   0    0

echo "]" >> "$STEPS_JSON"
wait
echo "loaded phase finished $(date -Is)"
