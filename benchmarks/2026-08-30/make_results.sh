#!/usr/bin/env bash
# Regenerate results.txt: every measured number from this benchmark as plain
# text, in one file. Interpretation and caveats live in REPORT.md.
#
#   PLOTPY=<venv-with-matplotlib>/bin/python ./make_results.sh
set -euo pipefail
cd "$(dirname "$0")"
PLOTPY="${PLOTPY:-python3}"

{
echo "========================================================================"
echo "pirewall — real-hardware performance benchmark, results"
echo "Raspberry Pi 4 Model B Rev 1.5 (4 GB) · benchmark run 2026-08-30"
echo "Generated $(date -Is)"
echo "Full write-up, caveats and honesty labels: REPORT.md"
echo "========================================================================"
echo
echo "### analyze.py — per-load-step throughput/latency and phase summaries"
echo
"$PLOTPY" analyze.py --dir .

echo
echo "========================================================================"
echo "### Per-stage pipeline latency (ms/operation), real Pi 4, real models"
echo "    uncontended = flows finalized after the capture window closed"
echo "    contended   = flows completed while load generator + daemon +"
echo "                  observer were all running (right-hand columns)"
echo "========================================================================"
python3 - <<'PYEOF'
import csv, statistics
rows = list(csv.DictReader(open("data/flow_stages_loaded.csv")))
during = [r for r in rows if float(r["elapsed_s"]) <= 1800.0]
flush = [r for r in rows if float(r["elapsed_s"]) > 1800.0]

def stat(sub, k):
    v = sorted(float(r[k]) for r in sub if r[k] not in ("", "nan"))
    return len(v), statistics.fmean(v), v[len(v) // 2], v[int(.95 * (len(v) - 1))], v[-1]

print(f"{'stage':<28}{'n':>7}{'mean':>10}{'p50':>10}{'p95':>10}{'max':>10}   | "
      f"{'mean':>9}{'p50':>9}{'p95':>9}")
pk = list(csv.DictReader(open("data/packet_stages_loaded.csv")))
for name, col in (("packet parse", "parse_us"), ("flow aggregation", "flow_aggregation_us")):
    v = sorted(float(r[col]) / 1000.0 for r in pk)
    n = len(v)
    print(f"{name:<28}{n:>7}{statistics.fmean(v):>10.4f}{v[n//2]:>10.4f}"
          f"{v[int(.95*(n-1))]:>10.4f}{v[-1]:>10.4f}   | (per packet)")
for k, label in (("feature_extraction", "feature extraction"),
                 ("lightgbm_inference", "LightGBM inference"),
                 ("isolation_forest_inference", "Isolation Forest infer."),
                 ("behavior_analysis", "behavior analysis"),
                 ("threat_assessment", "threat assessment"),
                 ("decision", "decision"),
                 ("candidate_generation", "candidate generation"),
                 ("end_to_end_ms", "END-TO-END pkt->decision")):
    n, m, p50, p95, mx = stat(flush, k)
    _, cm, cp50, cp95, _ = stat(during, k)
    print(f"{label:<28}{n:>7}{m:>10.3f}{p50:>10.3f}{p95:>10.3f}{mx:>10.3f}   | "
          f"{cm:>9.3f}{cp50:>9.3f}{cp95:>9.3f}")
print(f"\ncontended n = {len(during)}   uncontended n = {len(flush)}   "
      f"total flows = {len(rows)}")
print("Isolation Forest = %.1f %% of end-to-end cost"
      % (stat(flush, 'isolation_forest_inference')[1] / stat(flush, 'end_to_end_ms')[1] * 100))
print("Flow-path ceiling = %.1f decisions/s (1000 / %.3f ms)"
      % (1000.0 / stat(flush, 'end_to_end_ms')[1], stat(flush, 'end_to_end_ms')[1]))
print("\nNOTE: the 274 ms flow-aggregation maximum is 1 sample of 586,125 and is NOT")
print("an LRU eviction (the table peaked at 4,500 flows against max_flows=100,000).")
print("Left unattributed; plan against the p95 of 0.12 ms.")
PYEOF

echo
echo "========================================================================"
echo "### Per-load-step, daemon-side (pirewall-core process)"
echo "    drops are SUMMED over each fresh 15 s tick, never differenced:"
echo "    getsockopt(PACKET_STATISTICS) zeroes tp_drops on every read, so"
echo "    CaptureStatistics.packets_dropped is a per-interval value, not a"
echo "    counter. Differencing it reports zero drops. See REPORT.md §4."
echo "========================================================================"
python3 -c "
import json
print(f\"{'step':<26}{'pps':>9}{'packets':>10}{'drops':>8}{'drop%':>8}{'cpu mean%':>11}{'cpu p95%':>10}{'rss max MB':>12}\")
data = json.load(open('data/per_step_daemon.json'))
for o in data:
    print(f\"{o['step']:<26}{o['daemon_pps']:>9.1f}{o['packets']:>10}{o['drops_summed_per_tick']:>8}\"
          f\"{o['drop_pct']:>8.2f}{o['core_cpu_mean']:>11.1f}{o['core_cpu_p95']:>10.1f}{o['core_rss_max']:>12.2f}\")
print()
print('total packets:', sum(o['packets'] for o in data),
      ' total drops:', sum(o['drops_summed_per_tick'] for o in data))
"

echo
echo "========================================================================"
echo "### Detection-queue depth (systemd StatusText), changes only"
echo "========================================================================"
awk -F'"' 'NR>1{split($2,a,"queued_flows="); q=a[2]; if(q!=prev){print "  "$1" queued_flows="q; prev=q}}' \
    data/status_line_loaded.csv
echo
echo "  peak 3,084 flows, drained to 27 in 106 s = 28.8 flows/s"
echo "  — independently corroborates the 30.7 ms/flow Isolation Forest cost."
echo "  No flows were dropped for backpressure; the queue absorbed the backlog."

echo
echo "========================================================================"
echo "### Rule-path latency (spec §40 'rule-deployment latency')"
echo "    validation chain = real FirewallManager + FakeFirewallBackend"
echo "    nft timings      = real nft binary, read-only commands only"
echo "========================================================================"
cat data/rule_path_latency.json

echo
echo "========================================================================"
echo "### scripts/diagnostics/performance_smoke.py re-run on this Pi 4"
echo "    Same script, same Fake backends, same freshly-trained placeholder"
echo "    models as the dev-machine numbers in docs/PROGRESS.md Phase 9."
echo "========================================================================"
cat data/performance_smoke_pi.txt
cat <<'TXT'

  dev machine (x86_64 macOS) -> Raspberry Pi 4, same script:
    packet capture+parse        0.032 ->  0.089 ms   (2.8x slower)
    flow aggregation            0.041 ->  0.133 ms   (3.2x)
    feature extraction          0.016 ->  0.041 ms   (2.6x)
    LightGBM inference          0.089 ->  0.334 ms   (3.8x)
    Isolation Forest inference 12.068 -> 33.041 ms   (2.7x)
    threat assessment           0.022 ->  0.051 ms   (2.3x)
    rule deployment (Fake)      5.064 -> 18.675 ms   (3.7x)

  Real CICIDS2017 models vs placeholder, both on the Pi:
    LightGBM inference          0.334 ->  1.693 ms   (5.1x, 12-class v0.4.0)
    Isolation Forest inference 33.041 -> 30.695 ms   (0.93x — barely moved,
      confirming the cost is scikit-learn per-call overhead, not tree count)
TXT

cat <<'TXT'

========================================================================
### What this run did NOT measure
========================================================================
  - Real traffic. wlan0 had no associated stations: empty station dump,
    zero packets in 12 s of tcpdump, one packet in 31 min. Load was
    generated from the Pi as broadcast UDP on wlan0.
  - iperf3 between two LAN devices — there is no second device.
  - Throughput in bits/second. 802.11 broadcast caps at ~700 pps /
    ~0.8 Mbit/s regardless of sender count.
  - Real end-to-end nftables deployment (would mutate the live ruleset).
  - Detection accuracy. All 4,662 flows scored LOW -> ALLOW -> no
    candidate rule. Zero adaptive rules were created. Spec §34 attack lab
    remains outstanding.
  - A headless baseline. A desktop session and the driving CLI were
    running, so HOST cpu/memory are not a clean pirewall baseline; the
    per-process pirewall-core figures are.

========================================================================
END — see REPORT.md for interpretation, caveats and honesty labels.
========================================================================
TXT
} > results.txt 2>&1

echo "wrote $(wc -l < results.txt) lines to $(pwd)/results.txt"
