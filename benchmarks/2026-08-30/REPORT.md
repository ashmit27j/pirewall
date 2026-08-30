# pirewall — real-hardware performance benchmark

**Date:** 2026-08-30 · **Host:** Raspberry Pi 4 Model B Rev 1.5, 4 GB, 4× Cortex-A72
@ 1.8 GHz · Raspberry Pi OS (Linux 6.18.39+rpt-rpi-v8, aarch64) · Python 3.12.14

This is the spec §40 measurement that could only be done against
`FakePacketCapture`/`FakeFirewallBackend` until now. Everything below was
measured on this Pi, against the running `pirewall-core` service, with the real
`AF_PACKET` capture path and the real CICIDS2017-trained models
(LightGBM v0.4.0, Isolation Forest v0.2.0 — both `is_placeholder: false`).

**Nothing in pirewall's runtime code was modified.** The enforcement mode
(`assisted`) and the nftables ruleset were not touched. All observation is
read-only: RPC read operations, `/proc`, `systemctl show`, and an independent
`AF_PACKET` socket of the benchmark's own.

---

## 1. What was actually measured, and what could not be

Read this section before any number below it.

### The capture interface had no real traffic

The benchmark plan asked for "real traffic, not synthetic" and for iperf3
between two LAN devices. Neither was possible on this deployment as it stands:

* `capture.interface = wlan0`, the Pi's own AP for the protected LAN
  `192.168.100.0/24`.
* `iw dev wlan0 station dump` was **empty** — no stations associated.
  `ip neigh` showed only `FAILED`/`STALE` entries. A 12-second `tcpdump` on
  `wlan0` captured **zero packets**.
* Over a 31-minute idle window, `pirewall-core` saw **exactly one packet**
  (and it was non-IPv4).
* `eth0` — where the Admin PC (`192.168.101.2`) lives — is **DOWN**, so Wazuh
  and Netdata forwarding both fail continuously (see §7).

There is no second LAN device to run iperf3 against. So the idle phase is a
genuine zero-traffic baseline (still useful: it is the true resting cost of the
daemon), and load was generated from the Pi itself.

### How load was generated instead

`loadgen.py` sends UDP datagrams to the LAN broadcast address out of `wlan0`.
These are real frames on the real radio through the real driver, so the
daemon's real `AF_PACKET` socket sees them. Broadcast was chosen deliberately:
a unicast destination would have required an ARP entry for a host that does not
exist, i.e. editing the host's neighbour table, which this benchmark is not
allowed to do. Source/destination ports are varied so each step produces many
distinct 5-tuples and exercises flow-table insertion and eviction.

**Ceiling:** 802.11 broadcast is sent at a low basic rate, so the medium caps
out around **700 packets/s ≈ 0.8 Mbit/s** regardless of how many senders run.
The load ladder is therefore a *packet-rate and flow-rate* stressor, not a
bandwidth stressor. Every conclusion below is about per-packet and per-flow CPU
cost, which is what the pipeline is actually bound by — but **no statement
here should be read as a bits/second capacity figure.**

### Per-stage latency: how it was obtained

The running daemon exports only an aggregate `inference_latency_ms`; it has no
per-stage timing, and this benchmark may not add any. So `stage_latency.py` is
an independent observer process: it opens its **own** `AF_PACKET` socket on
`wlan0` (kernel packet sockets each get their own copy, so the daemon is
unaffected apart from CPU contention) and runs the same canonical modules in
the same order as `pirewall.runtime.pipeline.FlowPipeline`, timing each stage.

It stops at candidate generation. `FirewallManager` is never imported, so
nothing in it can validate, deploy, or propose a rule to a backend.

"End-to-end packet → decision" means **the sum of the CPU stages a packet must
pass through to yield a decision**, measured on the packet that completes the
flow. It deliberately excludes the flow's own lifetime — a flow is only
finalized after `flow.inactive_timeout_seconds` (60 s) of silence or a TCP
close, which is a configured dwell time, not latency.

### Contended versus uncontended

4,662 flows were measured. 662 completed while the load generator, the daemon
and the observer were all running (**contended**); 4,000 were finalized by
`FlowAggregator.flush()` after the capture window closed, on an otherwise quiet
machine (**uncontended**). Both are real measurements of the same code on the
same real flows, and both are reported separately — the uncontended figure is
the clean per-operation cost, the contended figure is what the pipeline
actually delivered while everything was running at once.

### Not measured

* **Real nftables rule-deployment latency.** Measuring it end to end requires
  inserting rules into the live ruleset. §5 decomposes it instead.
* **Detection accuracy.** Every flow in this run was benign broadcast traffic.
  This is a §40 performance benchmark; the §34 attack-lab exercise is a
  separate piece of work and remains **Environment-dependent**.
* **A headless baseline.** This Pi was running a full desktop session (labwc +
  terminal) and the Claude Code CLI that drove the benchmark. **Host-level**
  CPU/memory therefore do not describe a headless pirewall deployment. The
  **per-process** `pirewall-core` figures do, and those are what the report
  leads with.

---

## 2. Idle versus loaded — headline numbers

| | **Idle** (31 min) | **Loaded** (30 min) |
|---|---|---|
| Samples (5 s interval) | 372 | 360 |
| Packets seen by `pirewall-core` | **1** | **602,502** |
| Mean packet rate | ~0.0005 /s | 335 /s (peak step 697 /s) |
| Kernel packet drops | **0** | **5,050** (0.84 % of all packets; see §4) |
| `pirewall-core` CPU, mean | **0.30 %** of one core | **15.56 %** of one core |
| `pirewall-core` CPU, p95 / max | 0.80 % / 1.40 % | **99.60 % / 111.40 %** |
| `pirewall-core` RSS | **147.80 → 147.83 MB** (flat) | **147.83 → 168.78 MB** |
| `pirewall-api` RSS | 56.80 MB (flat) | 56.80 MB (flat) |
| Flows completed | 0 | 4,662 (observer) |
| Live flow table, max | 0 | **4,500** (observer's own aggregator) |
| Detection queue depth, max | 0 | **3,084 flows** |
| Adaptive rules created | 0 | **0** (see §6) |

CPU is percent of a **single** core; 400 % would be all four.

Idle cost is essentially nil — 0.3 % of one core and a completely flat RSS over
31 minutes. There is no idle leak and no idle busy-loop.

---

## 3. Latency per pipeline stage (spec §40)

Chart: `charts/latency_by_stage.png`. Raw data: `data/flow_stages_loaded.csv`,
`data/packet_stages_loaded.csv`, `data/stage_summary_loaded.json`.

All values in **milliseconds per operation**, real Pi 4, real models.

### Packet path — per packet (n = 586,125)

| stage | mean | p50 | p95 | max |
|---|---|---|---|---|
| packet parse | 0.0665 | 0.0408 | 0.1669 | 10.34 |
| flow aggregation | 0.0601 | 0.0421 | 0.1220 | 274.08 |

The 274 ms flow-aggregation maximum is one sample out of 586,125 and is **not**
an LRU eviction — the table peaked at 4,500 flows against a `max_flows` of
100,000, so no eviction ever ran. Most likely a GC pause or the scheduler
descheduling the thread, but this run does not distinguish those, so it is left
unattributed. The p95 of 0.12 ms is the figure to plan against.

### Flow path — per completed flow

| stage | uncontended mean | uncontended p50 | uncontended p95 | **contended mean** | **contended p95** |
|---|---|---|---|---|---|
| feature extraction | 0.092 | 0.082 | 0.124 | 0.132 | 0.284 |
| **LightGBM inference** | 1.693 | 1.472 | 2.966 | 2.538 | 5.763 |
| **Isolation Forest inference** | **30.695** | **29.780** | **38.898** | **56.934** | **122.737** |
| behavior analysis | 0.732 | 0.701 | 0.894 | 0.979 | 1.467 |
| threat assessment | 0.184 | 0.163 | 0.246 | 0.262 | 0.562 |
| decision | 0.055 | 0.050 | 0.065 | 0.073 | 0.140 |
| candidate generation | 0.004 | 0.003 | 0.005 | 0.005 | 0.011 |
| **END-TO-END packet → decision** | **33.454** | **32.422** | **42.059** | **60.922** | **130.422** |
| | n = 4,000 | | | n = 662 | |

**Isolation Forest is 92 % of the end-to-end cost.** Everything else in the
pipeline put together — parse, aggregation, feature extraction, LightGBM,
behavior analysis, scoring, decision, candidate generation — comes to about
2.7 ms. The single `IsolationForest.decision_function` call per flow is
30.7 ms.

That caps the flow path at **≈ 30 decisions/second** on this hardware, and the
drain measurement in §4 confirms it independently: the daemon cleared a
3,084-flow backlog in 106 s, i.e. **28.8 flows/s**.

---

## 4. Packet drops — the one real failure mode found

Chart: `charts/packet_drop_rate.png`.

Across both phases, `pirewall-core` dropped packets in exactly **two 15-second
intervals**, both inside the `max-pps-2000-flows` step:

| daemon tick | step | packets in tick | dropped | drop rate |
|---|---|---|---|---|
| 23.75 min | 06-max-pps-2000-flows | 6,253 | **771** | **12.3 %** |
| 24.00 min | 06-max-pps-2000-flows | 11,122 | **4,279** | **38.5 %** |
| every other tick, both phases | — | — | **0** | **0 %** |

The mechanism is visible in the other series: at that moment
`pirewall-core`'s CPU hit **111 %** of a core, its detection queue reached
**3,084 flows**, and its RSS jumped from 150 MB to 159 MB. 2,000 concurrent
flows began completing faster than Isolation Forest could score them; the
detection thread saturated a core; the capture socket's receive buffer
overflowed and the kernel discarded packets.

**The capture path itself is not the bottleneck.** At 697 packets/s with only
20 concurrent flows, the daemon used 8.7 % of a core and dropped nothing.
Drops appeared only when the *flow* path backed up.

### A defect found while measuring this

`CaptureStatistics.packets_dropped` is **not a cumulative counter**, but it is
used as one. `AFPacketCapture._read_kernel_drops()` reads it with
`getsockopt(SOL_PACKET, PACKET_STATISTICS)`, and the kernel **zeroes
`tp_drops` on every read**. Each 15 s daemon tick therefore reports only the
drops since the previous tick, and the value can and does go *down*.

Consequences:

* `NetdataMetricsSnapshot.packet_drops` (spec §33/§41) is exported as
  `pirewall.packet_drops`, which reads as a lifetime total but is actually a
  per-15 s delta. Any dashboard differencing it as a counter will produce
  negative rates.
* This benchmark's own first pass computed drops by differencing and got a
  nonsense answer. The corrected figures above sum each tick's reading.

This is a genuine bug in the observability surface, not a measurement
artifact. It is **reported, not fixed** — this run is observation-only.

---

## 5. Rule-path latency (spec §40 "rule-deployment latency")

Measuring real deployment end to end means inserting rules into the live
ruleset, which was out of scope. The path was measured in its two real pieces
instead (`data/rule_path_latency.json`):

| measurement | mean | p50 | p95 | notes |
|---|---|---|---|---|
| Full 10-stage validation chain + deploy call, **Fake** backend | **0.220 ms** | 0.185 | 0.379 | 200 accepted candidates; real `FirewallManager`, real config, real validation |
| `nft -j list chain inet pirewall adaptive` (**real** binary, read-only) | **7.381 ms** | 6.702 | 10.498 | `_list_ruleset()`; every apply/remove performs this for handle lookup |
| `nft -j list tables` (**real** binary, read-only) | **9.885 ms** | 9.388 | 12.255 | `health_check()` |

So a real deployment on this Pi costs roughly **0.2 ms of pirewall logic plus
7–20 ms of `nft` subprocess round-trips** — the validation chain is free by
comparison, and the cost is dominated by forking `nft`. Treat that as a bound,
not a measurement.

A fresh `FirewallManager` was used every 20 candidates so each one was measured
on the accepted path rather than short-circuited by the A3 rate cap
(`max_adaptive_rules_per_window = 20`). Candidates used TEST-NET-3
(203.0.113.0/24) sources so they pass safety validation rather than
short-circuit it.

**Not re-measured:** the Phase 9 observation that deployment slows as
`active_rules()` grows (O(n) conflict/duplicate/priority checks). Reaching a
large active-rule count through the real rate cap takes far longer than this
session allowed.

---

## 6. Flow table, and what the pipeline concluded

Chart: `charts/flow_table_over_time.png`.

Live table size peaked at **4,500 open flows** during `max-pps-2000-flows`
(observer's own `FlowAggregator`, `max_flows = 100000`, so nowhere near the
cap). RSS tracked it: 147.8 MB idle → 168.8 MB at peak, i.e. roughly **4.7 kB
of RSS per open flow** including everything downstream of it.

Every one of the 4,662 completed flows was scored **LOW** (mean threat score
35.5, max 40.6), so the decision ladder returned **ALLOW**, and
`generate_candidate_rule` correctly returned `None` for all of them.
**Zero candidate rules were generated and zero rules were created**, which
matches `active_rule_count = 0` reported by the daemon throughout. The one
pre-existing monitor rule expired on its own TTL during the idle phase.

This means the load did not exercise the validation chain in the live daemon.
Worth noting for anyone repeating this: the generated traffic's source is
`192.168.100.1`, which is `network.pirewall_lan_ip`, so had any flow scored
high enough to generate a candidate, the safety stage would have rejected it
outright (spec §24) — the run could not have created a rule even in principle.

### A second observability gap found

`StatusResult.tracked_flow_count` **is not the live flow table.** The
dispatcher computes it as `len(self._state.flows)` — the bounded ring buffer of
*recently completed* flows, capped at `api.history_size` (500). During this run
it rose to 500 and saturated there while the actual table held 4,500 flows.

The live figure *is* computed — `CoreDaemon._tick()` does
`active_flows = len(self._aggregator)` — but it is passed only to the Netdata
snapshot, which on this deployment cannot be delivered (§7). So on a Pi without
a reachable Netdata, **the live flow-table size is not observable at all**,
which spec §41 explicitly requires ("active flows"). That is why this report's
flow-table numbers come from the observer's own aggregator.

Also reported, not fixed.

---

## 7. Operational observations

* **Netdata export fails every 15 s.** `integration.netdata_host` is
  `192.168.101.2` on `eth0`, which is down: `[Errno 101] Network is
  unreachable`, one `WARNING` per tick, forever. Every metric in §41 that only
  reaches Netdata — live flow count, flow creation/expiration rate,
  backpressure drops, inference latency — is therefore unobservable on this
  deployment. Same for Wazuh (`[Errno 111] Connection refused`).
* **`queued_flows` in the systemd status line is the only backpressure signal
  available**, and it worked: it showed the 3,084-flow peak and the drain. It
  is not exposed over RPC.
* **No flows were dropped for backpressure** — the queue absorbed the entire
  3,084-flow backlog without a single `flows_dropped_for_backpressure`. Nothing
  in the journal for the whole window except the Netdata warnings.
* **RPC read latency** under load: mean 55 ms, p95 220 ms, max 727 ms
  (`list_flows` + `list_detections` serialize up to 500 Pydantic models per
  call). At idle: mean 29 ms, p95 105 ms.

---

## 8. Simulated versus real — the gap

### Same script, same Fake backends, same placeholder models

`scripts/diagnostics/performance_smoke.py` re-run unmodified on this Pi
(`data/performance_smoke_pi.txt`), against the dev-machine numbers recorded in
`docs/PROGRESS.md` Phase 9. This is the apples-to-apples comparison — identical
code, identical synthetic workload, identical freshly-trained placeholder
models:

| stage | dev machine (x86_64 macOS) | **Raspberry Pi 4** | Pi is slower by |
|---|---|---|---|
| packet capture + parse | 0.032 ms | **0.089 ms** | **2.8×** |
| flow aggregation | 0.041 ms | **0.133 ms** | **3.2×** |
| feature extraction | 0.016 ms | **0.041 ms** | **2.6×** |
| LightGBM inference | 0.089 ms | **0.334 ms** | **3.8×** |
| Isolation Forest inference | 12.068 ms | **33.041 ms** | **2.7×** |
| threat assessment | 0.022 ms | **0.051 ms** | **2.3×** |
| rule deployment (Fake backend) | 5.064 ms | **18.675 ms** | **3.7×** |

**The Pi 4 is a consistent 2.3–3.8× slower than the dev machine.** No stage
behaves qualitatively differently; nothing fell off a cliff.

### The predictions in PROGRESS.md, checked

| prior claim (`docs/PROGRESS.md`) | measured on the Pi | verdict |
|---|---|---|
| Isolation Forest "plausibly **10–20 flows/s** on a Pi 4's Cortex-A72" | **30.3 flows/s** (placeholder model), **32.6 flows/s** (real v0.2.0 model, uncontended) | **Pessimistic by ~1.6×, but the right order of magnitude and the right conclusion** |
| "Isolation Forest inference is the clear bottleneck" | 92 % of end-to-end cost | **Confirmed, and worse in relative terms than on x86** |
| "rule deployment slows as `active_rules()` grows" | not re-measured | still open |
| Flow table at `max_flows=100000` ≈ 93 MiB | not reached (peak 4,500 flows); measured **~4.7 kB RSS per open flow**, consistent with the ~979 B/flow flow-state estimate plus downstream buffers | consistent, not contradicted |

### Real models versus placeholder models

The real CICIDS2017 artifacts are more expensive than the placeholders the
smoke script trains, so the two must not be mixed:

| stage | placeholder model, Pi | **real model, Pi** | ratio |
|---|---|---|---|
| LightGBM inference | 0.334 ms | **1.693 ms** | 5.1× (12-class v0.4.0 booster) |
| Isolation Forest inference | 33.041 ms | **30.695 ms** | 0.93× (both 100 trees; per-call overhead dominates, not tree count) |

This is the single most useful corroboration in the run: Isolation Forest's
cost is **almost entirely scikit-learn's fixed per-call overhead**, exactly as
the audit pass concluded on x86. Changing the model barely moved it. Only
batching will.

---

## 9. Conclusions

1. **Packet capture and the packet path are not a problem on a Pi 4.** 700
   packets/s cost 8.7 % of one core with zero drops. Parse is 0.041 ms/packet
   and flow aggregation 0.042 ms/packet at the median.
2. **The flow path is capped at ~30 decisions/second**, and Isolation Forest is
   92 % of it. Two independent measurements agree: 30.7 ms/flow measured
   directly, and 28.8 flows/s measured from the backlog drain rate.
3. **Exceeding that cap causes real packet loss**, not just delay. Once the
   detection queue backed up, the daemon saturated a core and the kernel
   dropped 38.5 % of packets in a 15 s window. This is the first time that
   failure mode has been observed rather than predicted.
4. **Memory is comfortable.** 147.8 MB idle, 168.8 MB at 4,500 concurrent
   flows, against `MemoryMax=768M`. RSS is flat at idle over 31 minutes.
5. **The `MEDIUM`/`HIGH` question is untouched.** Every flow here was benign.
   Detection accuracy still needs the §34 attack lab.
6. **Two observability defects were found**, both in spec §41 territory:
   `packets_dropped` is a per-interval value used as a counter, and the live
   flow-table size is not exposed anywhere reachable on this deployment.

### Recommended next steps, in order

1. **Fix `packets_dropped`.** `AFPacketCapture` should accumulate into a
   running total rather than returning the kernel's self-clearing delta.
   Small, self-contained, and it makes the §41 drop metric trustworthy.
2. **Expose live flow-table size over RPC.** `CoreDaemon._tick()` already
   computes it; it just needs to reach `CoreStateStore` so `get_status` can
   report it. Rename or replace `tracked_flow_count`, whose current meaning
   contradicts its name.
3. **Batch Isolation Forest inference.** This is the one change that moves the
   throughput ceiling, and the measurements now justify it with real numbers:
   ~30 flows/s single-call versus a per-flow cost dominated by fixed overhead.
   This is the design work `docs/PROGRESS.md` already flagged; it is no longer
   speculative.
4. **Then re-run this benchmark** — the scripts are checked in and take about
   an hour end to end.

Until (3), a household busier than ~30 concurrent flow completions per second
will queue, and past a few thousand queued flows it will drop packets. In
`SHADOW`/`ASSISTED` mode that delays observation without failing open on
enforcement, which is the mitigation `ADDENDUM.md` A1 was written for.

---

## 10. Files

```
benchmarks/2026-08-30/
├── REPORT.md                      this file
├── results.txt                    every measured number as plain text
├── make_results.sh                regenerates results.txt
├── collect_runtime.py             read-only observer of the running daemon
├── stage_latency.py               independent per-stage latency harness
├── rule_path_latency.py           validation chain + real read-only nft timing
├── loadgen.py                     broadcast UDP load generator
├── run_load_phase.sh              the load ladder
├── sample_status_line.sh          queue-depth sampler
├── analyze.py                     charts + tables (separate matplotlib venv)
├── charts/
│   ├── latency_by_stage.png
│   ├── cpu_memory_over_time.png
│   ├── packet_drop_rate.png
│   ├── throughput_vs_latency.png
│   └── flow_table_over_time.png
└── data/
    ├── runtime_idle.csv           372 samples, 31 min
    ├── runtime_loaded.csv         360 samples, 30 min
    ├── packet_stages_{idle,loaded}.csv    per-packet parse/aggregation timings
    ├── flow_stages_{idle,loaded}.csv      per-flow, per-stage timings + verdicts
    ├── flowtable_{idle,loaded}.csv        live flow-table size over time
    ├── stage_summary_{idle,loaded}.json   percentiles per stage
    ├── status_line_loaded.csv     queue depth over time
    ├── load_steps.json            step schedule with timestamps
    ├── load_step_results.json     per-step throughput/latency
    ├── per_step_daemon.json       per-step daemon CPU/RSS/packets/drops
    ├── rule_path_latency.json     §5 measurements
    ├── performance_smoke_pi.txt   Phase 9 script, re-run on this Pi
    ├── journal_loaded.txt         pirewall-core journal for the loaded window
    ├── environment_pre.txt        pre-run host/ruleset state
    └── host_context.txt           desktop-session caveat
```

`analyze.py` needs matplotlib, which is deliberately **not** added to
pirewall's dependencies (`CLAUDE.md`); it was installed into a separate
throwaway virtualenv.

**Note on version control:** the repository's `.gitignore` has a blanket
`data/` rule (there to keep raw datasets out), which also matches
`benchmarks/2026-08-30/data/`. The scripts, charts and this report are
trackable; the raw CSV/JSON is not, unless an explicit negation is added.
`packet_stages_loaded.csv` is 12.5 MB (586,125 rows), so that may well be the
right default — but it is a side effect of a rule written for something else,
not a decision anyone made about benchmark data. Left as-is; nothing was
committed.

---

## 11. Honesty labels (`CLAUDE.md`)

| item | label |
|---|---|
| Idle and loaded daemon metrics (CPU, RSS, packets, drops, queue depth) | **Tested** — measured on real Pi 4 hardware against the running service |
| Per-stage pipeline latency, real models | **Tested** — real `AF_PACKET` capture, real artifacts, 4,662 flows |
| Packet-drop failure mode under flow backlog | **Tested** — observed twice, with corroborating CPU and queue-depth series |
| Dev-machine versus Pi comparison | **Tested** — same script re-run unmodified on the Pi |
| Validation-chain latency | **Mocked** — real validation code, `FakeFirewallBackend` |
| `nft` round-trip latency | **Tested** — real `nft` binary, read-only commands |
| Real end-to-end nftables rule deployment | **Not measured** — requires mutating the live ruleset |
| Throughput as bits/second | **Not measured** — 802.11 broadcast caps at ~0.8 Mbit/s |
| Behaviour under genuine multi-host LAN traffic | **Environment-dependent** — no stations were associated to `wlan0` |
| Detection accuracy | **Environment-dependent** — spec §34 attack lab, unchanged by this run |
| Host-level CPU/memory as a headless baseline | **Not valid** — a desktop session was running; use the per-process figures |
