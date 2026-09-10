# Attack-lab benchmark — 2026-09-10

Real attack traffic run against the live Pi deployment, in **SHADOW** mode
throughout (nothing was ever blocked; every number below is what the
detection pipeline actually produced, not simulated).

## Setup

- **Attacker**: the Kali Admin PC (`sshuser@192.168.101.2` over `eth0` for
  control; `wlan0` joined to the `pirewall-lan` AP as `192.168.100.145` to
  generate traffic pirewall's capture interface (`wlan0` on the Pi) can
  actually see).
- **Target**: the Pi's own LAN address, `192.168.100.1` — the only host
  available this session; a genuinely separate dedicated test host was not
  available. Attacking the Pi's own real, currently-running services was a
  deliberate, explicit user decision made after being told the tradeoffs
  (shadow mode means nothing gets blocked, so the full attack load reaches
  the live stack).
- All traffic logged via `pirewall-core`'s real RPC socket
  (`list_flows`/`list_threats`/`list_detections`/`list_events`/
  `get_capture_stats`), the same interface `pirewall-api` uses — no
  fabricated numbers.
- Raw per-attack RPC snapshots and command output are the sibling files in
  this directory; `log.txt` has exact timestamps.

## Results

| # | Attack | Tool / method | Detected? | Patterns fired | Threat level reached |
|---|---|---|---|---|---|
| 1 | Port scan | `nmap -sS -p 1-1000` | **Yes** | `scanning`, `burst`, `high_frequency` | LOW (max 8.3/100) |
| 2 | SYN flood | `hping3 -S --flood` (~10,000 pkt/s, 15s, 149,735 sent) | **Yes** | `scanning`, `repeated_failures`, `slow_rate_dos` (100% of tracked flows) | LOW (max 33.3/100) |
| 3 | Slow brute-force login | 15x `POST /portal/login`, 2s apart, wrong password | **Yes — at the application layer** | portal's own login throttle fired (`authentication_failure` events, 5-minute lockout counting down correctly) | n/a — handled by the portal, not the adaptive pipeline |
| 4 | UDP DoS-style flood | `hping3 --udp --flood -p 53` (~8,900 pkt/s, 15s, 133,475 sent) | **Yes** | `scanning`, `repeated_failures`, `slow_rate_dos` | LOW (max 33.3/100) |
| 5 | Many small requests | 200 concurrent `curl` to `/portal/health` | **Yes** | `scanning`, `repeated_failures`, `slow_rate_dos`, `repeated_connections`, `burst`, `high_frequency` (all six, on ~90% of the 281 flows attributed to the source) | LOW (max 33.3/100) |

**Every attack type was detected as anomalous by the behavioral layer.**
None reached MEDIUM/HIGH/CRITICAL, and none would have triggered
RATE_LIMIT or BLOCK even in `active` enforcement — see finding 1 below.

## Findings (Observed, from this run)

1. **Every volumetric/flood-style attack detected here is scored no higher
   than LOW (max 33.3/100), never MEDIUM or above.** The ML model
   (`known_evidence`) does not recognize any of this traffic as an attack
   class either — LightGBM's `predicted_class` stayed `BENIGN` for the
   port scan even at 99.99% confidence. Detection here is carried entirely
   by the behavioral layer, correctly, but `pirewall/engine/scoring.py`'s
   current weighting never lets a behavior-only signal (no ML
   corroboration) reach a score that would act on it — meaning **a
   real, sustained SYN/UDP flood or port scan against this deployment
   would never be rate-limited or blocked even in `active` mode**, only
   ever logged. This is a materially different and arguably more
   important finding than the false-positive work in Step 2: it is a
   **false-negative** gap on the canonical attacks the paper's evaluation
   is supposed to measure. Not fixed this session — scope was Step 2's
   false-positive investigation; recorded as `KNOWN_ISSUES.md` #20 for a
   deliberate follow-up.

2. **`AFPacketCapture` drops the large majority of packets under a
   real flood on the Pi's actual hardware** (`KNOWN_ISSUES.md` #11,
   previously unverified): the SYN flood (~10,000 pkt/s) was captured at
   only `packets_seen=19,695` against `packets_dropped=297,595` over the
   run — roughly **94% dropped** at the kernel/`AF_PACKET` ring-buffer
   level before ever reaching the detection pipeline. The UDP flood showed
   the same shape (~77% dropped). The Pi's hardware is the bottleneck, not
   pirewall's own logic — but it means a flood large enough to matter is
   *also* large enough to blind most of what pirewall would otherwise see
   of it, which the detection results above still caught in what little
   got through.

3. **The bounded history buffers (500 entries each for flows/detections/
   threats) were fully evicted by each flood within seconds.** After the
   SYN flood, all 500 entries in every one of `list_flows`/
   `list_detections`/`list_threats` were flood traffic — the nmap scan's
   own detection records (Finding for attack #1, captured to this
   directory's `1-nmap-scan-state.json` before the flood) were gone from
   live state entirely by the time attack #2 finished. With Wazuh
   forwarding still broken this session (`KNOWN_ISSUES.md` #6), this
   means **a flood can erase the record of everything that happened
   immediately before it**, with no external copy surviving. Recorded as
   `KNOWN_ISSUES.md` #21.

4. **`capture_stats.packets_seen` update lag reproduced and confirmed**
   (`KNOWN_ISSUES.md` #14): querying immediately after attack #5 showed no
   change in `packets_seen`, then a re-query 3 seconds later showed it had
   advanced by 2,138. Confirms the existing "sampled on the metrics tick,
   not per-packet" hypothesis rather than a parse failure — #14 updated
   from "cause not established" to confirmed.

5. **The portal's own login-attempt throttle worked correctly** and
   independently of the adaptive pipeline — a real positive result, not
   just an absence of failure: 5-minute lockout, counted down accurately
   per `authentication_failure` event, well before the adaptive engine's
   own `REPEATED_FAILURES`/`repeated_connections_threshold` would have had
   reason to fire at this slow a rate (15 attempts over ~30s never crossed
   any adaptive-layer threshold on its own).

6. **The Pi's real stack stayed up and responsive throughout**, including
   through two back-to-back multi-thousand-packet-per-second floods —
   `pirewall-core`/`pirewall-api`/`pirewall-portal` all remained `active`,
   load average recovered within the observation window. No crash, no
   watchdog intervention needed (so item 11's "watchdog reaping a hung
   process" remains unverified — nothing hung).

## Not done this session

- **A genuinely separate dedicated test host** was not available; the Pi's
  own address was used as the target after an explicit user decision.
  TPR/FPR numbers above are against the Pi's own real production traffic
  mixed with attack traffic on the same box, not a clean target — a real
  dedicated host would give cleaner numbers.
- **`NftablesBackend` rule removal under contention** and **the watchdog
  reaping a hung process** (`KNOWN_ISSUES.md` #11's remaining items) —
  nothing in this session's traffic exercised either path; the daemon
  never hung and enforcement stayed in `shadow` throughout, so no rule was
  ever ephemeral enough to test removal-under-contention.
- **Batched Isolation Forest inference benchmark** on real Pi hardware
  (`benchmarks/2026-08-31-anomaly-batching/quick_benchmark.py`) — not run
  this session; timeboxed out in favor of the attack-lab and the primary
  false-positive investigation.
- Real end-to-end nftables rule-deployment latency, multi-client LAN load,
  power draw — lower-priority items explicitly marked "only if time
  allows"; not attempted.
