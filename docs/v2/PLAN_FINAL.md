# Pirewall v2: final plan (v2 of the plan, after two critique rounds)

**How this plan was produced.** Draft v0 went to four independent critics: a red team, an ML-methodology reviewer, a Pi systems/feasibility engineer and a safety/experiment-design reviewer. The resulting synthesis (v1) then went through a round-2 contradiction review, and a builder agent implemented the nftables data plane and tested it with real traffic in network namespaces.

**Supporting evidence**, all in `/home/claude/plan/`:
- `critique_*.md` (the five critiques)
- `v2/RESULTS.md` (18/19 ruleset behaviours pass with real traffic; IPv6 can't be tested in the sandbox)
- `v2/*.nft.template`, `v2/netns_testbed.sh` and `v2/test_ruleset.py`

**Labels:** [V] verified in the sandbox, [R] reasoned, [P] must be confirmed on the Pi.

---

## 1. Facts that drive the design

1. **The onboard Wi-Fi bridges client↔client frames in firmware.** BCM43455/brcmfmac does this and ignores `ap_isolate` (RaspAP docs) [R/P]. v2 therefore covers client→Internet and client→Pi only. Covering client↔client would need a mac80211 USB adapter with isolation and a proxy-ARP hairpin.
2. **nft dynamic meters fail open when full** [V]. `ct state new` meters miss floods to services that reply [V]. The kernel reassembles fragments before priority raw, so a fragment rule needs priority -450 [V]. The meter burst is part of the threshold: a 3 s flood fit entirely inside a 40k-packet burst [V].
3. **NFStream:**
   - Flows end only on idle/active timeouts, never on FIN/RST. A flow is emitted about `idle_timeout` after its last packet [V].
   - `accounting_mode=1` gives IP-length bytes, and its features are identical at snaplen 128 and full snaplen [V].
   - Throughput is about 64–71k pps per process on a Xeon; the Pi 4 estimate is 12–18k [P].
   - The current systemd seccomp filter crashes it through a `sched_setaffinity` error-path bug [V].
   - It pulls in numpy and pandas.
4. **python3-nftables works from the uv Python 3.12 venv.** It is ctypes calling libnftables. Adding an element takes 0.36 ms against 10.2 ms through a subprocess [V].
5. **The AP is a NetworkManager shared-mode hotspot.** That means wpa_supplicant's AP mode, an NM-spawned dnsmasq with a 50-lease cap, and NM's own table `inet nm-shared-<if>` (forward at prio 0, nat at 100). Our chains at raw/-299/-5 run first and don't conflict [R].
6. **Debian's `nftables.service` runs `flush ruleset`** and would wipe every table [R/P].
7. **Config models are `extra="forbid"`, and rules and allowlist entries are IP-only** [V]. Every change must therefore be additive.
8. **Public datasets can't be downloaded from the sandbox.** CIC-IoT2023 (about 548 GB) is cut. CIC-IDS2017 Friday (8.3 GB) can serve as an external test only, if the user downloads it.

## 2. Scope statement (README and paper, verbatim)

> Pirewall v2 is a host-level adaptive defence for a single Raspberry Pi 4 acting as a Wi-Fi access point for a small LAN. It mitigates volumetric floods, port scans and brute-force attempts **originating from LAN clients toward the Internet or the Pi**, and blocks IP and ARP spoofing of other LAN clients. It uses static in-kernel nftables guards plus adaptive per-device sets driven by deterministic and ML evidence.
>
> It does not inspect payloads or see inside encrypted traffic. It does not see client↔client traffic on the onboard radio. It does not defend against RF-layer attacks (jamming, deauthentication, evil twin; 802.11w PMF only mitigates) or MAC cloning by a PSK holder. It is IPv4-only (IPv6 is dropped on the LAN), and it cannot restore Wi-Fi airtime.
>
> The ML components were trained on a short capture of one network, and their false-positive bounds may not transfer. All results come from N scripted runs on real hardware, with manifests.

## 3. Goals and acceptance (measured on the Pi by the harness)

- **G1 Floods.** SYN/UDP/ICMP floods, fixed-source and random-source, from one LAN client at the Pi and through it. Victim-side TTM ≤ 2 s. Admin API p95 < 1 s during the flood.
- **G2 Scans.** nmap -sS T4/T3 at the Pi is caught by the kernel closed-port meter in ≤ 2 s. Scans through the Pi are blocked at device level in ≤ idle_timeout + 5 s. T2 is detected (MONITOR) in ≤ 120 s.
- **G3 Brute force.** SSH/HTTP brute force against a WAN-side victim, and portal brute force, are detected and get RATE_LIMIT.
- **G4 Spoofing.** Spoofing a bound neighbour's IP, and ARP poisoning, are dropped. The neighbour never appears in any set.
- **G5 Benign cost.** 0 enforce actions over T clean benign device-hours (upper bound 3/T), and MONITOR ≤ 1 per device-hour. Measured offline over all clean hours with D1/D2/D3 plus a kernel-meter simulator, and live during the held-out window.
- **G6 Crash resilience.** After `kill -9` of core or the sensor, the guards and existing elements keep working. A restart causes no LAN outage.
- **G7 Traceability.** Every paper number comes from `lab/aggregate.py` over hashed manifests. Sandbox results are never mixed with Pi results.
- **G8 Baseline.** v1 is measured on the same harness: it stays runnable as `pipeline.engine="v1"`.

## 4. Architecture

### 4.1 Processes
- **`pirewall-sensor` (new).**
  - Runs NFStream on the LAN interface.
  - Holds only CAP_NET_RAW, with seccomp that allows the affinity syscalls, `MemoryMax` ≥ 500M and `n_meters=2`.
  - Its only output is a write-only unix socket carrying `FlowRecordV2` frames to core.
  - It restarts freely: a crash costs visibility, not enforcement. nDPI is the sensor's only C parser, so a parser bug can't reach CAP_NET_ADMIN.
- **`pirewall-core`.**
  - Holds CAP_NET_ADMIN and does no packet parsing.
  - Polls the kernel every second for offender sets, counters, set fill levels and table existence.
  - Runs lease sync as an internal thread: inotify plus a 2 s poll, strict regexes on MAC/IP/expiry only, hostnames ignored.
  - Runs D1/D2/D3, the policy engine, validator v2 and FirewallManager, writing through libnftables (fallback: one batched `nft -j -f -` per tick).
  - Pollers serve snapshots outside the single RPC lock.
- **`pirewall-api` and `pirewall-portal`:** as in v1, with the A4/C1 split preserved.

### 4.2 Kernel data plane (built and tested: `plan/v2/*.nft.template`)
- **`table inet pirewall_static`** comes from a template and is reviewed and loaded by `pirewall-start`. Reloading flushes chains, never the table. Core may write exactly one thing in it: the contents of the `guard_verdict_*` chains (drop or empty), through `FirewallManager.set_guard_mode`. Panic is the only other way to change it. A test diffs the ruleset before and after every core operation.
  - **`frag_guard`** (prio -450): LAN fragments dropped.
  - **`prerouting_raw`** (prio raw, `iifname LAN`), in order:
    1. Drop IPv6.
    2. Per-MAC DHCP brake, then exempt DHCP and multicast/broadcast.
    3. Drop LAN packets claiming any Pi address (`@pi_addrs`).
    4. Reverse-path and subnet check.
    5. Bound IP whose IP.MAC doesn't match → drop.
    6. Unbound source → tight meter class plus `@unbound_seen`.
    7. `allow_bound` (MAC.IP) → return.
    8. Stateless per-MAC SYN/UDP/ICMP/total-pps meters → `@offenders`.
    9. Keyless global backstops.

    Steps 4–9 jump to `guard_verdict_raw`, so anti-spoof has a real observe mode.
  - **`input_guard`** meters DNS qps per MAC, closed-port hits per MAC (fast scans of the Pi), and `ct count` concurrency on the portal and API ports.
  - **`forward_guard`** meters new connections per MAC and per (MAC, daddr), and drops LAN→WAN 53/853 that doesn't go through the Pi.
  - **An ARP anti-poisoning table** checks `arp saddr ip . arp saddr ether` against `@macbind`.
  - **Rate and burst are calibrated together:** burst ≈ 1–2 s of the rate.
  - **Meter-set membership is not evidence.** Only `@offenders` is.
- **`table inet pirewall_adaptive`** (prerouting -299, right after anti-spoof and before conntrack). Only FirewallManager writes its sets: `block_mac`, `block4`, `ratelimit_mac` (new-connection rate plus a generous byte cap), `allow_bound` and `pi_addrs`.
  - Before any block rule it exempts DHCP, DNS and the portal ports, so blocked devices still renew their lease and see the C4 block notice.
  - It has **no `@infra4` source accept**. Infra protection lives in the validator and in `ip daddr` exemptions.
  - Every element carries a timeout ≤ 3600 s.
- **Base fixes:** the admin rule becomes `iifname eth0 ether saddr <admin MAC> ip saddr <admin IP>`, DNS accepts are pinned to the LAN interface, and the portal `authed` set becomes `ipv4_addr . ether_addr`.
- **Guard defaults:**
  - Input: enforce.
  - Raw anti-spoof: enforce **only if bindings were seeded**, otherwise observe.
  - Forward: observe until the offline G5 check passes.
- **Safety nets:**
  - Preflight refuses to run if `nftables.service` is enabled with `flush ruleset`.
  - Core checks every second that the tables still exist. On loss it raises CRITICAL and triggers a re-render.
  - A set over 80% full raises an alert. A failed add is CRITICAL and falls back to a coarser action.

### 4.3 Identity model (additive migration, done first)
- **`RuleTarget{ip, mac|None}`** is added to the rule models, optional, so v1 tests keep passing.
- **`BindingTable`** (leases plus `[[antispoof.static]]`) resolves IP↔MAC.
- **Lookups:** `blocking_rules_matching(ip)` resolves IP to MAC.
- **Portal sessions** store `(ip, mac)`.
- **Allowlist entries** gain an optional MAC; `allow_bound` is rendered from entries that have both IP and MAC.
- **The validator safety stage** checks both IP and MAC.

### 4.4 Sensor and features (schema v2, frozen at H28)
- **Exporter config:** `NFStreamer(idle_timeout=10, active_timeout=10, accounting_mode=1, snapshot_length=1536, statistical_analysis=True, splt_analysis=8, n_dissections=20, n_meters=2)`.
  - One shared config object is used by both the sensor and `scripts/dataset/pcap_to_flows.py`.
  - `idle_timeout=5` is a variant, but only if it's also used for training.
- **Model features exclude** IP, MAC, OUI, raw ports, SNI, app names and timestamps. The destination port becomes a coarse category, with an ablation run with and without it.
- **A connection start** is a record with `src2dst_syn_packets > 0` and no earlier record for the same 5-tuple. D1 counts connection starts, not records.

### 4.5 Detection tiers
- **K (kernel).** Evidence is `KERNEL_GUARD{code, mac, guard_mode, sustained_polls}`.
- **D1 (deterministic; the only tier allowed to act, besides K).** Runs per MAC over 10 s, 60 s and 1 h windows:
  - Vertical and horizontal scans.
  - Failed-handshake ratio.
  - Brute force: many short, similar flows to one dst:port.
  - Slow-rate DoS: concurrent long, low-rate connections to one destination (ported from v1).
  - Fan-in per destination.
  - New-MAC and new-lease rate (MAC churn and lease starvation).
  - Portal auth failures, per account and global.

  Thresholds = clamp(benign P99.9 × margin, floor, hard ceiling), and thresholds hot-reload from config.
- **D2: Isolation Forest (MONITOR only).** Trained on our own benign training block; threshold at a validation per-flow FPR of 1e-3.
- **D3: LightGBM, binary plus a coarse family head (MONITOR or corroboration only).**
  - Rows capped per run, connection-grouped splits.
  - Isotonic calibration; the operating point is set by benign FPR.
  - Shortcut audit before any number is reported.

### 4.6 Policy engine (the table is data, with an exhaustive test matrix)

| Evidence | SHADOW | ASSISTED | ACTIVE |
|---|---|---|---|
| K offender from an *observe* guard | log | MONITOR | MONITOR |
| K offender from an *enforce* guard, sustained ≥ 2 polls | log | RATE_LIMIT mac 5 min | RATE_LIMIT mac 5 min |
| D1 high-certainty (fast scan, brute force) | log | RATE_LIMIT; BLOCK goes to the approval queue | BLOCK mac 5 min |
| D1 + K, or D1 repeated with **new independent** evidence | log | BLOCK goes to approval | BLOCK, TTL ×2 (cap 1 h) |
| D2 or D3 alone, or D2 + D3 | log | MONITOR | MONITOR |
| D2/D3 + D1 | log | RATE_LIMIT | RATE_LIMIT |

**Invariants, enforced by tests:**
- ML-only or anomaly-only evidence ⇒ at most MONITOR.
- Allowlisted or infra targets ⇒ never acted on.
- Each adaptive set has exactly one writer.
- No verdict rule reads `@offenders`.
- Escalation requires new evidence.

**Validator order:** schema → network → allowlist → safety (infra, admin MAC, Pi/gateway, non-unicast) → conflict (block ⊃ ratelimit; an upgrade is one atomic delete+add) → duplicate → rate-cap (counts element insertions) → escalation → expiration (timeout ≤ 3600 s) → authorization.

**Compatibility:** `PolicyDecision` maps to `threat_level` so the dashboard and API keep working.

### 4.7 Kill switch, panic and failure
- **Kill switch:** SHADOW, flush the adaptive sets, all three guard verdict chains set to observe, audit entry.
- **Panic:** delete both pirewall tables, over RPC or with a documented console one-liner.
- **Clean fail-open shutdown:** flush the adaptive sets only.
- **Crash:** elements expire by TTL.
- **Restart:** reconcile with live set contents; never recreate tables.
- **Sensor down or capture drop above X%:** SYSTEM_WARNING. The kernel tier keeps enforcing on its own.

### 4.8 What happens to v1 features
| v1 feature | v2 status |
|---|---|
| Heartbleed and JA3 detectors | Dropped (stated in ADDENDUM_4 and the paper); JA4 kept as log context |
| `TEMPORAL_PATTERN` / `PERSISTENCE` | Dropped, or MONITOR if time allows |
| `SLOW_RATE_DOS` | Ported into D1 |
| Netdata gauges | Re-sourced from sensor stats and nft counters |
| Wazuh decoder | Written for the v2 event JSON |
| v1 pipeline | Kept behind `pipeline.engine="v1"`, for the baseline |

### 4.9 Access and hygiene (P0)
- Delete the demo portal accounts.
- Throttle admin login per IP and globally; throttle the portal per account and globally.
- Allowlist additions through the API need the password again and must be MAC+IP.
- Fix the API log directory, the cert SANs and `session_timeout_seconds`.
- PMF: 30-minute timebox with `nmcli … 802-11-wireless-security.pmf required` (fall back to `optional`).
- Startup self-checks: IPv6 off on the LAN, bindings seeded, set fill, `nftables.service`.
- Raise the dnsmasq lease cap and use a shorter lease for unknown MACs through `dnsmasq-shared.d` [P].
- Config is additive only; `migrate_config.py` handles the rest.
- Record the new dependencies (nfstream, numpy, pandas, python3-nftables) in ARCHITECTURE.md.

## 5. Data and evaluation protocol
- **Benign capture.** `tcpdump -ni wlan0 -s 128 -G 3600 -w /mnt/ssd/benign-%Y%m%d%H.pcap` from H0, with a disk watchdog and household consent. pcaps are never committed. Lab MAC/time windows come out via `ground_truth.jsonl`.
- **Lab topology.**
  - Attacker: Kali on wlan0, with a dedicated MAC.
  - Victim A: the Pi itself (input path).
  - Victim B: a WAN-side host on the upstream LAN (forward path) running sshd, nginx and an iperf3 server.
  - A legitimate wired client and a legitimate Wi-Fi client, to measure collateral damage.
  - chrony on every host.
- **Campaigns.** N=5 for floods and scans, N=3 otherwise, in random order, with cooldown until the sets are empty:
  - SYN/UDP/ICMP floods: fixed source, `--rand-source`, and spoofing a neighbour.
  - nmap -sS T4/T3/T2, and masscan or rustscan as a held-out tool.
  - hydra against SSH and HTTP; portal brute force.
  - slowloris.
  - Meter-fill and MAC churn.
  - An established-flow flood against :53 and :8080.
  - Framing a neighbour; ARP poisoning.
- **Splits.**
  - Benign: temporal 60/15/≥1 h gap/25.
  - Attacks: split by run ID, leave-one-tool-out, parameter variants held out.
  - CIC-IDS2017 Friday as an external test only.
  - Each test set is touched once, with its hash logged.
- **Metrics.**
  - TTD.
  - TTM, measured victim-side.
  - Mitigation effectiveness.
  - Collateral damage (wired and Wi-Fi separately).
  - FP per device-hour with a Poisson CI or the rule of three.
  - Pi CPU, RSS and drops versus pps.
  - ML: PR-AUC, recall at FPR 1e-3/1e-4, expected alerts per day, reliability diagram, PSI drift.
  - Baselines: v1, and the ablation kernel-only → +D1 → +D2 → +D3.
- **Harness.** `lab/preflight.py`, `run_campaign.py`, `attacks/*.sh`, `benign/background.py`, `poll_state.py`, `capture.sh`, `score_run.py`, `benign_fp.py` (offline, with the kernel-meter simulator), `aggregate.py` and `verify_manifest.py`. Manifests record the git SHA, config, model and ruleset hashes, `pipeline.engine`, the enforcement and guard modes, tool versions and clock offsets.
- **Paper.** Tables I–VII and Figs 1–5 as in `critique_ml.md` §10, plus a threats-to-validity section mapped to Arp P1–P10.

## 6. Test tiers in the sandbox
- **U (unit):** policy matrix, set-semantics fake, validator v2, contracts.
- **N (netns, real nft):** the 19 assertions in `v2/test_ruleset.py`, plus core-in-the-loop versions (block notice reachable, restart with no outage, ruleset-diff invariant).
- **R (replay):** tcpreplay of Pi pcaps, for regression only.

## 7. Delivery in three increments
- **v2.0, by about H10:** contracts, identity migration, set backend, static and adaptive tables, lease sync, kill switch and panic, P0 fixes. Driven by the **v1 pipeline** through an adapter. This tests G1, G4 and G6 on the Pi.
- **v2.1, by about H22:** sensor, D1, policy engine, harness, offline G5 tooling.
- **v2.2, by about H30 (cuttable):** D2/D3 training and evaluation, ablation.
- **H30–42:** evaluation campaigns, aggregation, docs (ADDENDUM_4, KNOWN_ISSUES v2, SETUP v2), paper tables.

**Work packages** run as parallel agents in separate git worktrees, against `docs/V2_CONTRACTS.md` plus typed stubs frozen at H1. Only the integrator (me) edits `runtime/core.py`, `firewall/manager.py` and `ipc/dispatcher.py`.
- **WP-K:** kernel plane, backend, validator v2.
- **WP-S:** sensor and dataset tooling.
- **WP-D:** D1, policy, ML.
- **WP-L:** harness.
- **WP-A:** access fixes and docs.

**User schedule:**
- **H0–1:** start the capture, delete the demo accounts, run the version checks.
- **H1–3:** on the Pi, run `nft -c -f` on the templates, check that `ether saddr` is the station MAC on wlan0, test intra-BSS visibility, check NFStream pps and do the PMF timebox.
- **H10–12:** deploy v2.0 and run the flood/spoof campaigns.
- **H12–17:** sleep (capture continues).
- **H22–24:** deploy v2.1.
- **H24–30:** campaign #1 (dev runs).
- **H30–35:** sleep.
- **H35–41:** campaign #2 (eval runs) and the held-out benign window.
- **H41–42:** review.

**Cut order if late:** CIC-IDS2017 test → D3 family head → meter-fill/MAC-churn campaigns → 1 h D1 windows → Wazuh decoder → portal MAC binding.
