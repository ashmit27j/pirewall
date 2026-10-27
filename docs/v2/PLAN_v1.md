# Pirewall v2 — Plan v1 (after 4 independent critiques)

Inputs: PLAN_v0_draft.md + critique_redteam.md + critique_ml.md + critique_systems.md +
critique_safety_eval.md (all in this folder). nft rule shapes below were parse/behaviour-tested by the
critics with nft 1.0.9 in netns (Verified); everything must be re-checked on the Pi (Bookworm nft ~1.0.6,
kernel 6.6/6.12). Labels: [V] verified in sandbox, [R] reasoned, [P] must be verified on the Pi.

## 0. Hard facts that shaped v1
1. **Client↔client Wi-Fi traffic never reaches the Pi.** BCM43455/brcmfmac bridges intra-BSS frames in
   firmware and ignores ap_isolate (RaspAP docs) [R/P]. v2 covers **client→Internet (forward)** and
   **client→Pi (input)** only, unless a mac80211 USB Wi-Fi adapter (MT7612U/MT7921AU) is used with
   isolation + proxy-ARP hairpin. Lab victim must sit on the WAN side or a wired segment.
2. **A full nft dynamic meter fails open** (new keys are not policed) [V]. Anti-spoof first, sets ≥2× the
   DHCP pool, keyless global backstops, 80%-full alerts.
3. **`ct state new` meters miss floods to services that reply** (0/20 dropped once ESTABLISHED) [V] →
   stateless per-MAC pps meters on `input`; new-conn meters only on `forward`.
4. **NFStream never ends a flow on FIN/RST**; flows expire only on idle/active timeout [V]; default
   accounting is link-layer (54 B bare TCP) → `accounting_mode=1` [V]; per-packet loop is Python,
   ~64–71k pps/process on a 2.8 GHz Xeon → est. 12–18k pps per meter on Pi 4 [R/P]; current systemd
   `SystemCallFilter=~@resources` kills NFStream via a sched_setaffinity error-path bug [V].
5. **libpcap/AF_PACKET taps run before netfilter**: nft drops do not unload userland capture [R]. Flood
   evidence must come from kernel counters/offender sets, not flows.
6. **The AP is NetworkManager shared mode** (wpa_supplicant AP + NM-spawned dnsmasq, 50-lease cap,
   lease file `/var/lib/NetworkManager/dnsmasq-<if>.leases`), not hostapd [R/P].
7. **`ether saddr != ip saddr map @m` is a syntax error** [V] → two-set anti-spoof (`bound4` +
   `macbind` concat set) [V: drops neighbour spoof 1804/1804 and rand-source floods].
8. **A chain named `fwd` is a syntax error** [V]; verdicts cannot live in a `define` [V] → `jump guard_verdict`.
9. nDPI has had remote memory-safety CVEs (e.g. CVE-2020-15473) → the parser must not run in the
   process holding CAP_NET_ADMIN.
10. Public datasets cannot be fetched from the sandbox (cicresearch.ca does not resolve; distrinet 403).
    CIC-IoT2023 ≈ 548 GB → cut. CIC-IDS2017 Friday pcap (8.3 GB) only as an external test, if the user
    downloads it.

## 1. Scope (to be stated verbatim in README + paper)
Defends a Pi 4 Wi-Fi AP's LAN against floods, scans, brute force and IP spoofing **originating from LAN
clients toward the Internet or the Pi**, with static in-kernel guards + adaptive per-device sets driven by
deterministic and ML evidence. Out of scope: client↔client traffic on the onboard radio, payload/C2
content, ML evasion beyond MONITOR, RF attacks (deauth/jamming/evil twin; PMF only mitigates), WPA2-PSK
insider decryption/injection, IPv6 (dropped on LAN, not analysed), Wi-Fi airtime exhaustion, upstream
DNS integrity.

## 2. Goals / acceptance (measured on the Pi by the harness; N runs; manifests)
- G1 SYN/UDP/ICMP floods (fixed + random source) from one LAN client at the Pi and through the Pi:
  kernel mitigation, TTM ≤ 2 s (victim-side), Pi stays responsive (admin API p95 < 1 s).
- G2 nmap -sS T4/T3 blocked at device level ≤ 15 s; T2 detected ≤ 120 s (MONITOR).
- G3 SSH/HTTP brute force to a WAN-side victim and portal login brute force: detected + RATE_LIMIT.
- G4 Spoofing a bound neighbour's IP is dropped; neighbour never gets a set element.
- G5 Held-out benign: 0 RATE_LIMIT/BLOCK (report rule-of-three bound 3/T) and MONITOR ≤ 1/device-hour.
- G6 kill -9 of core/sensor: guards + existing elements keep working; restart causes no LAN outage.
- G7 Every number in the paper produced by `lab/aggregate.py` from hashed run manifests.
- G8 Everything v1 measured is re-measured on v1 and v2 with the same harness (baseline comparison).

## 3. Architecture
Processes (all systemd, hardened):
- `pirewall-sensor` (NEW): NFStream capture on LAN iface. CAP_NET_RAW only, no NET_ADMIN, no RPC
  sockets except a write-only unix socket to core; `MemoryMax` ~400M; restarts freely. Emits flow
  records (feature schema v2) as length-prefixed JSON. Sensor crash = loss of visibility, not enforcement.
- `pirewall-leases` (NEW, tiny, stdlib + libnftables): read-only watch of the NM dnsmasq lease file
  (+ `[[antispoof.static]]` from config); parses only MAC/IP/expiry with strict regexes; sole writer of
  `bound4`/`macbind`; replaces stale pairs (delete-then-add) in one nft batch. Survives core death.
- `pirewall-core`: CAP_NET_ADMIN, no packet parsing. Consumes flow records + polls kernel offender
  sets/counters (1 s) → D1/D2/D3 → policy engine → validator → FirewallManager → nft set elements
  (libnftables JSON, one long-lived handle; fallback `nft -j -f -` batch). Offender polling, lease
  state and meters run outside the single RPC lock.
- `pirewall-api`, `pirewall-portal`: as v1 (A4/C1 split kept), with hardening fixes in §3.6.

### 3.1 Kernel data plane: two tables (split is a safety invariant)
`table inet pirewall_static` — rendered template, loaded by `pirewall-start`/human, NEVER flushed by core
or the kill switch (only by "panic"). Reload = declare + flush chains (never `delete table`).
`table inet pirewall_adaptive` — sets only written by FirewallManager; kill switch flushes them.

Static chain `prerouting_raw` (hook prerouting, priority raw, iifname LAN only), in this order:
1. `meta nfproto ipv6 drop` (A5; startup self-check `disable_ipv6=1` on LAN, else refuse ACTIVE).
2. Fragments from LAN: drop (`ip frag-off & 0x3fff != 0`), counted.
3. Exempt: DHCP `udp sport 68 dport 67` (behind a per-MAC DHCP meter), multicast/broadcast daddr
   (224.0.0.0/4, 255.255.255.255, LAN broadcast) → `return` before anti-spoof.
4. Reverse path: `fib saddr . iif oif missing drop`; source not in protected_network → drop.
5. Anti-impersonation: `ip saddr @bound4 ip saddr . ether saddr != @macbind drop`.
6. Unbound sources (not in `bound4`, e.g. static-IP devices, lease lag): tight meter class +
   `@unbound_seen` evidence; enforce only after grace period; static devices declared in config.
7. `ether saddr . ip saddr @allow_bound return` (A2 allowlist, keyed on MAC+IP, after anti-spoof).
8. Stateless per-MAC meters (dynamic sets, size ≥ 2× pool, timeout 60 s), each `update @offenders
   { ether saddr . <code> }` + `jump guard_verdict`: SYN pps, UDP pps, ICMP pps, total pps.
9. Keyless global backstops per class (`limit rate over N/second`), counted.
Static chain `input_guard` (hook input, priority -5, iifname LAN): DNS qps per MAC, closed-port hits per
MAC (packets to ports not open on the Pi), `ct count over K` per MAC on portal :8080 and API ports,
then `jump guard_verdict_input`.
Static chain `forward_guard` (hook forward, priority -5, iifname LAN): `ct state new` rate per MAC,
per (MAC, daddr) new-conn rate (flood to one host), LAN→WAN udp/tcp 53/853 not via Pi → drop (force
DNS through the Pi), then `jump guard_verdict_forward`.
Verdict chains: `guard_verdict_input` / `guard_verdict_forward` / `guard_verdict_raw` contain `drop`
(enforce) or nothing (observe). Defaults: input = enforce, raw anti-spoof = enforce **only if bindings
were seeded** else observe, forward = observe until the benign FP check passes. Mode flip = one atomic
nft batch (flush chain + add rule).
Adaptive table `pirewall_adaptive` (priority -4 on input+forward, iifname LAN): `@infra4` accept is the
first rule everywhere (Admin PC, Pi addrs, gateway); `@allow_bound` return; `block_mac`/`block4` drop;
`ratelimit_mac` → per-element meter. All elements carry a timeout (≤ 3600 s).
Base ruleset fix: admin rule becomes `iifname "eth0" ether saddr <admin MAC> ip saddr <admin IP> tcp
dport {22, API} accept`; `enforce_admin_pc_ip` also checks interface.
Existing `pirewall_portal`: `authed` becomes `ipv4_addr . ether_addr` (session bound to MAC+IP).

### 3.2 Sensor / features (schema v2, frozen at H28)
`NFStreamer(source=LAN, idle_timeout=10, active_timeout=10, accounting_mode=1, snapshot_length=1536,
statistical_analysis=True, splt_analysis=8, n_dissections=20, n_meters=2)`; same config object imported
by `scripts/dataset/pcap_to_flows.py`. Patch/allow `sched_setaffinity`. Features exclude IP/MAC/OUI,
raw ports, SNI, app names, timestamps; destination port → coarse category (web/dns/ssh/mail/other-wk/
ephemeral) with with/without ablation. nDPI JA4/SNI kept as log context only. Identity for D1 = source
MAC (from flow `src_mac`).

### 3.3 Detection tiers
- **K (kernel)**: offender sets + drop counters, polled every 1 s → evidence `KERNEL_GUARD(code, mac)`.
- **D1 deterministic (may act)**, per MAC over 10 s / 60 s / 1 h windows from the flow stream:
  distinct dst ports per dst host (vertical scan), distinct dst hosts on one port (horizontal scan),
  failed-handshake ratio (SYN-only/RST flows), many short same-size flows to one dst:22/80/443 (brute
  force), fan-in per destination (distributed), new-MAC rate on the AP, portal auth failures (per account
  + global). Thresholds = clamp(benign P99.9 × margin, floor, hard ceiling); floors/ceilings from security
  priors (e.g. >100 distinct dst ports/60 s is never benign); poisoning-resistant because of the ceiling
  and because benign capture excludes lab MACs/windows.
- **D2 anomaly (MONITOR only)**: one global Isolation Forest on own benign training block; threshold =
  validation-block quantile for per-flow FPR 1e-3.
- **D3 supervised (MONITOR/corroborate only)**: LightGBM binary + coarse family head (flood/scan/brute/
  slow-DoS); rows capped per run; connection-grouped splits; isotonic calibration on validation;
  operating point by benign FPR, not F1. Shortcut audit (depth-3 tree print) before reporting.

### 3.4 Policy engine (replaces weighted sum; table is data + exhaustive test matrix)
| Evidence | SHADOW | ASSISTED | ACTIVE |
|---|---|---|---|
| K offender (any code) | log | RATE_LIMIT mac 5 min | RATE_LIMIT mac 5 min |
| D1 high-certainty (fast scan, brute force) | log | RATE_LIMIT; BLOCK → approval queue | BLOCK mac 5 min |
| D1 + K, or D1 repeated with **new independent evidence** | log | BLOCK → approval | BLOCK, TTL ×2 (cap 1 h) |
| D3 or D2 alone | log | MONITOR | MONITOR |
| D3 + D2 (no D1/K) | log | MONITOR (high) | MONITOR (high) |
| D3/D2 + D1 | log | RATE_LIMIT | RATE_LIMIT |
Invariants (tests): ML-only ⇒ ≤ MONITOR; anomaly-only ⇒ ≤ MONITOR; allowlist/infra ⇒ never; one
writer per adaptive set; kernel-written sets are never read by a verdict rule other than their own meter.
Validator v2 keeps stage order: schema → network → allowlist → safety (infra4, admin MAC, Pi/gateway,
non-unicast) → conflict (block ⊃ ratelimit; upgrade = atomic delete+add) → duplicate → rate-cap
(element insertions) → escalation (replaces priority) → expiration (mandatory timeout ≤ 3600 s) →
authorization. Block notice (C4) keyed by MAC.

### 3.5 Kill switch & failure modes
- Kill switch: SHADOW + flush adaptive sets + guards → observe (static table stays loaded). Audit event.
- Panic: `nft delete table inet pirewall_static; nft delete table inet pirewall_adaptive` via RPC **and**
  documented console one-liner.
- Clean fail-open shutdown: flush adaptive sets only. Crash: elements expire by TTL (≤ 1 h). Restart:
  reconcile RuleStatus with live set contents, never recreate tables.
- Sensor down > 30 s or capture drop > X% → SYSTEM_WARNING + "conservative mode" (K offenders acted on
  directly per table above; already true).

### 3.6 Access & hygiene fixes (P0)
Delete demo portal accounts; admin login throttle (per IP + global); portal throttle per account +
global; `ct count` on portal; allowlist additions via API require password re-entry and are MAC+IP;
fix api log dir, cert SANs, `session_timeout_seconds`; PMF attempt via `nmcli ... pmf required`
(fallback `optional`), 30-min timebox; startup self-checks (IPv6 off, bindings seeded, set fill < 80%).
Forensics: per-type in-memory quotas (a flood cannot evict scan records) + journald; Wazuh decoder.

## 4. Data & evaluation protocol
- Benign capture on the Pi from H0: `tcpdump -ni wlan0 -s 1600 -G 3600 -w benign-%Y%m%d%H.pcap`
  (consent of household; pcaps never committed; publish only hashed derived features). Lab MAC +
  windows excluded via `lab/ground_truth.jsonl`.
- Attack lab: attacker = Kali on wlan0 with a dedicated MAC; victims = (a) the Pi itself (input path),
  (b) a WAN-side host on the upstream LAN (forward path; sshd, nginx, iperf3 server), (c) legit wired
  client for collateral. chrony on all hosts.
- Campaigns (each N=5 runs for floods/scans, N=3 for the rest; randomized order; cooldown until sets
  empty): SYN/UDP/ICMP flood (fixed, `--rand-source`, spoof-neighbour), nmap -sS T4/T3/T2, masscan or
  rustscan (held-out tool), hydra ssh/http, portal brute force, slowloris, meter-fill (many MACs if the
  attacker NIC supports MAC changes), established-flow flood to :53/:8080, frame-neighbour.
- Splits: benign temporal 60/15/≥1 h gap/25; attacks by run ID; leave-one-tool-out; parameter variants
  held out; CIC-IDS2017 Friday (if downloaded) external test only; test sets touched once (hash logged).
- Metrics (definitions verbatim in critique_safety_eval.md §c): TTD, TTM (victim-side), mitigation
  effectiveness, collateral (wired + Wi-Fi), FP per device-hour with Poisson CI / rule of three, Pi CPU/
  RSS/drops vs pps; ML: PR-AUC, recall@FPR 1e-3/1e-4, expected alerts/day, reliability diagram, PSI drift.
- Baselines: v1 and kernel-only and +D1 and +D2 and +D3 (ablation) on the same harness.
- Harness scripts: `lab/preflight.py, run_campaign.py, attacks/*.sh, benign/background.py,
  poll_state.py, capture.sh, score_run.py, benign_fp.py, aggregate.py, verify_manifest.py` (CLI
  signatures in critique_safety_eval.md). Paper tables are only `aggregate.py` output; `env=sandbox`
  results can never be mixed with `env=pi`.
- Paper tables I–VII + Fig 1–5 as in critique_ml.md §10 + threats-to-validity mapped to Arp P1–P10.

## 5. Sandbox test tiers (no Pi)
U: unit + fakes (policy matrix, set-semantics fake, validator v2). N: netns integration with real nft
(attacker/legit/admin/router/victim namespaces; the 9 assertions in critique_safety_eval.md §d +
meter-fill, established-flow flood, IPv6, fragments). R: tcpreplay of Pi benign pcaps (tcprewrite onto
netns addresses) for FP/regression only.

## 6. Work packages (parallelisable by agents in separate worktrees)
- WP-K kernel: templates (static/adaptive), render + `nft -c` tests, libnftables backend, set-based
  FirewallManager/validator v2, kill switch/panic, lease watcher unit, netns tests.
- WP-S sensor: `pirewall-sensor` service, NFStream config, flow-record socket protocol, schema v2,
  `pcap_to_flows.py`, systemd unit + affinity fix, throughput script for the Pi.
- WP-D detection: kernel offender poller, D1 detectors, D2/D3 training + eval scripts, policy engine +
  matrix tests, core integration, dashboard deltas (minimal).
- WP-L lab: harness scripts, campaigns, scoring, aggregate, manifests.
- WP-A access/hygiene + docs: P0 items, ADDENDUM_4 (static guards, two tables, sensor split, MAC
  identity, scope), KNOWN_ISSUES v2, SETUP v2.

## 7. Schedule (42 h; C = Claude/agents in sandbox, U = user on Pi/Kali)
| Hours | U | C |
|---|---|---|
| H0–1 | Start benign capture; delete demo accounts; push overhaul branch (or confirm start from main); record `nft --version`, `uname -r`, `iw phy`; install python3-nftables hping3 nmap tcpdump chrony | P0 code fixes; freeze plan; spin up WP agents |
| H1–3 | Pi checks: intra-BSS visibility test, `nft -c -f` on draft ruleset, NFStream throughput on synthetic pcap, PMF timebox; pick WAN-side victim; chrony everywhere | WP-K/S/L/A in parallel |
| H3–12 | Keep capture running; dry-run harness pieces as they land | WP-K netns tests green; WP-S sensor + pcap_to_flows; WP-L harness |
| H12–20 | Run attack-lab campaign #1 (training/dev runs) with v1 deployed in SHADOW (also = v1 baseline) | WP-D D1 + policy + core integration; deploy package for Pi |
| H20–28 | Deploy v2 in SHADOW; forward_guard observe; copy benign pcaps for training | D1 thresholds from benign train block; D2/D3 training; feature freeze H28 |
| H28–36 | Campaign #2 (eval runs) on v2 SHADOW then ASSISTED/ACTIVE; held-out benign window continues | score/aggregate; fixes from Pi feedback |
| H36–40 | Final runs; collect manifests | aggregate tables/figures; ablation; KNOWN_ISSUES v2 |
| H40–42 | Review | docs, paper tables, scope statement |
Cut list (in order if late): CIC-IDS2017 external test → D3 family head → slowloris/meter-fill
campaigns → 1 h-window D1 detectors → portal MAC binding → Wazuh decoder.

## 8. Open decisions for the user
1. USB Wi-Fi adapter (mac80211) available? If yes, client↔client becomes in scope via isolation +
   hairpin; if no, it is a stated limitation.
2. WAN-side victim host available on the upstream network (laptop/second Pi)? Needed for forward path.
3. Household consent + how many real devices will generate benign traffic during the 42 h.
4. Start from `main` or from the unpushed overhaul branch (must be pushed, or ignored).
5. Delivery: Claude cannot push; deliver as git bundle/patch series + tarball unless GitHub access is
   granted to this session.
