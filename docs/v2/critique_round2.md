# Round-2 critique of PLAN_v1: contradictions, gaps and feasibility

Labels:
- **[V]** means verified in this sandbox this round.
- **[R]** means reasoned from code or docs.
- **[P]** means it must be checked on the Pi.

Repo references are to `main` @ 6cff037.

## Verified facts this round

- **F1 [V]** `python3-nftables` (Debian/Ubuntu package) is **pure Python plus ctypes** (`cdll.LoadLibrary("libnftables.so.1")`). It has no compiled CPython extension, so it works from the uv **Python 3.12** venv even though Bookworm's system Python is 3.11.
  - Test here: venv Python 3.12.3 with the package dir on `sys.path`, in an `unshare -rn` netns. Adding a table, a timeout set and an element worked, and the element listed with `expires 30s`.
  - Deploy: drop a `.pth` file pointing at `/usr/lib/python3/dist-packages/nftables`, or vendor the ~500-line file (GPLv2; the project licence must allow that).
  - Fallback: `nft -j -f -` (3.1 ms per op, about 15× slower than libnftables but adequate).
  - **Gotcha [V]:** a `list` inside the same batch as an `add` runs before commit and doesn't see the new element. Read-after-write needs a second call.
- **F2 [V]** With `accounting_mode=1` and `n_dissections=0`, NFStream 6.6.0 gives **identical** statistical and SPLT features for a 178 MB synthetic pcap and the same pcap truncated to snaplen 128 (20,000 flows, 0 differing columns). Snaplen only matters for nDPI dissection (SNI/JA4), which v1 of the plan already excludes from features.
- **F3 [V]** NFStream expires idle flows from an LRU scan every 10 ms (budget 1,000 flows per scan) on packet *and* timer ticks. Emission latency is about `idle_timeout` + ≤10 ms, regardless of how quiet the link is.
- **F4 [V]** Every config model inherits `extra="forbid"` (`core/models/common.py`). Removing or renaming any key, such as the `[threat]` weights, makes the Pi's existing `local_config.toml` **fail to load at startup**.
- **F5 [V]** `CandidateRule` and `FirewallRule` carry `source`/`destination: IPv4Network` and nothing else. There is no MAC field.
  - The portal (`portal_service.login`/`keepalive`) calls `blocking_rules_matching(client_ip)` and only ever receives an IP, from the HTTP request.
  - Allowlist entries are IP targets.
  - Test coupling: `CandidateRule` 24 files, `FirewallRule` 12, Fake/Nftables backend 44, `BehaviorAnalyzer` 11, feature schema 14, TLS detectors 8, scoring/decide 8.
- **F6 [R]** NetworkManager shared mode with the nftables backend (NM ≥1.32) creates `table inet nm-shared-<if>`:
  - `nat_postrouting` at priority 100 (masquerade).
  - `filter_forward` at priority 0: established accept, subnet accept, reject.
  - No prerouting or input chains (NM commit 9ebdb967ded7).
  - So `prerouting priority raw` runs before conntrack and before anything of NM's, and our forward chains at -5/-4 run before NM's priority 0. A drop anywhere is final. No conflict, apart from item 14.

## Required plan changes, in priority order

### 1. `@infra4 accept` on LAN-ingress chains is a spoofing bypass (Critical) [R]
**Problem.** Plan §3.1 makes "`@infra4` accept (Admin PC, Pi addrs, gateway)" the first rule of the adaptive chains, and every one of those chains is `iifname LAN`.
- None of those hosts legitimately sends from the LAN with that source address.
- The Pi's own LAN IP sits inside `protected_network` and is never in `bound4`, so the raw anti-spoof only puts it in the "unbound" class. It then hits `accept` and skips every adaptive block.

This is red-team #2 again, in a new place.

**Change.**
- In `prerouting_raw`, add `ip saddr @pi_addrs drop`: the Pi's own addresses arriving on LAN ingress are martians.
- Remove the `@infra4 accept` source match from every LAN chain.
- infra protection belongs **only** in the validator (a target may never be infra) and in `ip daddr` exemptions (see 2).

### 2. MAC/IP BLOCK on `input` breaks the C4 block notice and DHCP renewal (High) [R]
**Problem.** v1's adaptive chain hooked only `forward`, so a blocked device could still reach the portal (:80→:8080), DNS and DHCP on the Pi, and see *why* it was blocked (ADDENDUM_3 C4). v2 applies `block_mac`/`block4` on `input` too. The notice can never be delivered, and DHCP renewals and DNS fail, which looks like a broken Wi-Fi rather than a firewall action.

**Change.** In the adaptive `input` chain, exempt `udp dport 67`, `udp/tcp dport 53` (still metered by `input_guard`) and the portal ports. Put that exemption *before* block/ratelimit. Add a netns test that a blocked MAC still receives the block notice page.

### 3. Identity model: MAC-keyed enforcement, but every model and API is IP-only (High) [V F5]
**Change.** This is an explicit, additive migration work item (about 4 h, WP-K, done first).
- Add `RuleTarget{ip: IPv4Address, mac: EUI48 | None}` to `_RuleFields`, optional and defaulting to None, so the existing tests keep passing.
- Add a `BindingTable` in core, fed from leases and static config, that resolves IP↔MAC.
- `blocking_rules_matching(ip)` resolves IP→MAC and matches either key.
- Portal sessions store `(ip, mac)` from `BindingTable` at login. Change `authed` to `ipv4_addr . ether_addr` and the gate rule to `ip saddr . ether saddr @authed`.
- Allowlist entries gain an optional MAC. `allow_bound` is rendered only from entries that have both.
- The validator's safety stage checks both keys.
- Block notices look up by IP→MAC.

### 4. Keep v1 runnable and isolate v2 (High) [R, F4/F5]
**Problem.** Rewriting scoring, decision, behaviour, features and capture in place breaks dozens of test files at once while five agents edit `runtime/core.py` and `firewall/manager.py` simultaneously. It also destroys the v1 baseline G8 requires.

**Change.**
- Put v2 detection and policy in new modules: `pirewall/sensor/`, `pirewall/detection_v2/`, `pirewall/policy/`.
- Select with `pipeline.engine = "v1" | "v2"`. Both share the new set-based backend through an adapter. v1 decisions map to `RuleTarget(ip=src)`.
- Config is additive only: new `[guards]`, `[sensor]`, `[antispoof]`, `[policy]` sections with defaults. Deprecated keys stay accepted and are logged. Ship `scripts/deployment/migrate_config.py`.
- The v1 suite must stay green throughout.

### 5. Freeze the interfaces at H0–2, before any work package starts (High) [R]
**Problem.** The plan has no contract step, so parallel agents will diverge.

**Change.** Write `docs/V2_CONTRACTS.md` plus typed stubs and commit them first. It covers:
- `FlowRecordV2` (the exact NFStream columns kept, and the socket framing).
- `Evidence` variants (`KERNEL_GUARD{code, mac, sustained_polls}`, `D1{detector, window, value, threshold}`, `D2`, `D3`).
- `PolicyDecision`.
- `RuleTarget`.
- Set and chain names, and offender codes.
- New RPC methods: `get_guard_modes`, `set_guard_mode`, `panic`, `list_offenders`, `list_bindings`, `get_sensor_stats`.
- File ownership per work package (only the integrator touches `runtime/core.py`, `firewall/manager.py` and `ipc/dispatcher.py`).

### 6. Observe-mode guards still enforce through the policy table (High) [R]
**Problem.** §3.4 says "K offender (any code), ASSISTED → RATE_LIMIT mac 5 min". An offender recorded by `forward_guard` in **observe** mode would therefore be enforced anyway through `ratelimit_mac`. That defeats the observe default and G5.

**Problem, continued.** `ratelimit_mac` at 20 pps for a whole device is effectively an outage for video, so a phone-wake DNS burst turns into a 5-minute household outage.

**Change.**
- Evidence carries `guard_mode`. Observe-mode offenders produce MONITOR only.
- Enforce-mode offenders need `sustained_polls ≥ 2`, i.e. ≥2 s over threshold, before RATE_LIMIT.
- `ratelimit_mac` limits **new connections per second**, with a generous per-device byte cap, not total pps.
- Add policy-matrix tests for each of these.

### 7. Guard-mode flips and the kill switch write the "never touched" static table (Medium) [R]
**Change.** Define exactly one permitted core write to `pirewall_static`: replacing the contents of the `guard_verdict_*` chains (drop or empty), done by `FirewallManager.set_guard_mode`. Panic is the only other path. Everything else in `pirewall_static` is template-only, and a test enforces this by diffing the ruleset before and after every core operation.

**Change.** Route the anti-spoof drops (rules 4–6 in §3.1) through `jump guard_verdict_raw`. As written they are bare `drop`s, so the plan's "anti-spoof observe if not seeded" mode cannot exist. IPv6 and fragment drops stay as bare drops.

### 8. Fold the lease watcher into core (Medium) [R]
**Problem.** A separate `pirewall-leases` unit with CAP_NET_ADMIN is a second privileged writer, which contradicts the single-writer invariant. It also parses a file containing client-supplied hostnames. Its justification ("survives core death") is not needed:
- `bound4`/`macbind` elements are kernel state with timeout = lease expiry, so they **persist when core dies**.
- Only *new* leases go unbound while core is down, and those fall into the unbound meter class, not drop.

**Change.** Lease sync is a core thread (inotify plus 2 s poll, strict regex on the MAC/IP/expiry fields only, hostname ignored). It writes through `FirewallManager.sync_bindings()`, which is a C2-style non-RuleStatus path like portal elements. That removes one unit and one systemd file. Add `ReadOnlyPaths=/var/lib/NetworkManager` to core.

### 9. Benign data budget: G5 can't be supported as scheduled (High) [R]
**Problem.** Benign capture runs H0–42, but campaigns occupy H12–20 and H28–40, and collateral traffic in those windows isn't clean benign.
- That leaves roughly 20 clean hours (H0–12 and H20–28), much of it overnight idle.
- Thresholds set at H20 come from about 12 h, mostly night. Daytime false positives are likely.
- A 25% test block is about 5 h × devices. With 5 devices and zero events, rule-of-three gives ≈0.12/device-hour, which is weak.

**Change.**
- (a) Evaluate G5 **offline**: replay every clean benign hour through `pcap_to_flows` → D1/D2/D3 (pure functions of flows), plus a **kernel-meter simulator** that replays per-MAC token buckets over the pcap with the exact rendered thresholds. This uses all clean hours, not just a live window.
- (b) Report the bound honestly, as 3/T.
- (c) Make thresholds a config reload, so they can be refreshed at H28 from H0–28 clean data.
- (d) Restate G5 as "0 enforce actions over T clean device-hours, upper bound 3/T", not as a literal zero.

### 10. Benign capture: disk and privacy (Medium) [V F2, R]
**Problem.** `tcpdump -s 1600` for 42 h of household video can fill the SD card (5 Mb/s streaming ≈ 2.2 GB/h) and records payloads.

**Change.** Capture `-s 128`. F2 shows the features are identical under `accounting_mode=1`. That gives headers only, which is better for consent. Capture to a USB SSD with `-G 3600 -C` rotation and a disk-space watchdog. Live sensor snaplen can stay 1536 for SNI/JA4 log context only.

### 11. v1 capabilities silently dropped (Medium) [V repo]
State each as kept, ported or dropped, in ADDENDUM_4 and the paper:
- **Heartbleed and JA3 detectors** (`detection/tls_*`, fed by core's payload inspection): v2 core does no packet parsing, so they disappear. Either drop them (recommended; low value in 2026) or replace them with a sensor-side JA4 known-tool list as MONITOR evidence.
- **Behaviour patterns with no D1 equivalent:**
  - `SLOW_RATE_DOS` must be ported, because a slowloris campaign is planned and nothing in D1 detects it.
  - `TEMPORAL_PATTERN` (beaconing) and `PERSISTENCE`: drop, or move to MONITOR.
- **Netdata gauges** (inference latency, AF_PACKET drops, flow rates): re-source them from sensor stats and nft counters, or the Netdata charts go flat.
- **Dashboard and API** schemas use `ThreatAssessment.threat_score`/`threat_level`. The v2 policy has no score, so map `PolicyDecision` to `threat_level` for UI compatibility.
- **Wazuh event JSON** changes, so the decoder must match v2.

### 12. Forward-path scan TTD versus the idle timeout (Medium) [V F3]
**Problem.** Forward-path scans (to the WAN victim) are visible only through NFStream, because `forward_guard` is in observe mode. TTD ≈ `idle_timeout` (10 s) + D1 tick + poll ≈ 11–13 s. G2's "≤15 s blocked" therefore has about 2 s of margin.

**Problem, continued.** Because flows are split every 10 s, long keep-alive connections become many records. D1 "new connections" must count **connection starts** (records with `src2dst_syn_packets > 0` and no prior record for that 5-tuple), not records. Otherwise HTTP/2 keep-alives inflate the counts.

**Change.** Set G2 to "≤ idle_timeout + 5 s" and consider `idle_timeout=5`, trained identically. Specify the connection-start definition in the contract.

### 13. MAC churn and lease exhaustion (Medium) [R]
**Problem.** With the PSK, a new MAC costs only a reassociation, giving a fresh meter and a fresh block. With anti-spoof, every new MAC needs a DHCP lease. NM shared mode caps leases at 50, so about 50 churns starve the **whole LAN** of DHCP. That is a new DoS v1 didn't have.

**Change.**
- Add a D1 detector for new-MAC and new-lease rate, plus the keyless global backstops.
- Shorten the lease time for unknown MACs if NM allows it (`dnsmasq-shared.d` `dhcp-range` lease time) [P].
- Raise the lease cap via `dhcp-lease-max` in `dnsmasq-shared.d` [P].
- With the portal on, escalate per account.
- State the residual risk.

### 14. `flush ruleset` from Debian's nftables.service (Medium) [R/P]
**Problem.** Bookworm's default `/etc/nftables.conf` starts with `flush ruleset`. Enabling or restarting `nftables.service` wipes NM's tables, the portal tables and both pirewall tables, all silently.

**Change.**
- The preflight check verifies that `nftables.service` is disabled, or that its conf has no `flush ruleset`.
- Core checks every second that both tables and the set handles still exist. On loss it raises CRITICAL and re-renders through `pirewall-start` (guards are static policy, so re-applying the reviewed template is allowed).

### 15. NFStream dependency footprint and hardening (Low–Medium) [R]
**Change.**
- `nfstream` pulls in numpy, pandas, psutil, dpkt and cffi. Record this in ARCHITECTURE.md, since CLAUDE.md says to ask before adding dependencies.
- Pin the version.
- The sensor unit needs:
  - `AF_PACKET` and `CAP_NET_RAW`.
  - `SystemCallFilter=sched_setaffinity sched_getaffinity` (the known crash).
  - Writable `/dev/shm`.
  - `MemoryMax` ≥ 500M for `n_meters=2` (each meter imports pandas).
- Run the NFStream throughput test on the Pi at H1. If it delivers under 8k pps per meter, fall back to `n_meters=3` and a BPF prefilter.

### 16. The schedule is too serial for one human (Medium) [R]
**Problem.** The v2 deploy at H20 needs WP-K, WP-S and WP-D integrated, plus the model migration (item 3), in about 18 agent-hours. Integration on nft 1.0.6 (Bookworm) is untested, and the user is assumed awake for 42 h straight.

**Change.** Ship in three increments, each deployable and measurable on its own:
- **v2.0, by H10:** kernel guards, the set backend and anti-spoof, driven by the *v1* pipeline through the adapter. This alone tests G1, G4 and G6.
- **v2.1, by H22:** sensor plus D1 plus the policy engine.
- **v2.2, by H30, cuttable:** D2/D3.

Plan two user sleep blocks of about 5 h during unattended benign capture (overnight data is still useful). Pull `nft -c -f` of the rendered templates on the Pi forward to H1, so 1.0.6 syntax differences surface early.

### 17. Small fixes
- **Manifests** must record the `guards` modes and `pipeline.engine` as well as `enforcement_mode`. Otherwise "v2 in SHADOW" runs still show kernel mitigation and get misread.
- **`fib saddr . iif oif missing drop`:** it parsed in netns (round-1 [V]). Behaviour for a saddr equal to a local Pi address is uncertain, so item 1's explicit `@pi_addrs` drop is needed anyway.
- **The DHCP exemption (`sport 68 dport 67`)** is matched before anti-spoof, so unicast renewals from bound clients pass. That is fine.
- **Fallback when libnftables is unavailable:** batch every poll and sync into one `nft -j -f -` call per tick.
- **`api.rpc_timeout_seconds`:** the new `list_offenders` and binding calls must not run under core's single RPC lock (round-1 note). Serve them from snapshots updated by the poller thread.

## Sources
- NetworkManager nftables shared-mode commit: https://git.uninsane.org/colin/NetworkManager/commit/9ebdb967ded7
- NetworkManager 1.32 release notes: https://networkmanager.dev/blog/networkmanager-1-32/
- Local inspection: `python3-nftables_1.0.9` .deb contents and `nfstream/meter.py` (6.6.0).
