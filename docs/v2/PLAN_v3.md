# Pirewall v2: plan v3 (replaces PLAN_FINAL.md)

**Inputs:**
- PLAN_FINAL.md and the five critiques.
- `v2/RESULTS.md`: the tested nft data plane.
- `audit_new_main.md`: an audit of `main` @ 8b91b5f after the overhaul merge.
- The user's answers:
  - The TL-WN725N (RTL8188EU) is the only extra hardware.
  - There is no WAN-side victim host and no SSD.
  - Live, scripted and mock data modes are all wanted.
  - The startup script must be updated.
  - **The deliverable is a plan plus Claude Code prompts, not code.**

**Labels:** [V] verified in the sandbox, [R] reasoned, [P] still to verify on the Pi.

---

## 0. What changed since PLAN_FINAL

1. **The overhaul is merged** (schema 2.0.0, a behaviour/scoring retune, a fast path, and a Rust TPACKET_V3 engine).
   - **Partly fixed:** train/serve skew, assessment latency, capture drops (native engine 0% vs Python 59% under GIL contention on x86 [V]), and the 40-point score ceiling.
   - **Not fixed:**
     - Enforcement is still on the forward hook only.
     - Rules are still per-port tuples.
     - Rules are still applied one at a time through a subprocess.
     - Still no anti-spoofing.
     - The fail-open off-switch is still there.
     - All access items are still open.
     - Training is still on CICFlowMeter CSVs with random splits.
   - **New risks:**
     - Behaviour alone now RATE_LIMITs (80). Without anti-spoofing, a client spoofing a neighbour's IP gets the neighbour rate-limited.
     - Behaviour plus a spurious IF flag reaches 95, which is a BLOCK.
     - The native engine runs in core with `panic="abort"`, which is a new crash path.
   - `LIVE_AB.md` can't be used as evaluation: tuning and testing used the same pcaps, it is a single run, it ran in Docker, and it counts decisions, not mitigation.
2. **NFStream is dropped. The native engine stays.** `FlowEngine.feed(frame, ts_us)` already exists [V], so a pcap reader makes **training and live features byte-identical**. The engine gets MAC fields, `catch_unwind`, a fuzz target and ring-offset clamps. It stays inside core (a separate process is future work). This works because the kernel guards keep protecting when core dies.
3. **The TL-WN725N is already the WAN uplink (`wlan1`, rtl8xxxu).**
   - Mainline rtl8xxxu has **no AP mode** for RTL8188EU. Patches are still at RFC v3 as of July 2026, and the staging r8188eu driver was deleted in 2023.
   - So it can't take over the AP role with working client isolation.
   - **Client↔client traffic stays out of scope**, listed as a limitation and future work.
4. **The forward-path victim is a network namespace on the Pi.** `lab0` is a veth into a `labvictim` netns running sshd, nginx, iperf3 and dnsmasq-as-DNS. LAN→lab0 traffic crosses the **forward** hook exactly as Internet-bound traffic does. CPU is shared with pirewall, so it's measured and reported. If the Admin PC (eth0) is available it can be Victim C, but only through a lab-only table.
5. **Scoring is kept for explainability and the UI only.** **The policy table decides actions.** Anomaly evidence can never raise an action.
6. **The next feature schema is 3.0.0** (2.0.0 is taken). It covers native-engine features computed from our own pcaps, with `destination_port` as a category and MAC carried on `Flow` but excluded from features.
7. **Three data modes:**
   - `live`: real household capture.
   - `scripted`: generated benign traffic from our own devices.
   - `mock`: synthetic pcaps with ground truth, replayed offline or into a netns.

   Every artifact carries an `env` tag (`pi-live` / `pi-scripted` / `sandbox` / `mock`), and aggregation refuses to mix them.
8. **`pirewall-start` v2** is specified in §6.

## 1. Scope (README + paper, verbatim)
> Pirewall v2 is a host-level adaptive defence for a single Raspberry Pi 4 acting as a Wi-Fi access point for a small LAN. It mitigates volumetric floods, port scans and brute-force attempts originating from LAN clients toward the Internet or the Pi, and blocks IP and ARP spoofing of other LAN clients. It uses static in-kernel nftables guards plus adaptive per-device (MAC) sets, driven by deterministic detectors whose thresholds are learned from benign traffic, with ML anomaly and classification as supporting evidence.
>
> **Out of scope:**
> - client↔client traffic on the onboard radio, which is bridged in firmware;
> - payload and encrypted content;
> - ML evasion beyond MONITOR;
> - RF attacks (deauthentication, jamming, evil twin), which PMF only mitigates;
> - MAC cloning or injection by a PSK holder;
> - IPv6 (dropped on the LAN);
> - Wi-Fi airtime exhaustion;
> - upstream DNS integrity.
>
> The ML components were trained on one network's short capture. All reported numbers come from scripted, repeated runs on the real Pi, with hashed manifests.

## 2. Goals and acceptance (harness-measured on the Pi, `env=pi-*`)
- **G1 Floods.** SYN, UDP and ICMP floods, fixed-source and random-source, from one LAN client at the Pi (input path) and at `labvictim` (forward path). The victim-side TTM (time to mitigate) is at most 2 s. The admin API p95 stays under 1 s during the flood.
- **G2 Scans.** nmap -sS T4/T3 against the Pi is caught by the kernel closed-port meter in ≤ 2 s. A scan of `labvictim` is blocked at device level within (idle timeout + 5) s. A T2 scan is detected (MONITOR) within 120 s. masscan is a held-out tool.
- **G3 Brute force.** hydra against SSH and HTTP on `labvictim`, and portal brute force, are detected and get RATE_LIMIT.
- **G4 Spoofing.** Spoofing a bound neighbour's IP, and ARP poisoning, are dropped. The neighbour never appears in any set.
- **G5 Benign cost.**
  - Zero enforce actions over T clean device-hours (upper bound 3/T), and MONITOR ≤ 1 per device-hour.
  - Measured offline over all clean `pi-live` hours, using D1/D2/D3 and a kernel-meter simulator, plus a live held-out window.
  - `pi-scripted` benign is reported separately.
- **G6 Crash safety.** After `kill -9` of core, the guards and existing set elements keep working. A restart causes no LAN outage.
- **G7 Traceability.** Every number in the paper comes from `lab/aggregate.py` over hashed manifests.
- **G8 Baseline.** v1 (`pipeline.engine="v1"`, which is the merged main pipeline) runs on the same harness as the baseline.

## 3. Architecture (unchanged from PLAN_FINAL §4 except where noted)
- **Processes.** `pirewall-core` holds CAP_NET_ADMIN and CAP_NET_RAW and runs the native engine in-process, now hardened. Lease sync is a core thread (inotify plus a 2 s poll; it parses only MAC, IP and expiry). `pirewall-api` and `pirewall-portal` are unchanged.
- **Kernel plane.** As in PLAN_FINAL §4.2: `pirewall_static` + `pirewall_adaptive`, with the tested templates in `v2/`.
- **Fail-open revert** now flushes **only the adaptive sets**. The static guards stay, so a core crash loop is no longer an off-switch. A crash-loop event raises CRITICAL to Wazuh.
- **Identity.**
  - `src_mac`/`dst_mac` are added in `native/src/parse.rs` → `FlowState` → `FlowRecord`/`NewFlowRecord`, and in Python `PacketMetadata`/`Flow`, with parity tests kept.
  - Rule models gain `RuleTarget{ip, mac|None}`.
  - A `BindingTable` holds the bindings.
  - Portal sessions become `(ip, mac)`.
  - Allowlist entries gain an optional MAC.
- **Detection.**
  - **K (kernel offenders):** polled every 1 s.
  - **D1:** v2's detectors are a port of main's behaviour patterns, keyed by MAC and with thresholds learned from benign traffic. They cover scan, flood, failed-handshake, brute force, slow-rate DoS, fan-in, new-MAC/lease rate and portal auth. Thresholds are `clamp(P99.9 × margin, floor, ceiling)` and are **frozen before any evaluation run**.
  - **D2 (Isolation Forest):** MONITOR only.
  - **D3 (LightGBM):** MONITOR or corroboration only.
  - D2 and D3 are trained on schema 3.0.0 features from our own pcaps.
- **Policy table.** As in PLAN_FINAL §4.6, with observe-mode offenders limited to MONITOR and `sustained_polls ≥ 2`. Both `pipeline.engine` values drive the same set backend through an adapter; v1 decisions map to `RuleTarget(ip=src)`, with the MAC resolved through `BindingTable`.
- **Kill switch, panic and the PLAN_FINAL §4.7–4.9 items:** unchanged. That includes the C4 notice exemptions on input, no `@infra4` source accept, the `@pi_addrs` martian drop, the `nftables.service` flush guard and the access fixes.

## 4. Data modes
| Mode | Source | Where | Used for | Tooling |
|---|---|---|---|---|
| `pi-live` | real household devices on pirewall-lan, with consent | Pi wlan0 | D1 thresholds, D2/D3 training, G5 | `lab/capture/benign_capture.sh`: tcpdump `-s 128 -G 3600`, rotation, disk watchdog (stops at 85% full), consent banner, lab-MAC exclusion list |
| `pi-scripted` | our own devices running scripted benign profiles over the AP | Pi wlan0 | extra benign coverage, collateral-damage probes | `lab/benign/background.py --profile web\|video\|update\|dns-burst\|idle\|mixed` (curl top-sites list, large downloads, iperf3 to labvictim, DNS bursts, NTP; runs on Kali/laptop) |
| `sandbox` | netns testbed with real nft and real traffic tools | sandbox or any Linux box | integration tests, regression | `lab/netns/testbed.sh` (from `v2/netns_testbed.sh`), `tests/netns/` |
| `mock` | synthetic pcaps plus `ground_truth.jsonl` (benign sessions over several fake MACs, plus every attack class) | offline, no root, no Pi | development when the Pi is unavailable, CI, pipeline smoke tests | `lab/mock/gen_pcaps.py` (scapy, seeded) and `lab/mock/replay.py` (pcap → `FlowEngine.feed` → core in-process at an accelerated clock). `pirewall-start --data-mode mock` and `capture.backend="replay"` run core against a pcap with no root |

Rule: `aggregate.py` refuses to combine envs. Only `pi-*` numbers go in the paper. Mock and sandbox runs are regression evidence only.

## 5. Evaluation protocol
Unchanged from PLAN_FINAL §5, except:
- Victim B is `labvictim` on the Pi.
- Benign thresholds and policy are frozen, and their hashes recorded, **before** campaign #2.
- Campaign #1 (dev) may be used for tuning; campaign #2 (eval) may not.
- `LIVE_AB.md` is reclassified as a "development replay" in the docs and paper.

## 6. `pirewall-start` v2 (spec for the prompt)
**New flags:**
- `--engine v1|v2`
- `--guards observe|enforce` (per-guard overrides: `--guard-input`, `--guard-forward`, `--guard-raw`)
- `--data-mode live|scripted|mock`
- `--panic`
- `--lab-victim up|down`
- `--manifest`

Existing flags are kept: `--check`, `--dry-run`, `--no-portal`, `--skip-nft`.

**Order of operations:**
1. **Preflight** (`--check` runs only this). The script refuses to start if any of these fail:
   - `nftables.service` is disabled, or its conf contains no `flush ruleset`.
   - `net.ipv6.conf.<lan>.disable_ipv6=1`.
   - libnftables or python3-nftables is importable from the venv (via a `.pth` file), or the fallback is reported.
   - `pirewall_native` imports and `HAS_PACKET_RING` is set, or the Python fallback is reported.
   - The NM lease file is readable.
   - chrony is synced.
   - The config has migrated to v2 (`migrate_config.py --check`).
   - Model artifacts exist and their hashes match the metadata sidecar.
   - The admin MAC is configured.
2. Render the templates and `nft -c` all of them (base, static, adaptive, portal).
3. Load base, then **static and adaptive** (declare, then flush chains, never delete the table).
4. Seed `pi_addrs`, `allow_bound` and bindings from config, static bindings and the lease file. If seeding fails, the raw guard verdict is set to **observe** and a warning is shown.
5. Set the guard verdicts from flags or config (defaults: input enforce, raw enforce if seeded, forward observe).
6. Start core, confirm it's ready, then the API, then the portal, then load `portal.nft`. This is the existing ordering rule.
7. Write the manifest: versions, hashes, modes, a ruleset dump, the env tag.

**Other paths:**
- `--panic`: delete both pirewall tables and print the restore command.
- `--data-mode mock`: no root and no nft. Core runs with `capture.backend=replay` against `lab/mock/out/*.pcap`, and the API runs on localhost.
- `--lab-victim up|down`: create or remove the `labvictim` netns, the `lab0` veth, its services and the lab-only forward allowance.

## 7. Deliverable structure
- `PLAN_v3.md` (this file).
- `prompts/phase-11 … phase-20` (Claude Code prompts, in the repo's prompt style).
- `RUNBOOK_PI.md` (the user's hour-by-hour Pi steps).
- `v2/` (tested templates, testbed, results).
- `critique_*.md`, `audit_new_main.md`.

**Copy the whole folder into the repo as `docs/v2/` before running phase-11.**

## 8. Phase order (Claude Code sessions) and increments
| Phase | Content | Depends | Parallel-safe with |
|---|---|---|---|
| 11 | ADDENDUM_4, V2_CONTRACTS, CLAUDE.md v2 rules, additive config sections, `migrate_config.py` | — | — |
| 12 | Access/hygiene: throttles, demo-account removal tool, allowlist re-auth, log dir, SANs, session timeout | 11 | 13, 15 |
| 13 | Kernel plane: templates, render, libnftables set backend, guard modes, kill switch/panic, reconcile, ruleset-diff invariant, netns tier | 11 | 12, 15 |
| 14 | Identity: MAC through native and Python, RuleTarget, BindingTable + lease sync, portal (ip,mac), allowlist MAC, validator v2, v1 adapter | 13 | — |
| 15 | Native hardening + pcap reader + `capture.backend=replay` + `scripts/dataset/pcap_to_flows.py` | 11 | 12, 13 |
| 16 | `pirewall-start` v2, systemd/tmpfiles/templates, `configure.py` MACs, `--data-mode`, lab victim netns | 13, 14, 15 | — |
| → | **v2.0 deployable**: kernel guards + anti-spoof + sets driven by the v1 pipeline | | |
| 17 | D1 (MAC-keyed, learned thresholds), K poller, policy engine + matrix tests, scoring → UI only, `pipeline.engine=v2` | 16 | 18 |
| 18 | Lab harness + data modes (benign capture, scripted generator, mock generator/replay), offline G5 evaluator + kernel-meter simulator, aggregate/manifests | 15 | 17 |
| → | **v2.1** | | |
| 19 | ML: schema 3.0.0 datasets from own pcaps, D2/D3 training/eval protocol, shortcut audit, reports | 17, 18 | — |
| 20 | Evaluation runbook execution support, docs reconciliation (KNOWN_ISSUES v2, PROGRESS, SETUP v2, README scope), paper tables from aggregate | all | — |

**Cut order if late:** the CIC-IDS2017 external test → the D3 family head → the meter-fill/MAC-churn campaigns → 1 h D1 windows → the Wazuh decoder → portal MAC binding.
