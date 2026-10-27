# Audit of new `main` @ 8b91b5f (merge of overhaul b26195a, 2026-10-16)

**Labels.** **[V]** means verified in this sandbox (x86_64, kernel 6.18, root). **[R]** means reasoned from code or docs.

**Scope of the change.** Commit b26195a touched 61 files (+5331/−329). It **did not change** `pirewall/firewall/`, `deploy/`, `pirewall/portal/`, `pirewall/api/`, `pirewall/detection/tls_fingerprint.py` or `scripts/deployment/pirewall-start` [V, `git diff --quiet`].

## 0. Verified facts

- **Test suite.**
  - `uv sync` followed by `pytest` gives 941 passed, 12 skipped, 1 failed [V].
  - With `uv sync --extra native` (built in about 32 s with the preinstalled cargo) it gives **951 passed, 2 skipped, 1 failed** [V].
  - The single failure is still `test_portal_rpc_socket.py::test_a_socket_in_the_wrong_group_is_refused`. It happens because the sandbox runs as root, and it fails on old main too.
  - `test_native_parity.py` and `test_core_daemon_native.py` both pass (10/10) [V].
  - `pirewall_native.HAS_PACKET_RING` is True [V].
- **Native capture benchmark, reproduced** [V]. I ran a netns/veth setup with hping3 `-S -i u100` (~12k frames/s) for 6 s per run:

  | Path | Frames/s | Drops |
  |---|---|---|
  | Python, no contention | 11.9k | 0% |
  | **Python + GIL contention** | 3.5k | **58.9%** |
  | Native, no contention | 12.7k | 0% |
  | **Native + GIL contention** | 9.8k | **0%** |

  This is the same shape as the overhaul's own REPORT.md, so its claim holds **on x86**. The Pi is still unmeasured, and REPORT.md says so honestly.
- **Scoring ceiling, numerical check** [V, `score_evidence` with the default `ThreatConfig`]:

  | Evidence | Without anomaly flag | With anomaly flag |
  |---|---|---|
  | Page load (diversity + repeated + frequency + burst) | 30 | 45 |
  | Scan alone | 55 | 70 |
  | Scan + burst + frequency | **75 (HIGH)** | **90 (CRITICAL)** |
  | Flood, or all patterns | **80 (HIGH)** | **95 (CRITICAL)** |

  The comment "BLOCK always needs corroboration" (`config/default_config.toml` ~L131) is only true if the Isolation Forest counts as corroboration. That forest still flags **10.3% of benign flows** (per LIVE_AB). So **behaviour plus a spurious anomaly flag reaches BLOCK.** The evidence-maturity gate passes on any pattern (`engine/decision.py:183`). In ACTIVE mode there is no approval step. Fast-path snapshots carry no ML evidence (`coordinator.analyze_snapshot`), so they cap at 80 and can only RATE_LIMIT. Completed flows can reach 95.
- **Model artifacts.**
  - Still gitignored and absent (`pirewall/ml/artifacts/` contains only `.gitkeep`) [V].
  - No hashes are recorded in the repo.
  - Training is still on the **CICFlowMeter CICIDS2017 CSVs** with a stratified random split (`docs/ML_PIPELINE.md` "Current real-data results").
- **Native engine and MAC addresses.** The native `FlowRecord`/`NewFlowRecord` carry **no MAC addresses**, and neither does the Python `Flow` [V, grep]. Any MAC-keyed identity in v2 needs new fields in the parser, the engine and the model.
- **Offline replay.** `FlowEngine.feed(frame, ts_us)` is exposed to Python (`native/src/lib.rs`, "replay and tests") [V]. A stdlib pcap/pcapng reader of about 50–80 lines is therefore all that's needed for **training data produced by the identical engine**. No pcap reader exists yet in `pirewall/` or `scripts/` [V].
- **Where the native engine runs.** It is in-process in **pirewall-core**, which holds CAP_NET_RAW and CAP_NET_ADMIN (`runtime/core.py:82,107`, `_select_capture` ~L413) [V].
- **Memory safety of the native engine.**
  - `parse.rs` contains 0 `unsafe` blocks and checks bounds explicitly before indexing [V].
  - `capture.rs` contains 19 `unsafe` sites for mmap, libc and ring walking. The ring walker trusts kernel-written offsets and `snaplen` without clamping them to `block_size`. The kernel is a trusted source, so this is acceptable, but a defensive clamp costs almost nothing [R].
  - `Cargo.toml` sets **`panic = "abort"`**. Any panic in the engine, reachable from packet data in theory, kills all of pirewall-core. That triggers fail-open, and after 3 crashes in 300 s systemd stops restarting it (`StartLimitBurst=3`). In effect this is a potential remote off-switch [R]. The parser looks panic-free, but it hasn't been fuzzed.

## 1. Status of the 25 flaws (from `Pirewall_v2_Audit_and_Plan.md`)

| # | Flaw | Status on new main | Evidence |
|---|---|---|---|
| 1 | Paper numbers can't be produced | **NOT FIXED** (the user says to ignore them; they must still be replaced) | No new attack-lab run on the Pi |
| 2 | Inflated ML metrics (random split) | **NOT FIXED** | Still a stratified random CICIDS split (ML_PIPELINE). LIVE_AB is a step forward but has circular tuning (see §2) |
| 3 | No reproducibility | **NOT FIXED** | Artifacts are gitignored with no hashes. LIVE_AB's `replay_score.py` was "kept in the session scratchpad" and not committed. Its pcaps aren't committed either |
| 4 | Train/serve skew | **PARTIAL** | Fixed: payload vs IP length, sample std, flag counts removed, 120 s active timeout, kernel timestamps (`features/schema.py`, `config/models.py:80`). Still different: CICFlowMeter ends flows at the first FIN and ignores RST, while pirewall ends them at RST or both FINs (`flow/timeout.py:19-22`); the 60 s inactive timeout has no CICFlowMeter equivalent; Ethernet-padding inflation remains in sums and means; protocol is still inferred heuristically in training; raw `destination_port` is still a feature; wired 2017 traffic vs Wi-Fi 2026 |
| 5 | CICIDS2017 label errors | **NOT FIXED** | Same CSVs. Engelen's TCP-appendix and attempted-attack artifacts are still in the training data |
| 6 | Classification only at flow completion | **PARTIAL** | The source-level fast path (`runtime/core.py:979-1012`) assesses behaviour within seconds, with a 10 s cooldown per source. ML still runs only on completed flows (up to 120 s) |
| 7 | Per-flow features blind to host-level attacks | **PARTIAL** | A FLOOD pattern was added (100 new connections/s to one destination), plus per-destination failure tracking. Detection is still keyed on source IP |
| 8 | Isolation Forest trained on another network | **PARTIAL** | CICIDS FPR went 0.0987→0.0498, and benign-replay anomalies 56%→10.3%. It is still trained on CICIDS, so 10% of benign flows flagged remains high in absolute terms |
| 9 | JA3/Heartbleed weak; flow statistics evadable | **NOT FIXED** | `tls_fingerprint.py` is unchanged |
| 10 | Scoring ceiling of 40 | **FIXED, with new risk** | Behaviour now caps at 80 → RATE_LIMIT. Behaviour plus anomaly reaches 95 → **BLOCK** (numbers above) |
| 11 | Absolute behaviour thresholds | **PARTIAL** | Real sliding window, per-destination counting, `opened_by_initiation`. Values still aren't set from this network |
| 12 | Everything keyed on source IP; LRU churn | **NOT FIXED** | No MAC anywhere. Random-source floods still create one source per packet |
| 13 | Adaptive chain only on `forward` | **NOT FIXED** | `firewall/backend/nftables.py:70` is still `"hook": "forward"`. Floods aimed at the Pi's open services (53, 8080), the very ones LIVE_AB "rate-limits", are not enforceable |
| 14 | Rules are src/32→dst/32:dport tuples | **NOT FIXED** | `generator.py:44-45` and `validator.py:254-261` (the dport is part of the duplicate key). LIVE_AB says decisions "collapse into one rule per source", which is **incorrect for scans**: each new destination port is a new rule, up to the A3 cap of 20/min |
| 15 | One rule per decision, `nft` subprocess per rule | **NOT FIXED** | Backend unchanged |
| 16 | Blocking can be weaponised (no anti-spoof) | **MADE WORSE in effect** | `base.nft.template:56` still accepts any `saddr` in the protected network, with no IP↔MAC binding. Behaviour alone can now RATE_LIMIT (80), and RATE_LIMIT needs no approval in ASSISTED mode. A Wi-Fi client spoofing a neighbour's IP with a SYN flood gets the neighbour rate-limited. Spoofed SYNs are still "initiations" [R] |
| 17 | Fail-open plus crash is an off-switch | **NOT FIXED, new trigger** | `StartLimitBurst=3`; `revert_to_base` (`manager.py:368`) is called by `_revert_ruleset_if_failing_open` (`core.py:700`). The native `panic=abort` adds another crash path |
| 18 | Python per-packet `recv`, ~94% drops | **PARTIAL** | Native TPACKET_V3 path is verified on x86 [V]. Not verified on the Pi; it's optional and needs a Rust toolchain on the Pi. The Python fallback now uses kernel timestamps and `SO_RCVBUFFORCE` |
| 19 | ~33 ms per flow, GIL-bound | **PARTIAL** | Per-packet work moved off the GIL. Per-flow Python work is still capped by the drain caps (1000 flows / 5000 signals per drain); beyond that the engine **sheds** flows and signals, which are counted but never assessed |
| 20 | History buffers evicted by floods | **NOT FIXED** | |
| 21 | Demo portal accounts live | **NOT FIXED** | Deployment state; KNOWN_ISSUES #4 is still "Observed" |
| 22 | Portal session = IP only; plaintext HTTP | **NOT FIXED** | `portal/` unchanged |
| 23 | Admin login has no throttle; admin trusted by IP | **NOT FIXED** | `api/` unchanged. `base.nft:79` admin rule has no `iifname` |
| 24 | Wi-Fi layer (PMF, deauth) | **NOT FIXED** | |
| 25 | IPv6 bypass if enabled | Unchanged (documented) | |
| minor | `session_timeout_seconds`, API log dir, cert SAN | **NOT FIXED** | KNOWN_ISSUES #15, #17, #9 still Observed |

## 2. Critical reading of LIVE_AB.md and REPORT.md

Both documents are honestly labelled: "NOT a Raspberry Pi", Docker/WSL2 VM, and they list their own caveats. Nothing in them looks fabricated, and the native-capture ratio reproduced here. They do **not** support the claims they imply, for these reasons:

1. **Circular tuning.** Pattern points were changed *after* a first run on the same `attacks.pcap` and `benign.pcap` ("busy-pattern points were lowered… SCANNING raised to 55 so the observed nmap pattern still reaches HIGH"). The FLOOD pattern and its 100/s threshold came from the same replay. The evaluation set was the tuning set, so these numbers are a fit to the data, not a test.
2. **Too little data.** It is a single run of each attack. The benign set is 780 flows of scripted curl traffic, not a phone or a home network.
3. **Decisions, not mitigation.** "Rate-limited within 0.06 s" is the time to a *decision* in an offline replay on packet clock. No rule was deployed. On the real daemon:
   - The Pi-targeted attacks (input path) would not be enforced at all (#13).
   - Scan decisions become one rule per port (#14).
   - RATE_LIMIT allows 10 pps per tuple, a limit nmap simply moves past.
4. **Not reproducible.** `replay_score.py` and both pcaps are not committed.
5. **Wrong model.** The old pipeline's v0.4.0 was a "repro" retrain, not the Pi's artifact. LIVE_AB itself says the Pi may be running the diverged v0.2.0.

**Verdict:** a useful diagnosis, but it can't be cited as evaluation. It belongs as "development replay" in the paper at most.

## 3. Offline pcap support in the native engine

`FlowEngine.feed(frame, ts_us)` already exists, so offline extraction is easy. About 1–2 h of work:
- A stdlib pcap/pcapng reader (DLT_EN10MB) feeding `feed`.
- A `sweep(now)`/`flush()` call at the end.
- Reuse of `pirewall.capture.native`'s conversion into `Flow` → `extract_features`.

That gives byte-identical training and runtime features, and it is the strongest fix for #4/#5: train on our own pcaps, not CICFlowMeter CSVs. To replay CICIDS2017 *pcaps*, use the same reader. Labels then come from IP plus time windows (Engelen's rules), not from the CSVs.

## 4. Impact on PLAN_FINAL.md

**Redundant now:**
- The NFStream sensor (§4.1/§4.4). The native engine gives TPACKET_V3, kernel timestamps and a GIL-free hot path, with parity tests, inside the project's own code. NFStream adds pandas/numpy, a Python per-packet loop (~12–18k pps estimated on the Pi), and seccomp and RCE surface.
  - **Recommendation:** drop NFStream. Keep the native engine and add a pcap replay entry point.
  - NFStream's one advantage, nDPI/JA4 and SNI context, is optional log enrichment only.
- The "fix the 40 ceiling" items.

**Conflicts with the new code:**
1. **The plan's policy table replaces the weighted sum, but new main has just retuned that sum.** Decide one of:
   - Keep scoring for UI/explainability only, with actions driven by the policy table (recommended).
   - Keep scoring as the decision driver, and at minimum make the anomaly contribution unable to push behaviour from HIGH to CRITICAL. For example: BLOCK requires an attack-class LightGBM verdict or a protocol signature, never anomaly.
2. **Schema.** The plan's "schema v2" (NFStream columns) collides with the existing `SCHEMA_VERSION = "2.0.0"`. Name the next one **3.0.0**: native-engine features on our own pcaps, `destination_port` as a category, MAC excluded from features but carried on `Flow`.
3. **Process split.** The plan's `pirewall-sensor` (CAP_NET_RAW only) now means moving the **native engine** out of core. Either:
   - Split it into a sensor process that sends `FlowRecord`s over a socket, accepting the extra latency; or
   - Accept the in-core engine, and mitigate with `panic=unwind` plus `catch_unwind` around `feed`, fuzzing `parse::parse` (cargo-fuzz, about 1 h), and clamping ring offsets.

   Given the 42 h budget, mitigation is the realistic choice.
4. **MAC identity.** Add `src_mac`/`dst_mac` to `parse.rs` → `FlowState` → `FlowRecord`/`NewFlowRecord`, and to the Python `PacketMetadata` and `Flow`, keeping the parity test. This is needed for MAC-keyed meters in core, `opened_by_initiation` by MAC, and lease binding.
5. **Config.** New keys exist: `capture.backend`, `native_max_*`, `flow.active_timeout_seconds=120`, `threat.behavior_pattern_points`, `behavior_weight=80`, `detection.source_assessment_cooldown_seconds`. Because of `extra="forbid"`, migration was already needed (`docs/DEPLOYMENT.md` §3.2). v2 must ship `migrate_config.py` covering both 1.x→2.0 and 2.0→v2.
6. **Load shedding.** Drain caps shed flows and signals. An attacker can flood to make the engine shed a concurrent scan's signals. The kernel guards in the plan (`input_guard` closed-port meter, per-MAC meters) cover this, so it stays a plan requirement.

**Still required unchanged:** everything in plan §4.2 (two tables, anti-spoof, input-hook coverage, set-based source-level actions, kill switch and panic), §4.3, §4.7, §4.9 (access fixes), and §5 (evaluation protocol, now also to stop circular tuning: freeze points and thresholds before any eval run).

## 5. Startup script and deploy templates: what v2 must change

`scripts/deployment/pirewall-start` (610 lines, unchanged by the overhaul) currently:
- Checks binaries.
- Renders templates.
- Loads `base.nft` (with `nft -c` first).
- Handles NM masquerade.
- Loads `portal.nft` after `pirewall-portal`.
- Starts the units.
- Snapshots the ruleset.

v2 additions:
1. **Preflight.**
   - Refuse if `nftables.service` is enabled with `flush ruleset`.
   - Check `disable_ipv6=1` on the LAN interface.
   - Check that `python3-nftables`/`libnftables1` is present, or report the fallback.
   - Report whether `pirewall_native` is importable and whether `HAS_PACKET_RING` is set.
   - Report the NM lease-file path and that it's readable.
   - Check chrony.
   - Record versions (nft, kernel, model hashes) to `/var/lib/pirewall/manifest.json`.
2. **Render and load.** Render and `nft -c` `pirewall_static` and `pirewall_adaptive` (declare plus flush chains, never `delete table`). Load them **after** `base` and **before** `pirewall-core` starts. Seed `pi_addrs`/`allow_bound`/bindings from config and the lease file, and if seeding fails, set the raw guard verdict to observe.
3. **Flags.**
   - `--guards observe|enforce` and `--engine v1|v2`.
   - `--panic`: delete both pirewall tables and leave base and portal.
   - `--data-mode live|scripted|mock` for dev and testing (see the next item).
4. **Data modes.**
   - `mock`: core runs on `FakeFlowCapture` or a pcap replay through `FlowEngine.feed`, with no root and no Pi.
   - `scripted`: a background-traffic generator.
   - `live`: wlan0.
5. **Base and portal templates.**
   - Pin the admin rule to `iifname eth0` plus the admin MAC (`base.nft:79`).
   - Pin DNS accepts to the LAN interface.
   - Make the portal `authed` set `ipv4_addr . ether_addr`, with a matching gate rule. This needs portal code changes.
6. **systemd.**
   - Add `ReadOnlyPaths=/var/lib/NetworkManager` (lease file) to core.
   - If the native engine stays in core, consider a separate `StartLimit` policy so a crash loop raises an alert rather than failing silently.
   - The tmpfiles entries for new state.
7. **`configure.py`.** Capture admin MAC and LAN interface MAC, and the static bindings.
