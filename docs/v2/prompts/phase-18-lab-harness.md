# Phase 18: lab harness, data modes, offline G5 evaluator and aggregation

**Read first:**
- `CLAUDE.md` (v2 section), `docs/HANDOFF.md`
- `docs/ADDENDUM_4.md` D7 (data modes, env tags, the no-mixing rule)
- `docs/V2_CONTRACTS.md` §8 (`[lab]` config), §12 (ownership), §13
- `docs/v2/PLAN_v3.md` §2 (G1–G8), §4 (data modes), §5
- `docs/v2/PLAN_FINAL.md` §5 (campaigns, splits, metrics, harness file list)
- `docs/v2/critique_safety_eval.md` and `docs/v2/critique_ml.md` (evaluation design)
- `docs/v2/RUNBOOK_PI.md` (which steps call which harness command)
- `scripts/dataset/pcap_to_flows.py` (its row format, `manifest.json` and `ground_truth.jsonl` format are the inputs you build on)
- `scripts/train/fit_d1_thresholds.py` and `pirewall/detection_v2/{d1,thresholds}.py` (the offline evaluator must call the same `D1State.measure_*` functions)
- `pirewall/policy/` (the offline evaluator maps evidence to actions through the real policy engine)
- `scripts/deployment/pirewall-start` (`--data-mode`, `--lab-victim`, the manifest) and `scripts/deployment/startup.py`
- `deploy/firewall/pirewall_static.nft.template` and `scripts/deployment/render_templates.py` (meter rates and bursts)

**Depends on:** phase 15 (pcap reader/writer, replay, `pcap_to_flows`) and phase 16 (`pirewall-start`). Phase 17 is complete, so the evaluator can use D1 and the policy engine directly.

**Owns:** `lab/**`, `tests/unit/test_lab_*.py`, `tests/integration/test_lab_*.py`, the `lab` optional-dependency group in `pyproject.toml` (scapy, dev/lab only), and this phase's PROGRESS row and section. **Integrator files are not yours:** `pirewall/runtime/core.py`, `pirewall/firewall/manager.py`, `pirewall/ipc/dispatcher.py`. If you need something from them, use their public API; if that is impossible, stop and record a hand-over for the human, do not edit them.

## Goal
Every number the project will ever report can be produced by a script, from hashed inputs, with exactly one env tag, and re-checked later. Developers without the Pi get realistic mock traffic with ground truth. The forward guard can be judged safe to enforce (G5) offline, before anyone flips it.

## Deliverables

### 1. Layout and conventions
`lab/README.md` describes the layout below, the env tags and the no-mixing rule. Every script:
- is stdlib + the project's own packages (`pirewall.*`, `scripts.*`); only `lab/mock/gen_pcaps.py` may import scapy, and nothing under `pirewall/` ever imports `lab/` or scapy (add an import-graph test);
- writes outputs under a run directory with a `manifest.json` (see 5) and never into the repo's tracked tree; `lab/**/out/`, `lab/runs/` and `lab/data/` are gitignored, and pcaps are never committed;
- takes `--env-tag` only where the tag cannot be read from an input manifest, never defaults to a `pi-*` tag, and refuses `pi-*` off a Pi (reuse `startup.py`'s Pi detection rather than writing a second one).

### 2. Data modes (PLAN_v3 §4)
- **`lab/capture/benign_capture.sh`** (pi-live). `tcpdump -ni <lan_if> -s 128 -G 3600 -w <dir>/benign-%Y%m%d%H.pcap`, interface and directory from config/flags. A disk watchdog stops capture at 85% full of the target filesystem and logs why. A consent banner must be acknowledged (`--i-have-consent` for unattended restarts). A lab-MAC exclusion list (attacker/lab devices) is written into the capture manifest so later tools can drop those MACs; do not BPF-filter them out at capture time (the evaluator needs to see them to exclude them by window). `start|stop|status` subcommands; a systemd-run or nohup recipe in the README, not a new unit file.
- **`lab/benign/background.py`** (pi-scripted, runs on the client devices, not the Pi). Profiles `web|video|update|dns-burst|idle|mixed`: curl-equivalents over a top-sites list, large downloads, iperf3 to `labvictim`, DNS bursts, NTP. Each run writes a `ground_truth.jsonl` window per profile segment labelled `benign:<profile>` with the device's MAC and wall-clock times. Stdlib only (it runs on Kali/laptops without the project venv), external tools optional and detected.
- **`lab/mock/gen_pcaps.py`** (mock). Seeded, deterministic (same seed ⇒ byte-identical pcaps, tested). Benign sessions over several fake unicast MACs (web, DNS, NTP, a phone waking up, an OS update, P2P), plus one pcap per attack class: SYN/UDP/ICMP flood (fixed and random source), vertical scan at T4/T3/T2 pacing, horizontal scan, masscan-like, hydra-like SSH and HTTP brute force, portal brute force, slowloris, IP spoof of a bound neighbour, ARP poisoning, MAC churn / DHCP lease starvation. Writes `lab/mock/out/*.pcap` and one `ground_truth.jsonl` in exactly the format `pcap_to_flows.py --ground-truth` reads. Uses `pirewall.capture.pcapio`'s writer for the file format; scapy only to build frames.
- **`lab/mock/replay.py`**: a thin driver that runs `pirewall-start --data-mode mock --pcap …` (or core in-process with `capture.backend = "replay"`) at an accelerated clock, collects decisions/events over RPC, and writes a run directory tagged `mock`. After this phase `pirewall-start --data-mode mock --check` works without `--pcap` once `gen_pcaps.py` has run.
- Switch phase 17's `tests/integration/test_v2_engine_mock_end_to_end.py` to use the generated mock pcaps when present (inline fixtures stay as the fallback). That test file is phase 17's; this edit is additive and is the only one allowed.

### 3. Campaign harness (PLAN_FINAL §5; runs on the Pi, root)
- **`lab/campaigns/*.toml`**: campaign spec: `phase = "dev" | "eval"`, attacks with N (5 for floods and scans, 3 otherwise), parameters, the random-order seed, cooldown rule.
- **`lab/attacks/*.sh`**: one per attack (hping3 floods incl. `--rand-source` and neighbour spoof, nmap -sS T4/T3/T2, masscan as the held-out tool, hydra SSH/HTTP, portal brute force, slowloris, arpspoof/arping poisoning, MAC churn). Each runs **on the attacker host** and **refuses any target outside the lab**: the Pi's LAN address, the `[lab]` victim network, or an explicit `--lab-target` that is inside `network.protected_network`. `--dry-run` prints the command. Record tool versions.
- **`lab/preflight.py`**: the Pi side is ready: `pirewall-start --check` passes, `labvictim` up, chrony offsets of every host within bound, thresholds file present, sets empty, disk space; prints the manifest fields it will record.
- **`lab/run_campaign.py`**: randomized order from the seed; for each run: start victim-side capture, start legitimate-client throughput probe, mark `t0`, trigger the attack (over SSH to the attacker host; host/user from flags), poll state, stop, cool down until the adaptive sets are empty (poll, never kill-switch), write the run directory. `phase = "eval"` refuses unless `verify_manifest.py` confirms the D1 thresholds file has `frozen = true` and records the thresholds and policy-table hashes.
- **`lab/poll_state.py`**: reads core over the RPC socket as a member of `pirewall-ipc` (read-only operations only: offenders, bindings, guard modes, engine stats, rules, events). Never imports `pirewall.firewall.backend` or `pirewall.capture`.
- **`lab/capture.sh`**: victim-side pcap (inside `labvictim` for the forward path, on the Pi input path for Victim A) for TTM.
- **`lab/score_run.py`**: per run: TTD (first evidence/decision event − `t0`), TTM measured victim-side (first instant after which attacker packets reaching the victim stay below a documented fraction of the offered rate), mitigation effectiveness, collateral damage (wired and Wi-Fi legitimate clients separately), admin API p95 during the attack (G1).

### 4. Offline G5 evaluator — `lab/benign_fp.py`
Over `pcap_to_flows` output of all clean benign hours (lab MACs and windows excluded by their manifests):
- run D1 through the same `D1State.measure_*` code core runs, with the thresholds file given;
- run a **kernel-meter simulator** (`lab/meter_sim.py`): per-MAC token buckets reproducing the static template's meters (rate **and** burst, timeouts, set sizes, fail-open when full). Rates and bursts come from the same config keys `render_templates.py` substitutes, or are parsed from the rendered template, never retyped;
- optionally D2/D3 when model artifacts are given;
- map every evidence bundle through the real `pirewall.policy` engine for each enforcement mode;
- report enforce actions and MONITORs per device-hour, with the rule-of-three upper bound (3/T) when zero and a Poisson 95% CI otherwise, pi-live and pi-scripted separately;
- print an explicit verdict line for the forward guard: **"forward guard may enforce: yes/no"** with the reason. It never changes the guard itself.

### 5. Manifests and aggregation
- **`lab/manifest.py`**: one schema for run, capture, dataset and evaluator manifests: git SHA + dirty flag, config hash, model and thresholds hashes, policy table hash, ruleset hash (from `pirewall-start`'s manifest), `pipeline.engine`, enforcement and guard modes, tool versions, chrony offsets, the env tag, and a sha256 for every file in the run directory.
- **`lab/verify_manifest.py`**: recompute hashes, fail on any mismatch or missing file, check the frozen-thresholds rule for eval runs.
- **`lab/aggregate.py`**: medians and CIs per attack/metric over run directories. **Refuses** (non-zero exit, names the offending runs) to combine different env tags, and refuses dev and eval runs in one table. Output is machine-readable (JSON + CSV) with the env tag in every row and in the filename; phase 20 turns it into paper tables.

## Tests
- `gen_pcaps.py`: deterministic by seed; every attack class present in `ground_truth.jsonl`; `pcap_to_flows` labels attack flows with the right class and benign flows `benign`.
- Meter simulator: token-bucket semantics incl. burst, timeout expiry, fail-open when the meter set is full; a 3 s flood that fits inside the burst does not trip it (PLAN_FINAL §1.2).
- `benign_fp.py` on mock data: the attack MACs are flagged, the benign MACs stay at zero enforce actions; rule-of-three and Poisson CI computed correctly on hand-made counts.
- `aggregate.py` refuses mixed env tags and mixed dev/eval; `verify_manifest.py` catches a changed byte and a missing file.
- `run_campaign.py --dry-run` with a fake poller and fake SSH: order is a deterministic function of the seed; cooldown waits until sets are empty; `eval` refuses an unfrozen thresholds file.
- Each `lab/attacks/*.sh --dry-run` refuses an out-of-lab target.
- Import-graph test: nothing under `pirewall/` imports `lab` or `scapy`.

## Non-goals
No ML training (phase 19). No paper tables (phase 20). No change to detectors, policy table, thresholds or guard defaults. No edit to the integrator files. Never run an attack tool in this session against anything except a netns created by the test itself.

## Definition of done
- `ruff check .`, `pyright` (strict) clean; `pytest` green as `pw` in WSL, `tests/netns` green as root (see `docs/HANDOFF.md` §"Running the gates").
- `uv run python lab/mock/gen_pcaps.py --seed 1` then `scripts/deployment/pirewall-start --check --data-mode mock` exits 0 without `--pcap`.
- PROGRESS row 18 and a "Phase 18 details" section with honest labels; PROGRESS marks **v2.1** (engine + harness).
- V2_CONTRACTS §12 row for 18 confirmed; `docs/v2/RUNBOOK_PI.md` steps that call harness commands checked against the real CLI and corrected if needed.
- Environment-dependent (RUNBOOK): benign capture on the Pi, scripted profiles from client devices, campaigns #1 and #2, the offline G5 run on real `pi-live` data.
- Commit with a message that lists every deliverable and its label, merge to `main`, push (see `docs/HANDOFF.md` §"Git workflow").
