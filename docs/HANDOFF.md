# HANDOFF — start here if you are new to pirewall (human or model)

Last updated **2026-10-29**, after phase 17. This file is the shortest path
from zero to productive. It does not replace the rulebooks; it tells you
which ones to read, in what order, and where everything lives.

---

## 1. Where things stand

| | |
|---|---|
| Branch | `main` (v2 work merged in, fast-forward from the `v2` branch, 2026-10-29). Work on `main` from here on. |
| v1 (phases 1–10) | Complete. Ran on the real Pi (portal verified there). |
| v2 (phases 11–17) | Complete in code: kernel guards + adaptive sets + MAC identity + hardened native engine + `pirewall-start` v2 + D1/K detectors + policy engine. **Nothing from v2 has run on the Pi yet.** All of it is sandbox/mock-tested only. |
| Default engine | `pipeline.engine = "v1"` (the human decides when to flip to `"v2"`). |
| Next build phases | 18 (lab harness) → 19 (ML on schema 3.0.0) → 20 (evaluation, docs, paper tables). Prompts: `docs/v2/prompts/phase-18-*.md`, `phase-19-*.md`, `phase-20-*.md`. 18 can start now; 19 needs 18; 20 needs everything. |
| Next human steps | `docs/v2/RUNBOOK_PI.md`, stages H0 → H22 can run now. A model helping on the Pi uses `docs/v2/prompts/pi-session.md`. |
| Open risks | `docs/KNOWN_ISSUES.md` → "v2 open items". |
| Test baseline | 1914 passed / 39 skipped as `pw` in WSL, netns 34/34 as root (phase 17, env=sandbox). |

## 2. How to resume (a new session, any model)

1. Read `CLAUDE.md` (the contract; it overrides everything except the
   human). Then this file.
2. Read the top of `docs/PROGRESS.md` (the two status tables) and the
   section for the last completed phase. **PROGRESS.md is ~320 KB: read by
   section, never whole.** Use the headings (`### Phase 17 details`, etc.).
3. Pick the next prompt: `docs/v2/prompts/phase-18-lab-harness.md` unless
   PROGRESS says it is done. Follow its "Read first" list. For a v2 phase,
   always read `docs/ADDENDUM_4.md` and `docs/V2_CONTRACTS.md` in full and
   check the ownership table (§12) before editing any file.
4. Do the work, run the gates (§3), update PROGRESS with honest labels,
   commit, merge to `main`, push (§4).
5. If credits or context run out mid-phase: commit what is green with a
   `WIP phase-NN:` message that lists what is done and what is not, push it,
   and add a "Phase NN — in progress" note to PROGRESS saying exactly where
   you stopped. The next session reads that first.

### Precedence of the rulebooks (newest wins)

`MASTER_SPEC.md` (frozen) < `ADDENDUM.md` (A1–A8) < `ADDENDUM_2.md` (B1–B6)
< `ADDENDUM_3.md` (C1–C6) < `CLAUDE.md` v1 rules < `ADDENDUM_4.md` (D1–D9,
v2) together with `V2_CONTRACTS.md` (exact types, names, ownership). Design
rationale: `docs/v2/PLAN_v3.md` (authoritative), then `docs/v2/PLAN_FINAL.md`,
then the critiques in `docs/v2/critique_*.md`.

## 3. Running the gates

The dev host is Windows. Windows Python has no `AF_UNIX`/`fcntl`, so a
Windows-only `pytest` silently skips the socket/daemon tests: **never treat a
Windows run as a full verification.** Use WSL (Ubuntu, repo at
`/mnt/d/CodingProjects_D/pirewall`):

| Gate | Where | Command |
|---|---|---|
| Lint | anywhere | `uv run ruff check .` |
| Types | anywhere | `uv run pyright` (strict, configured in `pyproject.toml`) |
| Suite | WSL as user `pw` | `PATH=/home/pw/.local/bin:$PATH UV_PROJECT_ENVIRONMENT=/home/pw/pirewall-venv uv run pytest -q` |
| netns tier (real nft, real traffic) | WSL as root | `UV_PROJECT_ENVIRONMENT=/root/pirewall-venv uv run pytest -q tests/netns` (~80 s) |
| Rust | WSL as `pw` | `cd native && cargo test` (needs `PYO3_PYTHON`, `LD_LIBRARY_PATH`, `CARGO_TARGET_DIR`; see `native/fuzz/README.md`) |

Gotchas: run the suite as `pw`, not root (one permission test fails as
root); the tree is CRLF, so strip `\r` before feeding repo files to `nft` in
WSL; write multi-line edit scripts to a file (Git Bash heredocs mangle
backslashes) and always use `encoding="utf-8"`. After editing any
`*.nft.template`, run the netns tier: unit tests don't parse templates with
nft. Without WSL, run what you can and **say which tiers were skipped**.

## 4. Git workflow

- Commit to `main` and push to `origin main` at the end of every phase (the
  human's standing instruction, 2026-10-29). Ask the human before creating
  or pushing any other branch.
- Commit message: `phase-NN: <summary>`, then a body listing every
  deliverable with its honesty label (Implemented / Tested / Mocked /
  Environment-dependent / Not yet validated), the gate results with env tag,
  deviations, and what is handed to the next phase. Someone reading only
  `git log` should know the state.
- Never commit pcaps, datasets, model binaries, `config/local_config.toml`,
  certificates or household MACs (`.gitignore` covers most; check
  `git status` before committing).

---

## 5. Learning the project from the ground up

Read in this order: concepts (5.1), then the data path (5.2) end to end,
then whichever subsystem you are changing.

### 5.1 Concepts, by category

**A. Safety model (why the system is shaped the way it is)**
- *Detection → Decision → Enforcement are separate layers.* ML only produces
  evidence; it can never write a rule or run a command.
- *Single deploy path.* Only `FirewallManager` talks to a firewall backend,
  and only after the full validation chain.
- *Validation chain* (in order): schema → network → allowlist → safety →
  conflict → duplicate → rate cap → (v2: escalation) → expiration →
  authorization. Safety forbids locking out the Pi, the Admin PC,
  management, the whole LAN or the Internet.
- *Enforcement modes* (A1): `SHADOW` (log what would happen; default),
  `ASSISTED` (BLOCKs wait in an approval queue, A7), `ACTIVE`.
- *Allowlist* (A2) outranks everything. *Rate cap* (A3) bounds rule
  creation, not detection. *Fail-open* (A6) on core failure; v2 flushes
  only the adaptive sets. *Kill switch* (A8): SHADOW + flush + all guards to
  observe. *Panic* (v2): delete the v2 tables.
- *Process split* (A4, C1): `pirewall-core` (privileged, capture +
  enforcement), `pirewall-api` (admin panel, no capabilities, RPC only),
  `pirewall-portal` (LAN-facing, its own restricted RPC socket).

**B. The kernel data plane (v2, D1/D2)**
- Two kernel tables. `pirewall_static` is reviewed template policy: guards
  (anti-spoof, stateless meters, closed-port and new-connection meters) that
  keep working when core is dead; its binding sets (`macbind`,
  `allow_bound`) are written only by `FirewallManager.sync_bindings`.
  `pirewall_adaptive` holds the enforcement sets (`block_mac`, `block4`,
  `ratelimit_mac`, `ratelimit4`) that only `FirewallManager` writes, as
  elements with timeouts ≤ 3600 s.
- *Guard modes* `observe | enforce` per hook (raw, input, forward), separate
  from the enforcement mode. Defaults: input enforce, raw enforce if
  bindings were seeded, forward observe.
- *Offenders*: the kernel adds a MAC + code to `@offenders` when a meter
  trips. Meter membership is never evidence; `@offenders` is.

**C. Identity (D3)**
- A device is a `RuleTarget{ip, mac | None}`. MACs come only from the DHCP
  lease file and static bindings, through `BindingTable` and
  `FirewallManager.sync_bindings`. The raw guard drops a bound IP arriving
  from the wrong MAC (anti-spoof) and ARP poisoning.

**D. Packets → flows → features**
- Native Rust engine (`native/`, TPACKET_V3) produces flows; a Python path
  is the fallback after repeated panics (D6). Pcap replay feeds the same
  engine, so training rows equal live rows byte for byte.
- One canonical feature extractor and a versioned schema (2.0.0 now; 3.0.0
  is phase 19). A *connection start* is what D1 counts.

**E. Detection and decision**
- *v1 pipeline* (`engine = "v1"`, the baseline): behaviour patterns + ML
  scores → threat score → decision ladder → candidate rule.
- *v2 pipeline* (`engine = "v2"`): tier **K** (kernel offenders, polled
  every 1 s, `sustained_polls`), tier **D1** (deterministic per-MAC
  detectors with learned, frozen thresholds), **D2/D3** (Isolation Forest /
  LightGBM, MONITOR or corroboration only). A reviewable *policy table*
  maps evidence class × enforcement mode → action. Scores are display-only.

**F. Evaluation discipline (D7)**
- Every artifact has one *env tag*: `pi-live`, `pi-scripted`, `sandbox`,
  `mock`. Only `pi-*` numbers are Pi results; aggregation never mixes tags.
  Thresholds are frozen before the evaluation campaign; test sets are
  touched once.
- Honesty labels on every deliverable: Implemented, Tested, Mocked,
  Environment-dependent, Not yet validated.

### 5.2 The data path, file by file

```
NIC ─► native/src/capture.rs (TPACKET_V3) ─► native/src/parse.rs ─► native/src/flow.rs
        │ (fallback) pirewall/capture/af_packet.py ─► capture/parser.py ─► flow/aggregator.py
        ▼
pirewall/flow/native.py (NativeFlowAggregator) ─► flow/connection_start.py
        ▼
pirewall/features/extractor.py + schema.py ─► FeatureVector
        ▼
 v1: detection/{behavior,known_attack,anomaly,tls_*}.py ─► detection/coordinator.py
     ─► engine/{scoring,threat,decision}.py ─► firewall/generator.py        (runtime/pipeline.py)
 v2: detection_v2/{kernel,d1,thresholds}.py (+ D2/D3 evidence) ─► policy/{engine,table}.py
                                                                             (runtime/pipeline_v2.py)
        ▼
firewall/manager.py ─► firewall/validator.py ─► firewall/rate_limiter.py
        ▼
firewall/backend/nftables_sets.py (v2 sets) | backend/nftables.py (v1 rules) ─► kernel
```

All of it runs inside `runtime/core.py` (`CoreDaemon`), started by
`pirewall/main.py`, brought up by `scripts/deployment/pirewall-start`.

### 5.3 File map by subsystem

**Rulebooks and status** — `CLAUDE.md`; `docs/MASTER_SPEC.md`;
`docs/ADDENDUM.md`, `ADDENDUM_2.md`, `ADDENDUM_3.md`, `ADDENDUM_4.md`;
`docs/V2_CONTRACTS.md`; `docs/PROGRESS.md`; `docs/KNOWN_ISSUES.md`;
`docs/v2/PLAN_v3.md`, `PLAN_FINAL.md`, `critique_*.md`, `audit_new_main.md`;
`docs/v2/v2/` (the sandbox-tested nft prototypes and their results).

**Core vocabulary and models** (`pirewall/core/`) — `enums.py` (every
finite value set), `exceptions.py`, `logging.py`; `models/` (Pydantic domain
objects: `packet`, `flow`, `feature_vector`, `evidence`, `evidence_v2`,
`behavior`, `threat`, `decision`, `rule`, `policy`, `identity`, `allowlist`,
`event`, `portal`, `metrics`, `status`, `capture_stats`, `model_metadata`,
`detection_record`, `common` incl. MAC types); `nft_names.py` (every nft
object name; never spell one inline); `binding_table.py` (interface) and
`bindings.py` (lease parser + table); `network_drift.py` (config vs kernel
addresses at startup); `passwords.py`; `throttle.py`.

**Config** — `config/default_config.toml` (every threshold, with comments);
`pirewall/config/models.py` (validated sections, `extra="forbid"`, additive
only); `loader.py`; `config/d1_thresholds.toml` (D1, floors until fitted);
`config/known_tool_fingerprints.toml` (JA3, v1).

**Capture** (`pirewall/capture/`) — `interfaces.py` (Protocol),
`af_packet.py` (Python real), `native.py` (Rust ring), `fake.py`,
`parser.py`, `pipeline.py`, `replay.py` (pcap as a capture backend),
`pcapio.py` (stdlib pcap/pcapng). Native engine: `native/src/{capture,parse,flow,lib}.rs`,
`native/tests/properties.rs`, `native/fuzz/`, `typings/pirewall_native.pyi`.

**Flows and features** — `pirewall/flow/{key,state,timeout,aggregator,native,fallback,connection_start}.py`;
`pirewall/features/{schema,extractor}.py`; `docs/FEATURE_SCHEMA.md`.

**Detection v1** — `pirewall/detection/{behavior,known_attack,anomaly,tls_fingerprint,tls_heartbeat,coordinator}.py`;
`pirewall/engine/{scoring,threat,decision}.py`.

**Detection v2 and policy** — `pirewall/detection_v2/kernel.py` (K poller),
`d1.py` (detectors), `thresholds.py` (file format, clamp, freeze);
`pirewall/policy/table.toml` (the policy, as data), `table.py` (loader and
D4 checks), `engine.py`; `scripts/train/fit_d1_thresholds.py`.

**Enforcement** (`pirewall/firewall/`) — `manager.py` (the single deploy
path, kill switch, panic, bindings sync, guard modes), `validator.py`,
`generator.py` (v1 decision → candidate), `rate_limiter.py`,
`allowlist_store.py`, `local_addresses.py`, `sets.py` (rule → set element),
`guards.py`, `interface.py`; `backend/{nftables,nftables_sets,nft_transport,fake,fake_sets}.py`;
`docs/FIREWALL.md`.

**Kernel templates** — `deploy/firewall/base.nft.template` (base policy,
admin access), `pirewall_static.nft.template` (guards),
`pirewall_adaptive.nft.template` (sets), `portal.nft.template`;
`deploy/lab/pirewall_lab.nft.template` (lab victim forwarding);
`deploy/network/*` (NAT, sysctl, dnsmasq, dhcpcd templates).

**Runtime orchestration** (`pirewall/runtime/`) — `core.py` (`CoreDaemon`:
threads for capture, detection, watch/K-poll, lease sync, RPC), `pipeline.py`
(v1), `pipeline_v2.py` (v2), `lease_sync.py`, `forwarder.py` (every event
goes through it), `metrics.py`, `watchdog.py` (sd_notify); entry point
`pirewall/main.py`.

**IPC** (`pirewall/ipc/`) — `protocol.py`/`protocol_v2.py` (typed
operations), `server.py`/`client.py`/`_framing.py` (AF_UNIX transport),
`dispatcher.py` (`CoreRpcDispatcher`), `portal_dispatcher.py` (the
restricted portal surface), `portal_service.py` (core-side portal logic),
`state.py`/`history.py` (bounded history), `snapshots.py` (lock-free v2
reads), `loopback.py` (test double).

**API and control panel** — `pirewall/api/` (`app.py`, `auth.py`,
`throttle.py`, `schemas.py`, `routes/*`; entry `__main__.py`);
`pirewall/web/{render,routes,v2_panel}.py`; `docs/API.md`.

**Captive portal** — `pirewall/portal/{app,routes,render,sessions,store,demo_policy}.py`;
`scripts/deployment/portal_users.py`.

**ML** — `pirewall/ml/preprocessing/` (CICIDS/UNSW adapters, v1),
`training/` (trainers, metrics, report, resampling), `inference/` (loader
with schema guard, predictors), `artifacts/metadata.py`, `labels.py`;
`scripts/train/train_{lightgbm,isolation_forest}.py`;
`scripts/dataset/pcap_to_flows.py` (own pcaps → rows); `docs/ML_PIPELINE.md`,
`docs/ML_DATA_AUDIT.md`.

**Integrations** — `pirewall/integration/{wazuh,netdata,fake}.py`;
`deploy/wazuh/pirewall_decoder.xml`.

**Deployment** — `scripts/deployment/pirewall-start` (bash: preflight, load
order, data modes, panic, lab victim, manifest) and `startup.py` (its Python
half); `configure.py` + `discovery.py` (write `local_config.toml`);
`migrate_config.py`; `render_templates.py`; `install_nftables_pth.sh`;
`lease_check.py`; `make_certs.sh`; `deploy/systemd/*` (units, tmpfiles,
crash-loop alert); `docs/SETUP.md`, `setup-new-network.md`,
`docs/DEPLOYMENT.md`, `docs/DEPLOYMENT_COMPLETE.md`, `docs/SECURITY.md`.

**Evaluation (phase 18+)** — `lab/**` (not yet written); `benchmarks/`
(dated measurement folders; `v2-native-pi/` is the Pi capture benchmark,
written, not run); `docs/v2/RUNBOOK_PI.md`.

**Tests** — `tests/unit` (pure logic), `tests/integration` (whole daemon,
real AF_UNIX, mock end to end), `tests/security` (privilege boundaries,
import-graph rules, injection), `tests/ml`, `tests/system`, `tests/netns`
(root, real nft and traffic in network namespaces), `tests/helpers`,
`tests/fixtures`; `docs/TESTING.md`.

**Phase prompts** — v1: `prompts/phase-01…09`; v2:
`docs/v2/prompts/phase-11…20`, `pi-session.md`.
