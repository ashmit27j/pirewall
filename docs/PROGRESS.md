# pirewall — Progress Tracker

Update this file at the end of every session. Use the labels defined in
`CLAUDE.md` ("Labeling honesty"): Implemented / Tested / Mocked /
Environment-dependent / Not yet validated.

## Phase status

| # | Phase | Status | Notes |
|---|-------|--------|-------|
| 1 | Foundation (config, core models, interfaces, exceptions) | Complete | Tested: enums, exceptions, all domain models, config loader (94 tests). ruff clean, pyright --strict clean (49 files). No packet capture/flow/ML/firewall/API logic added (non-goal). |
| 2 | Packet capture & parsing | Complete | Tested: parser (valid IPv4/IPv6/TCP/UDP/ICMP/ICMPv6 + exhaustive malformed/truncated cases), `FakePacketCapture`, capture->parse pipeline (`pirewall/capture/pipeline.py`), 34 new tests (128 total). Mocked: all capture-consumer logic exercised only against `FakePacketCapture`. Environment-dependent: `AFPacketCapture` (real Linux `AF_PACKET` socket, promiscuous mode, kernel drop stats) — implemented per spec §6 but requires a real Linux host, a real interface, and `CAP_NET_RAW` to exercise; cannot be run on the dev machine. A human must verify it on the target Pi (start it against a real interface, confirm packets/drops/malformed counts look sane under real traffic). ruff clean, pyright --strict clean (62 files, `pythonPlatform = "Linux"` pinned in pyproject.toml so Linux-only stdlib surface type-checks off-Linux too). |
| 3 | Flow aggregation & feature extraction | Complete | Tested: flow-key bidirectional normalization, `FlowState` accumulation (forward/backward attribution, TCP flag counts, `RunningStats` for packet-size/inter-arrival, bounded-memory per flow), `FlowTable` LRU eviction (flood-tested to 5000 flows against a 100-flow cap), active/inactive timeout + TCP FIN/RST completion, `FlowAggregator` end-to-end (including IPv6 packets never entering the table — ADDENDUM.md A5), and the canonical feature schema/extractor (determinism, schema versioning, zero-division guards). 40 new tests (168 total). ruff clean, pyright --strict clean (76 files). |
| 4 | Dataset adapters, preprocessing & ML training (dev machine) | Complete (pipeline); model quality Environment-dependent | See detailed notes below. |
| 5 | ML inference, behavior analysis & threat assessment | Complete | Tested: schema-mismatch refusal (model load-time and per-call), LightGBM/Isolation Forest loaders+predictors against real (placeholder) trained artifacts, `KnownEvidence`/`AnomalyEvidence` wrappers, deterministic behavior analysis (port-scan/SYN-flood-like/repeated-connection scenarios + bounded-state flood test to 5000 sources), scoring (hand-computed cases), and `ThreatAssessment` (determinism, explainability, level thresholds). 32 new tests (225 total). Environment-dependent: actual detection *accuracy* against real attacks — needs the spec §34 attack-lab exercise against a real-data-trained model, not this session's synthetic-fixture placeholder. ruff clean, pyright --strict clean (109 files). |
| 6 | Firewall decision, rule generation, validation & nftables backend | Complete | Tested: decision engine (threat-level -> action ladder), candidate generator (narrowest-possible /32 rules, ALLOW produces none), the full 10-stage validation chain in ADDENDUM.md order (schema/network/allowlist/safety/conflict/duplicate/rate-cap/priority/expiration/authorization — each independently tested, plus end-to-end via `FirewallManager`+`FakeFirewallBackend`), SHADOW/ASSISTED/kill-switch lifecycle branching, and backend-isolation + injection-safety security tests. 62 new tests (289 total). Environment-dependent: `NftablesBackend` against a real `nft` binary/ruleset — implemented via nft's JSON interface (spec §20) but requires a real Linux host, root/`CAP_NET_ADMIN`, and `nft` itself to exercise; a human must verify table/chain bootstrap, rule translation, and removal on the target Pi. |
| 7 | API, auth, security events & control panel | Complete | Tested: auth (password hashing/verification, sessions, Admin-PC-IP restriction), the full RPC dispatcher (every operation via `LoopbackRpcClient`), every API endpoint end-to-end via `TestClient` (login, admin-pc restriction, session enforcement, rules disable/remove/approve/reject, allowlist CRUD, kill-switch, route-surface enumeration), the control panel's HTML rendering (every spec §30 section + addendum sections, XSS-escaping, empty-state handling), and both A4 import-isolation checks (`pirewall/api/`, `pirewall/web/` never import capture/firewall.manager/firewall.backend). 53 new tests (344 total). Environment-dependent: `UnixSocketRpcServer`/`UnixSocketRpcClient` against a real `AF_UNIX` socket, and TLS with real certificates — both require a real Linux host (`socket.AF_UNIX` doesn't exist on this Windows dev machine) and are unverified here; `LoopbackRpcClient` exercises the exact same `CoreRpcDispatcher` logic in-process for everything else. See docs/ARCHITECTURE.md for the dependency decisions this phase made (stdlib `scrypt` over bcrypt/argon2, opaque tokens over JWT, hand-rolled HTML over Jinja2, uvicorn/httpx as FastAPI companions). |
| 8 | Raspberry Pi hardening, deployment & integrations (Wazuh/Netdata) | Complete | See detailed notes below. |
| 9 | Security/integration testing, docs & final validation | Not started | |

### Phase 4 details

Real CICIDS2017/UNSW-NB15 dataset files were **not found** on this machine
(checked common locations; none configured/present). Per the operator's
standing instruction, everything except real-dataset training quality was
still built and verified using small synthetic fixture data:  

- **Tested** — `load_cicids2017`/`load_unsw_nb15` adapters (11 tests):
  valid-row mapping, missing-value/invalid-value skip-and-count behavior,
  missing-required-column failure, missing-file failure with an actionable
  download message. Documented, honest limitations for each dataset's
  column-layout assumptions live in each adapter's module docstring and
  under "Known deviations" below.
- **Tested** — `train_lightgbm`/`train_isolation_forest` (the training
  pipeline itself), `pirewall/ml/artifacts/metadata.py` save/load
  round-trip, and the `scripts/train/train_lightgbm.py` /
  `train_isolation_forest.py` CLIs (missing-dataset-file exit code +
  message, successful end-to-end run) — all against synthetic fixtures
  (25 tests).
- **Mocked/placeholder** — this session ran both training CLIs against a
  70-row synthetic fixture CSV (generated by a throwaway script, not
  committed) and produced real artifact files at
  `pirewall/ml/artifacts/lightgbm_model.txt` and
  `pirewall/ml/artifacts/isolation_forest_model.joblib` (gitignored, not
  committed — they exist in this workspace only, purely so Phase 5 has a
  real artifact to load and test against). Both carry
  `ModelMetadata.is_placeholder = true` and an explicit
  `notes = "NOT trained on real data — placeholder for pipeline testing..."`.
  **The evaluation metrics in those metadata files (accuracy ≈0.83,
  isolation-forest precision ≈0.50) are pipeline sanity numbers on
  synthetic data — they are not, and must never be reported as, real
  detection performance.**
- **Environment-dependent** — real detection-performance numbers. To get
  them: download CICIDS2017 (CICFlowMeter "MachineLearningCVE" CSVs,
  https://www.unb.ca/cic/datasets/ids-2017.html) and/or UNSW-NB15
  (`UNSW_NB15_training-set.csv`/`testing-set.csv`,
  https://research.unsw.edu.au/projects/unsw-nb15-dataset), then run:
  `python -m scripts.train.train_lightgbm --dataset cicids --dataset-path <file> --model-version <version> --output-dir pirewall/ml/artifacts`
  (and the equivalent `train_isolation_forest` command) **without**
  `--placeholder`. Report the printed metrics back — do not hand-edit
  metadata files.

ruff clean, pyright --strict clean (93 files, 193 tests total).

### Phase 8 details

Goal: deployment artifacts + hardening documentation + Wazuh/Netdata
forwarding, without touching this session's real host network config,
systemd state, or nftables ruleset (spec §21, `CLAUDE.md`). Deliverables 1-7
from `prompts/phase-08-hardening-deployment-integration.md`, in order:

1. **Tested** — `pirewall/integration/wazuh.py` (`WazuhForwarder`,
   `format_event`, `SyslogWazuhTransport`) + `pirewall/integration/fake.py`
   (`FakeWazuhTransport`). Payload shaping (every populated `SecurityEvent`
   field maps to a structured dict key; unset optional fields are omitted;
   enabled/disabled no-op behavior; transport-failure propagation) — 5
   tests. `SyslogWazuhTransport` itself (the real TCP-socket transport) is
   **Environment-dependent**: it requires a real Wazuh agent/syslog
   listener on the Admin PC; see `docs/DEPLOYMENT.md` §8.
2. **Tested** — `pirewall/integration/netdata.py` (`NetdataExporter`,
   `snapshot_to_metrics`, `StatsdNetdataTransport`) +
   `pirewall/core/models/metrics.py` (`NetdataMetricsSnapshot`, a new
   Pydantic model covering every spec §33 metric plus the ADDENDUM.md A3
   addition: adaptive-rule creation rate and budget-fraction). Payload
   shaping (every spec §33 metric + the A3 addition present, correctly
   prefixed `pirewall.*`, booleans encoded 0/1; enabled/disabled;
   transport-failure propagation) — 5 tests. `StatsdNetdataTransport` (the
   real UDP StatsD transport) is **Environment-dependent**: requires a real
   Netdata instance with its StatsD collector enabled on the Admin PC; see
   `docs/DEPLOYMENT.md` §8. No running collector loop exists yet to
   periodically *build* a `NetdataMetricsSnapshot` from live state — see
   the "not yet built" note below.
3. **Implemented, Environment-dependent** — `deploy/network/` (README +
   three `${TOKEN}`-parameterized templates: IP forwarding/sysctl hardening,
   static LAN interface config, NAT/masquerade). Token substitution itself
   is **Tested** via `scripts/deployment/render_templates.py` (new CLI —
   loads a real `PirewallConfig`, substitutes `${TOKEN}`s, writes to
   `deploy/rendered/`, never applies anything) — 4 tests, including
   end-to-end rendering of every real checked-in template file with no
   leftover placeholders. Actually applying the rendered files to a real
   interface/kernel is Environment-dependent.
4. **Implemented, Environment-dependent** — `deploy/systemd/pirewall-core.service` +
   `pirewall-api.service` + README (the two-process split, ADDENDUM.md A4:
   dedicated non-root users, `pirewall-core`'s primary group is the shared
   `pirewall-ipc` group + `UMask=0117` for socket permissions,
   `pirewall-api` only holds `pirewall-ipc` as a supplementary group and
   has an explicitly empty `CapabilityBoundingSet=`/`AmbientCapabilities=`;
   ADDENDUM.md A6: `Type=notify`+`WatchdogSec=30s` +
   `Restart=on-failure`+`StartLimitBurst=3`/`StartLimitIntervalSec=300` on
   `pirewall-core`, matching `config.failure`'s defaults). **Tested**
   (static structure only) via `tests/security/test_systemd_hardening.py`
   — 13 tests parsing both unit files and asserting every required
   directive is present with the right value (including the A4 "verify
   capabilities are actually absent, not just unused" requirement). Real
   installation, real user/group creation, and real systemd
   capability/namespace enforcement are Environment-dependent — see
   `docs/DEPLOYMENT.md` §5, §7.
5. **Implemented, Environment-dependent** — `deploy/firewall/base.nft.template` +
   README: deny-by-default `forward`/`input` chains (policy `drop`),
   management access (SSH + the API port) scoped to `${ADMIN_PC_IP}` only,
   a deliberate `priority 10` (evaluated *after* the adaptive backend's
   `priority 0` `forward` chain — documented in both the template's
   comments and the README so a narrow adaptive block/rate-limit rule
   always gets first say). **Tested** (static structure only) via
   `tests/security/test_firewall_base_template.py` — 5 tests. Real `nft -c
   -f` syntax validation and real traffic filtering are Environment-dependent.
6. **Implemented** — `docs/SECURITY.md`: consolidates spec §27/§45 hardening
   guidance (OS, least privilege/service isolation, SSH, network exposure,
   secrets, filesystem, updates) with a summary table of every resource-
   exhaustion protection already built in Phases 1-7 (not new to this
   phase — cross-referenced, not reimplemented) and an explicit threat-model
   section for the two-process split.
7. **Implemented** — `docs/DEPLOYMENT.md`: step-by-step real-Pi deployment
   (OS setup -> packages -> template rendering/application -> service
   users -> certificates -> systemd units -> Admin PC Wazuh/Netdata setup
   -> secure update procedure), explicit about exactly which steps this
   session's tests can and can't verify.

**Known gap, intentionally not filled this phase:** `pirewall/main.py`
(the actual running process that wires capture -> flow -> features ->
detection -> engine -> firewall manager into one loop, sends `sd_notify`
watchdog heartbeats, and serves the RPC socket) and `pirewall/api/__main__.py`
(the equivalent entry point for `pirewall-api`) do not exist yet. Neither
was in this phase's explicit deliverable list (deployment *templates* and
hardening *documentation*, not new subsystem wiring), and Phase 9's prompt
explicitly says "do not add new subsystems... stop and report" rather than
improvise architecture there either. Both `.service` files' `ExecStart=`
lines reference these modules with an explicit `NOTE:` comment that they
don't exist yet — **do not start either systemd unit for real until they're
built.** Flagging this now as a real, load-bearing gap rather than
discovering it silently at Phase 9 or on real hardware.

ruff clean, pyright --strict clean (166 files), 376 tests total (32 new
this phase, up from Phase 7's 344: 5 wazuh + 5 netdata + 13
systemd-hardening + 5 firewall-base-template + 4 render-templates).

## Addendum items (`docs/ADDENDUM.md`)

Fill in as each is implemented — don't wait for Phase 9 for these, update as
you go since they land across several phases.

| Item | Status | Notes |
|------|--------|-------|
| A1 Shadow / dry-run enforcement mode | Implemented + Tested (Phase 6) | `FirewallManager` branches on `EnforcementMode.SHADOW`: an otherwise-approved candidate becomes `RuleStatus.SHADOWED`, never reaches the backend, and produces a "[shadow mode] would have ..." `SecurityEvent`. |
| A2 Static allowlist (outranks adaptive rules) | Implemented + Tested (Phase 6, 7) | Phase 6: validator stage as previously noted. Phase 7: `GET/POST/DELETE /api/v1/allowlist`, admin-only, control-panel section with add/remove — tested end-to-end via `TestClient`. |
| A3 Rate cap on rule creation | Implemented + Tested (Phase 6, 8) | `RuleCreationRateLimiter` (fixed window) backs the `rate_cap` validator stage; rejects with `RuleRejectionReason.RATE_LIMITED` once the window's budget is spent. Detection/`SecurityEvent` generation is untouched by the cap (the cap only ever runs after a `ThreatAssessment`/`FirewallDecision` already exist). Phase 8: `pirewall.core.models.metrics.NetdataMetricsSnapshot` adds `adaptive_rule_creation_rate_per_window`/`adaptive_rule_budget_fraction`, exported by `pirewall.integration.netdata` (payload shaping tested) — no live collector loop populates a snapshot from the real rate limiter yet, see Phase 8's "known gap" note above. |
| A4 Privileged/unprivileged process split | Implemented + Tested (pipeline); real transport and real two-process deployment Environment-dependent (Phase 7, 8) | Typed RPC protocol (`pirewall.ipc`): `CoreRpcDispatcher` (all 16 operations, fully unit-tested), `UnixSocketRpcServer`/`UnixSocketRpcClient` (real Linux `AF_UNIX` transport; this session's dev machine is macOS, not Linux, so this remains unexercised at runtime — `pyright`'s `pythonPlatform=Linux` pin only confirms it type-checks, not that it works), `LoopbackRpcClient` (in-process test double). `pirewall/api/`+`pirewall/web/` proven to never import `pirewall.capture`/`firewall.manager`/`firewall.backend` via an AST-based import-graph test. Phase 8: `deploy/systemd/pirewall-core.service`/`pirewall-api.service` implement the actual two-process deployment (dedicated users, `pirewall-core`'s primary group is the shared `pirewall-ipc` group + `UMask=0117` for the socket, `pirewall-api` only a supplementary member with an explicitly empty `CapabilityBoundingSet=`/`AmbientCapabilities=`) — static structure Tested (`tests/security/test_systemd_hardening.py`), real installation/enforcement Environment-dependent. Both units' `ExecStart=` reference `pirewall.main`/`pirewall.api.__main__`, which don't exist yet (see Phase 8's "known gap" note). |
| A5 IPv4-only v1 scope | Implemented + Tested (Phase 1, 2, 6) | Phases 1-2 as previously noted. Phase 6: the validator's `network` stage adds a belt-and-suspenders runtime check (tested via a `model_copy`-bypassed candidate, since the type system already makes a real IPv6 `CandidateRule` unconstructable). |
| A6 Fail-open default + systemd watchdog | Implemented (Phase 1, 6 groundwork); watchdog directives Implemented + Tested (static), real enforcement Environment-dependent (Phase 8) | `FailureMode` enum, `failure.mode` config (default `fail_open`), `failure.watchdog_sec`/crash-loop fields. Phase 6: `revert_to_base()` explicitly fails open (backend removal errors are swallowed; the manager's own state still marks rules `REMOVED`). Phase 8: `deploy/systemd/pirewall-core.service` sets `Type=notify`+`WatchdogSec=30s`+`Restart=on-failure`+`StartLimitBurst=3`/`StartLimitIntervalSec=300`, matching `config.failure`'s defaults — asserted present by `tests/security/test_systemd_hardening.py`. Nothing in `pirewall/` yet actually calls `sd_notify` (no `pirewall/main.py` exists to do so — see Phase 8's "known gap" note), so the real crash-loop-detection *behavior* remains entirely Environment-dependent, not just the systemd config around it. |
| A7 Assisted mode / BLOCK approval queue | Implemented + Tested (Phase 6, 7) | Phase 6: manager logic as previously noted. Phase 7: `POST /api/v1/rules/{id}/approve`/`/reject`, control-panel Approve/Reject buttons on `PENDING_APPROVAL` rules — tested end-to-end via `TestClient`. |
| A8 Emergency kill-switch | Implemented + Tested (Phase 6, 7) | Phase 6: `revert_to_base()` as previously noted. Phase 7: `POST /api/v1/firewall/kill-switch` (same auth/Admin-PC path as every other write endpoint) + a control-panel button with a JS confirmation step — tested end-to-end via `TestClient`. |

## Acceptance criteria reconciliation (spec §50)

Fill this in during Phase 9 — one line per bullet in §50, with a label.
Leave blank until then; don't pre-fill with guesses.

### Network
- [ ] packet capture —
- [ ] packet parsing —
- [ ] flow aggregation —
- [ ] bidirectional flows —
- [ ] flow timeouts —
- [ ] bounded state —
- [ ] canonical Flow —

### Features
- [ ] canonical schema —
- [ ] deterministic extraction —
- [ ] training/runtime compatibility —

### ML
- [ ] CICIDS2017 adapter —
- [ ] UNSW-NB15 adapter —
- [ ] preprocessing —
- [ ] LightGBM —
- [ ] Isolation Forest —
- [ ] training pipeline —
- [ ] model artifacts —
- [ ] metadata —
- [ ] compatibility validation —

### Detection
- [ ] known-attack evidence —
- [ ] anomaly evidence —
- [ ] behavioral analysis —
- [ ] threat scoring —
- [ ] explainable assessments —

### Firewall
- [ ] explicit decisions —
- [ ] structured rules —
- [ ] candidate generation —
- [ ] validation —
- [ ] conflict detection —
- [ ] duplicate detection —
- [ ] safety checks —
- [ ] expiration —
- [ ] enforcement —
- [ ] audit trail —

### Gateway
- [ ] WAN/LAN configuration —
- [ ] forwarding —
- [ ] routing —
- [ ] firewall forwarding —
- [ ] NAT where required —
- [ ] protected network —

### API
- [ ] FastAPI —
- [ ] authentication —
- [ ] TLS —
- [ ] certificate support —
- [ ] Admin PC restriction —
- [ ] safe administrative operations —

### Control Panel
- [ ] system health —
- [ ] network statistics —
- [ ] threats —
- [ ] detections —
- [ ] firewall rules —
- [ ] events —
- [ ] ML status —

### Integration
- [ ] Wazuh —
- [ ] Netdata/metrics —
- [ ] Admin PC communication —

### Raspberry Pi Security
- [ ] least privilege —
- [ ] service isolation —
- [ ] secure systemd configuration —
- [ ] SSH hardening —
- [ ] restricted network exposure —
- [ ] secret protection —
- [ ] filesystem permissions —
- [ ] resource limits —
- [ ] secure firewall management —
- [ ] secure update procedure —

### Testing
- [ ] unit tests —
- [ ] integration tests —
- [ ] ML tests —
- [ ] security tests —
- [ ] failure tests —
- [ ] mocked hardware tests —
- [ ] strict type checking —

### Deployment
- [ ] Raspberry Pi installation —
- [ ] network configuration —
- [ ] IP forwarding —
- [ ] firewall configuration —
- [ ] permissions/capabilities —
- [ ] systemd —
- [ ] certificates —
- [ ] Admin PC configuration —

### Documentation
- [ ] README —
- [ ] architecture —
- [ ] feature schema —
- [ ] ML pipeline —
- [ ] firewall —
- [ ] security —
- [ ] deployment —
- [ ] testing —
- [ ] Raspberry Pi hardening —

## Known deviations from spec

List anything implemented differently than `docs/MASTER_SPEC.md` says, with
the reason.

- **Phase 6 decision engine**: the `ThreatLevel -> FirewallAction` ladder
  (LOW->ALLOW, MEDIUM->MONITOR, HIGH->RATE_LIMIT, CRITICAL->BLOCK) is a
  deliberate, documented design choice (`pirewall.engine.decision`), not
  derived from spec text (spec §19 lists the four actions but doesn't
  prescribe a mapping) or from data.
- **Phase 6 rule priority**: `priority = round(100 - threat_score)` (higher
  threat -> lower number -> evaluated first). Spec §23 lists `priority` as
  a rule field but doesn't define how it's computed; this is a simple,
  explainable scheme, not tuned against real conflicting-rule scenarios.
- **Phase 6 nftables RATE_LIMIT translation**: implemented as *two* nft
  rules sharing one comment/rule-id (an `accept`-under-`limit` rule
  followed by an unconditional `drop`), since a bare nft `limit` statement
  alone doesn't drop excess traffic — it just stops matching, letting
  excess fall through. `NftablesBackend.remove_rule` deletes every nft
  rule tagged with that id's comment, so this stays transparent to callers.
- **Phase 6 kill-switch event type**: `revert_to_base()`'s summary event
  uses `SecurityEventType.SYSTEM_WARNING` (severity `WARNING`) — no
  existing event type in spec §31's list names "administratively removed
  rule(s)"; `SYSTEM_WARNING` is the closest fit and matches how ADDENDUM.md
  A6 itself describes a crash-loop event.
- **Phase 2 parser**: no 802.1Q VLAN tag support (an Ethernet frame with
  ethertype 0x8100 is treated as unsupported and rejected). Not required by
  spec §7. Revisit if a real deployment's switch port trunks VLAN-tagged
  traffic to the Pi.
- **Phase 7 SecurityEvent wiring scope**: the phase prompt asked to "wire
  event emission into the relevant Phase 2-6 modules where it's missing
  (capture errors, flow errors, model errors, firewall
  blocks/rejections/expirations)." Firewall events were already wired in
  Phase 6. This phase added an optional `on_event` sink to
  `pirewall.capture.pipeline.capture_packets` so malformed packets can also
  emit `CAPTURE_ERROR` (tested). Flow-error and model-error emission were
  **not** wired further: nothing before Phase 8 owns a running "main loop"
  that calls flow aggregation/inference and would catch those exceptions
  to turn into events — `pirewall.ipc.state.CoreStateStore.record_event`
  exists as the sink once that loop exists. Do this wiring as part of
  Phase 8's `pirewall/main.py`, not as a standalone follow-up — the natural
  place is wherever those calls actually happen in sequence.
- **Phase 7 FastAPI route introspection**: the installed FastAPI version
  wraps each `include_router()` call in an internal `_IncludedRouter`
  rather than flattening routes into `app.routes` directly — route
  enumeration (and any future code that needs to walk `app.routes`) must
  go through `route.original_router.routes` to reach the real `APIRoute`
  objects. See `tests/unit/test_api_routes.py::test_registered_route_surface_matches_spec`.
- **Phase 5**: `pirewall.engine.scoring`'s combination formula (known-attack
  weight * confidence; anomaly is a flat weight if flagged; behavior scales
  by fraction of possible pattern types detected — all weights from
  `config.threat`) is a deliberately simple, explainable design choice, not
  something tuned/validated against real attack traffic. Revisit once real
  CICIDS2017/UNSW-NB15-trained models and spec §34 attack-lab data exist.
- **Phase 5**: moved `is_attack_label` (dataset-label -> attack/benign)
  from `pirewall.ml.training.metrics` into a new `pirewall.ml.labels`
  module so both training-time evaluation and runtime scoring
  (`pirewall.engine.scoring`) share one definition instead of risking
  drift between two copies.
- **Phase 4**: pyright wasn't resolving the project's `.venv` at all when
  invoked as `python -m pyright` (it silently fell back to a different
  interpreter's `site-packages`, so `lightgbm` reported as unresolvable
  even though it was installed). Fixed by adding explicit
  `venvPath = "."` / `venv = ".venv"` to `[tool.pyright]` in
  `pyproject.toml`. Worth knowing if pyright ever again reports a real,
  installed dependency as missing.
- **Phase 4 CICIDS2017 adapter**: targets the specific "MachineLearningCVE"
  CICFlowMeter CSV column layout (real Source/Destination IP and port
  columns present); a stripped-down mirror without those columns will fail
  with a clear missing-column error rather than silently degrading.
  Combines CICIDS2017's separate forward/backward packet-size mean/std
  into one overall value via a standard pooled-variance formula
  (`pirewall.ml.preprocessing.common.combine_weighted_stats`), since our
  canonical `Flow` model stores one overall `packet_size_stats`, not a
  forward/backward split.
- **Phase 4 UNSW-NB15 adapter**: targets the `UNSW_NB15_training-set.csv`/
  `testing-set.csv` partition format, which has no source/destination
  IP/port columns and no per-packet TCP flag counts. `Flow.source_ip`/
  `destination_ip` are set to a fixed documented placeholder
  (`10.255.255.1`/`.2`), ports are `None`, TCP flags are always zero, and
  `packet_size_stats`/`inter_arrival_stats` only carry a real *mean*
  (min/max set equal to the mean, std set to 0.0) since this dataset
  variant reports per-flow means only, not per-packet distributions. All
  documented in the adapter's module docstring.
- **Phase 3**: `ruff`'s `line-length` was widened from 100 to 110 in
  `pyproject.toml` — the canonical feature schema table (28 named features
  with descriptions) kept tripping E501 at 100 without meaningfully
  improving readability by wrapping every row to multiple lines. 110 is
  still well within normal convention.
- **Phase 3 flow table eviction**: the bounded `FlowTable` evicts the
  least-recently-used flow (LRU, `OrderedDict`-based) when at capacity —
  spec §8 requires bounded size + an eviction policy but doesn't mandate a
  specific algorithm; LRU is the least likely to evict a still-active flow
  under normal traffic patterns.
- **Phase 3 packet-size/inter-arrival stats**: computed online via
  Welford's algorithm (`pirewall.flow.state.RunningStats`) instead of
  storing every packet size/timestamp per flow — keeps per-flow memory
  bounded regardless of flow length, same spirit as the bounded flow table
  itself.
- **Phase 2 parser**: IPv6 extension headers (hop-by-hop, routing,
  fragment, ...) are not walked. If `next_header` names one, the packet's
  protocol is reported as `Protocol.OTHER` instead of skipping past the
  extension header chain to find the real transport header. Spec §7 only
  requires TCP/UDP/ICMP/ICMPv6 support, and IPv6 is out of the adaptive
  pipeline for v1 anyway (ADDENDUM.md A5), so this only affects capture
  statistics accuracy for IPv6 traffic using extension headers, not
  detection.

- **Phase 8 `deploy/firewall/base.nft.template` table/priority design**:
  spec §24/§27 describe the desired *posture* (deny-by-default forwarding,
  restricted management access) but not how it should coexist with the
  adaptive backend's own nftables table. This session's design: a separate
  `inet pirewall_base` table (distinct from `pirewall.firewall.backend.nftables`'s
  `inet pirewall` table) whose `forward` chain uses `priority 10` —
  deliberately *after* the adaptive chain's `priority 0` — so a narrow,
  evidence-scoped adaptive `BLOCK`/`RATE_LIMIT` rule always gets first say
  over the broader base policy, including overriding traffic the base
  ruleset would otherwise allow. Not derived from spec text or tested
  against real conflicting traffic; documented in the template's own
  comments and `deploy/firewall/README.md`.
- **Phase 8 `integration.netdata_port` default changed from `19999` to
  `8125`**: the pre-Phase-8 default config had `netdata_port = 19999`,
  which is Netdata's *web dashboard* port, not a port anything pushes
  metrics to. Since `pirewall.integration.netdata.StatsdNetdataTransport`
  pushes metrics via the StatsD protocol (the standard way a non-web-server
  process feeds Netdata without running its own scrape endpoint), the
  default was corrected to `8125` (Netdata's StatsD listener default) and
  a new `integration.netdata_host` field was added (mirroring the existing
  `wazuh_host`) since a metrics push target needs a host, not just a port —
  this field didn't exist before Phase 8 and was a genuine gap, not a
  redesign of anything Phase 7 built.

## Open questions for the human

List anything Claude Code got stuck on or needs a decision on (e.g. real
dataset file locations, Admin PC IP, actual WAN/LAN interface names).

- **Phase 6 safety validation — "pirewall itself" / "management access":**
  spec §24's safety stage lists four things a candidate rule must never be
  able to block: pirewall itself, the Admin PC, management access, and the
  entire protected LAN/internet. `config.admin.admin_pc_ip` and
  `config.network.protected_network` give concrete values for two of the
  four; there's no distinct config field for "the Pi's own management
  address" or a general "management access" concept separate from the
  Admin PC. **Provisional, conservative choice made this session:** folded
  "pirewall itself" and "management access" into the existing Admin-PC-IP
  and whole-protected-LAN checks, on the reasoning that in this
  architecture management access to pirewall *is* "reach the Pi from the
  Admin PC" (spec §29: administrative access is restricted to the Admin PC
  IP), so protecting that IP already covers the concrete case. This passes
  every safety scenario this phase's test list actually enumerates. If you
  want a sharper, independent check (e.g. the Pi's own LAN-facing IP as a
  separate field from the Admin PC, for a deployment where they differ),
  add it to `AdminConfig` and extend `pirewall.firewall.validator._validate_safety`
  accordingly — the validator-stage structure makes this a small, isolated
  change.

- **Phase 8 — `pirewall/main.py`/`pirewall/api/__main__.py` don't exist
  yet:** every deployment artifact this phase built (`deploy/systemd/*.service`,
  `docs/DEPLOYMENT.md`) targets these two entry points, but building them
  was outside both this phase's explicit deliverable list and Phase 9's
  ("do not add new subsystems... stop and report" for anything requiring
  real new subsystem work). Concretely still missing: a `pirewall-core`
  main loop that wires capture -> flow -> features -> detection -> engine
  -> firewall manager together, sends `sd_notify` watchdog heartbeats
  (ADDENDUM.md A6), and serves the RPC socket (ADDENDUM.md A4) inside one
  running process; and a `pirewall-api` equivalent that loads config,
  builds a `UnixSocketRpcClient`, calls `pirewall.api.app.create_app`, and
  serves it with uvicorn+TLS. Neither systemd unit can actually be started
  until these land. **Provisional call made this session:** flag this
  clearly (in both `.service` files' comments, `docs/DEPLOYMENT.md`'s
  opening note, and here) rather than build it unasked — if you want this
  built, it's real implementation work beyond Phase 9's "close gaps,
  reconcile, don't add subsystems" scope, so it likely deserves being
  scoped as its own follow-up rather than folded silently into Phase 9.
