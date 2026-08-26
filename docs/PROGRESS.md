# pirewall — Progress Tracker

Update this file at the end of every session. Use the labels defined in
`CLAUDE.md` ("Labeling honesty"): Implemented / Tested / Mocked /
Environment-dependent / Not yet validated.

## Phase status

| # | Phase | Status | Notes |
|---|-------|--------|-------|
| 1 | Foundation (config, core models, interfaces, exceptions) | Complete | Tested: enums, exceptions, all domain models, config loader (94 tests). ruff clean, pyright --strict clean (49 files). No packet capture/flow/ML/firewall/API logic added (non-goal). |
| 2 | Packet capture & parsing | Not started | |
| 3 | Flow aggregation & feature extraction | Not started | |
| 4 | Dataset adapters, preprocessing & ML training (dev machine) | Not started | |
| 5 | ML inference, behavior analysis & threat assessment | Not started | |
| 6 | Firewall decision, rule generation, validation & nftables backend | Not started | |
| 7 | API, auth, security events & control panel | Not started | |
| 8 | Raspberry Pi hardening, deployment & integrations (Wazuh/Netdata) | Not started | |
| 9 | Security/integration testing, docs & final validation | Not started | |

## Addendum items (`docs/ADDENDUM.md`)

Fill in as each is implemented — don't wait for Phase 9 for these, update as
you go since they land across several phases.

| Item | Status | Notes |
|------|--------|-------|
| A1 Shadow / dry-run enforcement mode | Implemented (Phase 1 groundwork) | `EnforcementMode` enum, `RuleStatus.SHADOWED`, `firewall.enforcement_mode` config (default `shadow`). Manager branching is Phase 6. |
| A2 Static allowlist (outranks adaptive rules) | Implemented (Phase 1 groundwork) | `AllowlistEntry` model, `firewall.allowlist` config (seed, empty by default). Validator stage + storage is Phase 6. |
| A3 Rate cap on rule creation | Implemented (Phase 1 groundwork) | `firewall.max_adaptive_rules_per_window` / `rate_window_seconds` config fields. Validator stage + counter state is Phase 6. |
| A4 Privileged/unprivileged process split | Not started | Socket protocol is Phase 7; systemd units are Phase 8. |
| A5 IPv4-only v1 scope | Implemented (Phase 1 groundwork) | `Flow`, `CandidateRule`/`FirewallRule`, `AllowlistEntry`, `BehaviorAssessment`, `ThreatAssessment` all use `IPv4Address`/`IPv4Network` fields — an IPv6 value cannot be constructed at all. Parser-level IPv6 handling is Phase 2. |
| A6 Fail-open default + systemd watchdog | Implemented (Phase 1 groundwork) | `FailureMode` enum, `failure.mode` config (default `fail_open`), `failure.watchdog_sec`/crash-loop fields. Watchdog wiring is Phase 8. |
| A7 Assisted mode / BLOCK approval queue | Implemented (Phase 1 groundwork) | `RuleStatus.PENDING_APPROVAL`, `firewall.assisted_review_threshold` config. Manager logic is Phase 6. |
| A8 Emergency kill-switch | Not started | Depends on `firewall/manager.py` (Phase 6) and the API (Phase 7). |

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

## Open questions for the human

List anything Claude Code got stuck on or needs a decision on (e.g. real
dataset file locations, Admin PC IP, actual WAN/LAN interface names).
