# pirewall — Testing Guide (spec §39)

## Running the suite

```sh
uv sync                       # installs dev dependencies (pytest, ruff, pyright)
uv run pytest                 # full suite
uv run pytest tests/unit      # one tier at a time — see below
uv run ruff check .
uv run pyright                # strict mode, per pyproject.toml
```

All 664 tests run without root, without a real NIC, and without a real
`nft` binary or real datasets — see "Fakes vs. real hardware" below for
exactly what that means and doesn't mean. Almost every test also needs no
real trained ML model: `tests/ml/` and the performance smoke pass each
train a fresh tiny placeholder model on demand, and the rest of the suite
runs with both `pirewall/ml/artifacts/*` models absent by design (they are
gitignored, machine-local, and never checked in — see
`docs/ML_DATA_AUDIT.md`). The two exceptions are
`test_batched_anomaly_scoring_uses_far_fewer_inference_calls_than_flows`
and `test_anomaly_scoring_backpressure_still_finishes_every_flow` in
`tests/integration/test_core_daemon.py`, which genuinely need the real
shipped Isolation Forest artifact to exercise real batching timings —
each is individually skipped with a clear reason (not failed, not
silently passed) when that artifact isn't present at
`pirewall/ml/artifacts/isolation_forest_model.joblib`, which is the case
on every fresh clone. Run `scripts/train/train_isolation_forest.py`
locally to produce one and un-skip them.

## Test tiers (`tests/`)

| Directory | What it covers |
|---|---|
| `tests/unit/` | One module/class at a time: domain models, config loading, parsing, flow keys/state/table, feature extraction, ML training/inference building blocks, decision engine, rule generation, validator (every stage independently), rate limiter, auth, API routes, control panel rendering, IPC dispatcher. |
| `tests/ml/` | Dataset adapters, training pipelines, model artifacts/metadata, inference — all against small synthetic fixture data (see `docs/ML_PIPELINE.md`). |
| `tests/integration/` | Multi-module pipelines exercised together: capture->parse, the full addendum-driven rule lifecycle (SHADOW/ASSISTED/kill-switch), candidate->validation->backend, the complete `Packet -> Flow -> FeatureVector -> Behavior -> ThreatAssessment -> FirewallDecision -> CandidateRule -> Validation -> FirewallBackend` chain against scripted benign/port-scan/SYN-flood traffic, the whole `CoreDaemon` running end to end through every real thread and the real `AF_UNIX` transport (`test_core_daemon.py`, `AF_UNIX`-gated), the real `UnixSocketRpcServer`/`UnixSocketRpcClient` transport on its own (`test_rpc_unix_socket.py`), a detection-loop queue-drain ordering regression (`test_detection_loop_ordering.py`), and `CoreDaemon`'s B4/B5 TLS structural-evidence wiring (`test_tls_evidence_wiring.py`, not `AF_UNIX`-gated — runs below the RPC socket). |
| `tests/security/` | Adversarial/safety-focused: malformed/truncated packets, injection attempts, Admin-PC-lockout prevention, firewall backend failure handling, resource exhaustion under flood conditions, import-graph isolation proofs (A4, backend-isolation), static structure checks on `deploy/systemd/*.service` and `deploy/firewall/base.nft.template`. |
| `tests/system/` | End-to-end smoke checks that don't fit the tiers above — currently the performance smoke pass regression guard. |
| `tests/helpers/` | Shared fixture factories (`make_config`, `make_flow`, `make_packet`, `make_candidate`, ...) — not tests themselves. |

## The Protocol + Fake pattern (spec §39)

Every hardware-dependent component is a `Protocol` (an interface) with two
implementations: a real one and a `Fake`. This is what makes the entire
suite above runnable without root or real hardware:

```text
PacketCapture                          FirewallBackend
    |-- AFPacketCapture (real,             |-- NftablesBackend (real,
    |     AF_PACKET, Environment-          |     nft binary, Environment-
    |     dependent)                       |     dependent)
    |-- FakePacketCapture (test-only)      |-- FakeFirewallBackend (test-only)

RpcClient (pirewall.ipc)
    |-- UnixSocketRpcClient (real, AF_UNIX, Tested on any POSIX host)
    |-- LoopbackRpcClient (test-only, calls the dispatcher in-process)
```

All core logic (flow aggregation, feature extraction, detection, decision,
rule generation, validation) is plain Python operating on typed domain
objects — it never touches a `Protocol` implementation directly, so it's
testable regardless of which side of the Fake/real line you're on.

## Fakes vs. real hardware — what's actually verified

A green `pytest` run proves the **logic** is correct against every Fake
implementation's behavior. It does **not** prove:

- `AFPacketCapture` actually captures real packets off a real NIC in
  promiscuous mode.
- `NftablesBackend` actually bootstraps tables/chains and translates rules
  correctly against a real `nft` binary.
- systemd actually applies the socket's *ownership* (`pirewall-core`
  user, `pirewall-ipc` group). The socket's *mode* is guaranteed by
  `UnixSocketRpcServer` itself and covered by
  `tests/integration/test_rpc_unix_socket.py`, which exercises the real
  `AF_UNIX` transport end to end — that part is no longer
  Environment-dependent.
- Real ML detection *accuracy* — `tests/ml/` trains tiny models on
  synthetic fixtures, not real attack traffic (see `docs/ML_PIPELINE.md`).
- Anything about real systemd capability/namespace enforcement, real
  socket file *ownership*, or real SSH/TLS hardening (`deploy/systemd/`,
  `deploy/firewall/`, `deploy/network/` are statically parsed by
  `tests/security/`, never actually loaded/installed). The socket's
  *mode* is a separate matter and is tested — see above.

Every one of these is labeled **Environment-dependent** in
`docs/PROGRESS.md`, with the exact human verification step needed. Per
CLAUDE.md's labeling honesty rules: never read "tests pass" as "verified
on real hardware."

## Performance smoke pass (spec §40)

```sh
uv run python -m scripts.diagnostics.performance_smoke
```

Reports packet throughput, flow/feature-extraction/inference/threat-
assessment/rule-deployment latency, driven through `FakePacketCapture`/
`FakeFirewallBackend` at a synthetic 2000-flow rate. **These numbers
describe this dev machine and the Fake backends only** — not real Pi 4
hardware. `tests/system/test_performance_smoke.py` runs the same code at a
smaller scale as a fast regression guard (every stage still executes and
reports a positive measurement) — it asserts no specific thresholds, since
those would be machine-dependent and unrelated to real-hardware
performance anyway.

## Security test coverage (spec §39)

| Item | Where |
|---|---|
| malformed/truncated packets | `tests/security/test_parser_malformed.py` |
| invalid IPs/CIDRs/ports | `tests/security/test_injection.py`, `tests/unit/test_models_rules.py` |
| malformed/missing configuration | `tests/unit/test_config_loader.py` |
| certificate configuration failures | `tests/unit/test_config_loader.py` (missing/empty `tls_cert_path`/`tls_key_path`) |
| unauthorized API requests / authentication failures | `tests/unit/test_auth.py`, `tests/unit/test_api_routes.py` |
| rule injection / command injection | `tests/security/test_injection.py` |
| overly broad / duplicate / conflicting rules | `tests/security/test_safety_validation.py`, `tests/integration/test_firewall_lifecycle.py` |
| Admin PC lockout prevention | `tests/security/test_safety_validation.py` |
| firewall backend failure handling | `tests/integration/test_firewall_lifecycle.py` (apply failure), `tests/security/test_firewall_failure_handling.py` (remove/kill-switch failure) |
| resource exhaustion | `tests/security/test_resource_exhaustion.py` (event-queue, excessive rule creation), plus earlier phases' flow-table/behavior-state flood tests (`tests/unit/test_flow_table.py`, `tests/unit/test_behavior.py`) |
| backend/process isolation | `tests/security/test_backend_isolation.py`, `tests/security/test_api_process_isolation.py` |
| systemd/nftables static hardening checks | `tests/security/test_systemd_hardening.py`, `tests/security/test_firewall_base_template.py` |

## Adding a test

Follow spec §47's loop (see `docs/DEVELOPMENT_WORKFLOW.md`): inspect
existing code and its contract first, add the test alongside the tier it
belongs to above, run `pytest`/`ruff check .`/`pyright` before considering
it done. Reuse `tests/helpers/` factories rather than hand-building domain
objects inline — every existing test does, and it keeps fixtures
consistent as models evolve.
