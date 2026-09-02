# pirewall — Architecture Notes

## System pipeline (spec §51)

The complete detection/enforcement pipeline, and the one separation the
whole system must preserve — detection produces evidence, evidence is
scored into a threat assessment, a decision is made, and only *then* does
anything touch the firewall. Since the ADDENDUM_2.md B1-B5 pass and its
batched-anomaly-scoring follow-up, this is no longer a single linear
chain: flow aggregation fans out to three bounded queues, four detectors
run (three inline, one on its own thread), and B3's evidence-maturity gate
sits between scoring and decision. `pirewall.runtime.core.CoreDaemon`'s own
module docstring is the authoritative thread table this diagram follows.

```text
                 NETWORK
                    |
                    v
             PACKET CAPTURE           pirewall.capture (AFPacketCapture / FakePacketCapture)
              (capture thread)
                    |
                    v
             FLOW AGGREGATION         pirewall.flow (FlowAggregator, bounded FlowTable)
                    |
        +-----------+----------------------+
        |           |                      |
        v           v                      v
    completed   new-flow-opened        slow-conn-cluster
     flow        signal (B1)             snapshot (B2)
        |           |                      |
        v           v                      v
  _flow_queue  _new_flow_queue       _slow_cluster_queue
        |           |                      |
        |           v                      v
        |     detection thread folds both into BehaviorAnalyzer
        |     (B2 also re-enqueues its representative flow onto _flow_queue)
        |                                   |
        +----------------<------------------+
        |
        v
   detection thread drains _flow_queue, runs FEATURE EXTRACTION
        |                                  pirewall.features (one canonical extractor)
        v
  +-----+--------------------+---------------------------------+
  |                          |                                  |
  v                          v                                  v
LightGBM              Behavior analysis          Heartbleed / JA3 fingerprint
(known-attack)         (deterministic;             (B4/B5 — TLS record-layer /
 pirewall.detection.    B1/B2 signals folded in)     ClientHello parsing, run on
 known_attack           pirewall.detection.behavior  the capture thread against raw
                                                      TCP/443 payload, cached by flow
                                                      key, popped here at completion —
                                                      pirewall.detection.tls_heartbeat
                                                      / tls_fingerprint)
  |                          |                                  |
  +------------+-------------+----------------------------------+
               |
               v
     Isolation Forest model loaded?      pirewall.detection.anomaly, wrapping
       |                    |             pirewall.ml.inference.isolation_forest_predictor
       | no                | yes
       v                    v
  score inline         hand off to the pirewall-anomaly-inference thread's
  (as before)           _anomaly_queue — process() returns here; see
       |                "Anomaly-inference detail" below. This flow resumes
       |                at THREAT ASSESSMENT once that thread calls
       |                FlowPipeline.finish() for it.
       v                    |
       +---------<----------+
       |
       v
     THREAT ASSESSMENT        pirewall.engine.threat + pirewall.engine.scoring
                               (combines known + anomaly + behavior +
                                protocol-signature evidence)
                    |
                    v
     EVIDENCE MATURITY GATE   pirewall.engine.decision.EvidenceMaturityTracker
                               (ADDENDUM_2.md B3 — caps a BLOCK/RATE_LIMIT
                                decision to MONITOR unless it carries
                                mature evidence; lives inside `decide`, not
                                as a separate module)
                    |
                    v
             FIREWALL DECISION         pirewall.engine.decision.decide
                    |
                    v
             CANDIDATE RULE            pirewall.firewall.generator
                    |
                    v
             RULE VALIDATION           pirewall.firewall.validator (10-stage chain)
                    |
                    v
             FIREWALL BACKEND          pirewall.firewall.manager (the ONE authorized caller)
                    |
                    v
               NFTABLES                pirewall.firewall.backend.nftables / .fake
                    |
                    v
             NETWORK TRAFFIC
```

**Anomaly-inference detail** (ADDENDUM_2 follow-up pass, section 3) — the
hand-off above, expanded. This thread is only spawned when
`DetectionCoordinator.models.isolation_forest is not None`; when no model
is loaded, the hand-off never happens and detection stays exactly the
single-threaded, synchronous path it always was:

```text
  detection thread                    pirewall-anomaly-inference thread
  (FlowPipeline.process)
        |
        v
  PendingAnomalyScoring
  (flow + features + known/
   behavior evidence already
   computed; anomaly_evidence
   left None)
        |
        v
  _anomaly_queue (bounded)  ------->  _collect_anomaly_batch
                                       flushes on whichever comes first:
                                       - detection.anomaly_batch_size flows
                                         (default 50)
                                       - detection.anomaly_batch_max_wait_seconds
                                         since the batch's first flow (default 0.2s)
                                             |
                                             v
                                       one detect_batch() /
                                       anomaly_score_batch() call per
                                       batch — N flows' feature rows
                                       stacked into a single
                                       decision_function() call
                                             |
                                             v
                                       FlowPipeline.finish() once per
                                       flow in the batch — rejoins the
                                       main pipeline at THREAT ASSESSMENT
```

**Backpressure on `_anomaly_queue` degrades, it does not drop the flow.**
Unlike the other three queues, a full `_anomaly_queue` does not lose a
flow: known-attack and behavior evidence were already computed inline
before the hand-off, so `_enqueue_anomaly_scoring` calls
`FlowPipeline.finish` immediately with `anomaly_evidence` left `None` —
the flow still reaches a real `ThreatAssessment`, just without an
Isolation Forest score. Counted by its own
`RuntimeCounters.anomaly_scores_dropped_for_backpressure` field and its
own rate-limited `SecurityEvent`, deliberately distinct from
`flows_dropped_for_backpressure` (a flow never assessed at all, when
`_flow_queue` itself is full).

Security events flow separately, out of every stage above that can emit
one, to two independent consumers:

```text
Threat / Firewall / System Events
       (pirewall.core.models.event.SecurityEvent)
              |
       +------+------+
       |             |
       v             v
     Wazuh      Control Panel
(pirewall.integration.wazuh)  (pirewall-api, via pirewall.ipc)
```

## Module boundaries and dependency direction

Dependencies flow one direction only (`CLAUDE.md`) — no module lower in
this list imports from a module higher up it:

```text
core.models / core.enums / core.exceptions   (no dependents flow backward into here)
        |
        v
config                                        (validated settings, spec §37)
        |
        v
capture  ->  flow  ->  features               (packet -> flow -> feature vector)
        |
        v
ml  ->  detection                             (model artifacts -> evidence wrappers)
        |
        v
engine                                        (scoring, threat assessment, decision)
        |
        v
firewall                                      (generator, validator, manager, backend)
        |
        v
ipc                                           (the ADDENDUM.md A4 process boundary)
        |
    +---+---+
    |       |
    v       v
  api     web                                 (pirewall-api process — never imports
                                                capture / firewall.manager / firewall.backend)
```

`integration` (Wazuh/Netdata forwarders, Phase 8) sits alongside `ipc`:
it's fed `SecurityEvent`s/metrics snapshots from `pirewall-core`'s own
state, and never calls into `firewall`/`capture` itself either.

`runtime` sits **below everything on the pirewall-core side** — it is the
composition root, so it is the one package allowed to depend on all of
them at once:

```text
capture + flow + features + detection + engine + firewall + ipc + integration
        |
        v
runtime                                       (CoreDaemon: threads, lifecycle, wiring)
        |
        v
pirewall.main                                 (argv, config, logging — nothing else)
```

Two consequences worth stating, because both are enforced by tests rather
than convention:

* **`runtime` is pirewall-core-only.** It imports `pirewall.capture` and
  `pirewall.firewall.manager`, so nothing under `pirewall/api/` or
  `pirewall/web/` may import it — that would put packet capture and the
  firewall backend inside the pirewall-api process. Like `pirewall/ipc/`,
  its `__init__.py` re-exports nothing so a stray
  `from pirewall.runtime import X` cannot silently pull the daemon in.
* **`runtime/core.py` may name a concrete backend, but never call one.**
  Something has to construct the real `NftablesBackend` and inject it — a
  composition root cannot itself be injected — so it is the one file
  besides `firewall/manager.py` on
  `tests/security/test_backend_isolation.py`'s allowlist. That exemption is
  construction-only, and independently asserted: the daemon calls no
  `FirewallBackend` method at all, not even the read-only `health_check`,
  which is exposed as `FirewallManager.backend_health` precisely so no
  second reference to the backend has to exist.

`runtime.pipeline` is also where the layer separation spec §19 requires
becomes concrete. Detection produces evidence and stops; `detection` never
imports `engine`, because that would invert `detection -> engine ->
firewall`. The pipeline is what carries evidence across each boundary, and
it holds no detection, scoring, or rule logic of its own.

## Batched anomaly scoring (ADDENDUM_2 follow-up pass, section 3)

`benchmarks/2026-08-30/REPORT.md` §3-4 measured single-flow Isolation
Forest scoring at **30.7 ms/call on a real Pi 4 — 92% of total
packet-to-decision cost** — and traced that cost to scikit-learn's own
fixed per-call overhead, not tree traversal: a follow-up quick benchmark
(`benchmarks/2026-08-31-anomaly-batching/quick_benchmark.py`, run on this
session's dev/CI hardware, *not* a Pi — no real Pi 4 was reachable this
session) found `decision_function`'s call cost is ~3.2-3.4 ms regardless of
batch size 1 through 100, so scoring 100 flows in one call costs about the
same wall time as scoring 1. Batching amortizes that fixed cost across
every flow in the batch instead of paying it once per flow.

**Where this lives, and why it's a fourth thread, not a fourth
responsibility bolted onto the detection thread:** the same reasoning
`CoreDaemon`'s own module docstring already gives for splitting capture
from detection — two stages that run at wildly different speeds must not
share a thread, or the slow one stalls the fast one — applies again between
detection and anomaly scoring. `pirewall.runtime.pipeline.FlowPipeline`
gained a `process`/`finish` split: `process` (called from the detection
thread, as before) now runs known-attack classification and behavior
analysis inline, then — only when an Isolation Forest model is loaded —
hands the flow off to an injected `anomaly_scorer` callback instead of
scoring inline, and returns immediately; `finish` (a new, separately
error-handled entry point) does the rest — `assess_threat` through
`FirewallManager.submit_candidate` — once that flow's anomaly evidence is
ready. `pirewall.detection.coordinator.DetectionCoordinator` gained the
matching split: `analyze_except_anomaly` (known + behavior only) and a
module-level `with_anomaly_evidence` combinator that folds a separately
obtained `AnomalyEvidence | None` back into the outcome `analyze_except_anomaly`
produced. `analyze` itself is now defined as exactly that composition, so
the non-batched path (no Isolation Forest loaded, or any direct caller —
`tests/unit/test_detection_coordinator.py`'s tests all still call `analyze`
unchanged) is provably identical to before this section existed.

`pirewall.runtime.core.CoreDaemon` owns the actual batching machinery, same
place B1/B2's `_new_flow_queue`/`_slow_cluster_queue` live, for the same
reason (`pirewall.flow`/`pirewall.detection` must not depend on
`threading`; `runtime` is the one package allowed to know about all of
capture/flow/detection/engine/firewall *and* how they're scheduled onto
threads):

* A new bounded `_anomaly_queue`, written by the detection thread
  (`_enqueue_anomaly_scoring`, called from `FlowPipeline.process` via the
  injected callback) and drained by a new dedicated
  `pirewall-anomaly-inference` thread — only spawned when
  `DetectionCoordinator.models.isolation_forest is not None` (`start()`);
  when no model is loaded, `anomaly_scorer` is never injected in the first
  place and `FlowPipeline.process` behaves exactly as it always did,
  single-flow, synchronous, no queue involved at all.
* `_collect_anomaly_batch` flushes on **size or timeout, whichever comes
  first**: it collects up to `detection.anomaly_batch_size` (default 50)
  flows, but never waits past `detection.anomaly_batch_max_wait_seconds`
  (default 0.2 s) from when the first flow of that batch arrived. This is
  what bounds worst-case *added* per-flow latency under low load to a few
  hundred milliseconds rather than however long it takes a batch to fill —
  the same requirement the phase prompt for this section stated explicitly.
* `_score_and_finish_batch` calls the new
  `pirewall.detection.anomaly.detect_batch` /
  `pirewall.ml.inference.isolation_forest_predictor.anomaly_score_batch`
  once per batch (one `decision_function` call, N feature rows stacked),
  then calls `FlowPipeline.finish` once per flow in the batch — every flow
  still gets its own `ThreatAssessment`/`FirewallDecision`/candidate-rule
  cycle, exactly as before; only *when* the anomaly half of its evidence
  was computed changed.
* **Same bounded-drop discipline as every other cross-thread queue here,
  but a different, milder failure mode.** `_enqueue_anomaly_scoring` drops
  on `queue.Full` exactly like `_enqueue`/`_handle_new_flow` do for their
  own queues — but because known-attack and behavioral evidence were
  already computed inline before the handoff, a drop here does not lose
  the flow: it finishes immediately via `FlowPipeline.finish` with
  `anomaly_evidence` left `None`, so the flow still reaches a real
  `ThreatAssessment`, just without an Isolation Forest score. Tracked by
  its own `RuntimeCounters.anomaly_scores_dropped_for_backpressure` field
  and its own rate-limited `SecurityEvent`, deliberately distinct from
  `flows_dropped_for_backpressure` (a flow never assessed at all) and from
  the packet-level `packets_dropped` counter (section 2 of this same
  follow-up pass) — three genuinely different failure modes, three
  separate signals, not one drop counter standing in for all of them.

**The module-boundary diagram above is unchanged, deliberately, not by
oversight.** The new thread is entirely internal to `runtime` — it calls
`pirewall.detection.anomaly`/`pirewall.ml.inference`, both of which
`runtime` already depended on before this section, and it introduces no new
cross-package edge. What changed is *scheduling* (a fourth `pirewall-core`
thread) and a `runtime.pipeline` API split (`process`/`finish`), not the
dependency graph.

This file exists per `CLAUDE.md`'s dependency policy: "Anything else [beyond
the allowed dependency list] — ask first, and say why here." It records
places where a phase needed something beyond the base list, and why the
choice made avoids (or, where unavoidable, justifies) adding one.

## Dependency decisions

### Password hashing: stdlib `hashlib.scrypt`, not bcrypt/argon2 (Phase 7)

Spec §29 asks for "securely hashed passwords." The obvious choices
(`bcrypt`, `argon2-cffi`, `passlib`) are not on `CLAUDE.md`'s allowed
dependency list. Python's stdlib `hashlib.scrypt` (RFC 7914, a memory-hard
KDF endorsed by NIST/OWASP alongside bcrypt/argon2 for password storage) is
sufficient for a single-admin credential and avoids adding a dependency
entirely. See `pirewall/api/auth.py`.

### Session tokens: stdlib `secrets`, no JWT library (Phase 7)

A single-admin system doesn't need JWT's cross-service claims/signing
machinery. `secrets.token_urlsafe()` opaque tokens, held server-side in an
in-memory session table with an expiry (`authentication.token_expiry_seconds`),
are simpler, sufficient, and dependency-free.

### Control panel templating: hand-rolled HTML via stdlib `html.escape`, not Jinja2 (Phase 7)

Spec §30 asks for "HTML, CSS, minimal JavaScript... not a large frontend
framework." Jinja2 is the most common FastAPI templating pairing but isn't
on the allowed list. `pirewall/web/render.py` builds pages as plain Python
functions returning strings, escaping dynamic content via stdlib
`html.escape` — this is a real, if unglamorous, choice to stay within the
dependency policy rather than reach for the default. Note the tradeoff it
carries: a template engine applies context-aware escaping, and doing this
by hand means getting the context right at each site. A post-Phase-9 audit
found ids interpolated into inline `onclick` JS, where `html.escape` is
not sufficient; values bound for JS now travel in `data-` attributes
instead (see `pirewall/web/render.py`'s module docstring).

### `uvicorn` and `httpx` alongside FastAPI (Phase 7)

`CLAUDE.md` lists FastAPI itself as allowed, but a bare `pip install
fastapi` has no ASGI server to actually run it, and FastAPI's own
`TestClient` (needed to test the app per this phase's test requirements)
requires `httpx`. Both are treated as necessary companions of the
already-approved FastAPI dependency, not new independent choices — the
same reasoning already applied to `joblib` (scikit-learn) and `numpy`
(lightgbm/scikit-learn) in Phases 4/5.

### Live event stream: Server-Sent Events, not WebSockets (entry-point session)

The control panel needs live `SecurityEvent` push. The obvious choice would
be a WebSocket, and one was written first — but a FastAPI WebSocket route
returns **404 under real uvicorn** unless `websockets` or `wsproto` is also
installed, and neither is on `CLAUDE.md`'s dependency list. (This was not
caught by the test suite: Starlette's `TestClient` implements the WebSocket
protocol in-process, so the tests passed against an endpoint that could not
work in production. It surfaced only when both real processes were run.)

Server-Sent Events need no new dependency at all — they are plain chunked
HTTP on the uvicorn already pinned — and they fit better besides: the
stream is strictly one-way, and browsers implement `EventSource` natively
with automatic reconnection. So `GET /api/v1/events/stream` is SSE, and no
dependency was added.

### Host CPU/memory metrics: `/proc`, not `psutil` (entry-point session)

`NetdataMetricsSnapshot` needs two host figures. `psutil` is a compiled
dependency not on the allowed list, and reading `/proc/stat` and
`/proc/meminfo` directly is a few lines. Off Linux both read `0.0`, which
is honest — pirewall only ever runs these on the Pi.

### `sd_notify`: the raw protocol, not `python-systemd` (entry-point session)

`Type=notify` and `WatchdogSec=` need `READY=1`/`WATCHDOG=1` datagrams sent
to the socket named by `$NOTIFY_SOCKET`. That is a handful of lines of
`AF_UNIX` datagram code (`pirewall/runtime/watchdog.py`); `python-systemd`
is a compiled dependency and unnecessary for a protocol this small. Outside
systemd `$NOTIFY_SOCKET` is unset and every method is a no-op, so
`python -m pirewall.main` behaves identically from a shell.

### `imbalanced-learn` for training-split resampling (imbalance-remediation session)

CICIDS2017 is ~80% one class (BENIGN) with several attack classes under 50
real-world rows (Heartbleed: 11, Web Attack-Sql Injection: 21,
Infiltration: 36) — LightGBM's held-out macro-F1 was 0.2367 with zero
correct predictions for several classes. `RandomUnderSampler`/`SMOTE`
(training-split only, see `pirewall/ml/training/resampling.py`) are the
standard, well-understood fix; hand-rolling equivalent stratified
undersampling is straightforward but SMOTE's k-nearest-neighbor
interpolation is not — reimplementing it would be the kind of "invent a
worse version of a well-known library" CLAUDE.md's dependency policy exists
to avoid. Added on explicit operator instruction, training-only (dev
machine, spec §4) — never imported by `pirewall/` runtime code, so it never
reaches the Pi.

## Process split (ADDENDUM.md A4)

`pirewall-core` (capture/flow/ML/detection/engine/firewall, Phases 2-6) and
`pirewall-api` (FastAPI + control panel, Phase 7) are separate processes.
`pirewall-api` never imports `pirewall.capture`, `pirewall.firewall.manager`,
or `pirewall.firewall.backend` — enforced by
`tests/security/test_api_process_isolation.py`. They communicate over a
Unix domain socket using the typed request/response protocol in
`pirewall/ipc/protocol.py`:

* `pirewall.ipc.dispatcher.CoreRpcDispatcher` — the actual operation logic
  (wraps `pirewall.ipc.state.CoreStateStore` and
  `pirewall.firewall.manager.FirewallManager`), pure Python, no networking,
  fully unit-testable.
* `pirewall.ipc.server.UnixSocketRpcServer` — the real transport, runs
  inside `pirewall-core`. Requires `socket.AF_UNIX`; exercised against a
  real socket by `tests/integration/test_rpc_unix_socket.py`.
* `pirewall.ipc.client.UnixSocketRpcClient` — the real transport's client
  half, runs inside `pirewall-api`. Covered by the same tests.
* `pirewall.runtime.core._SynchronizedDispatcher` — `CoreRpcDispatcher`
  with `handle()` serialized against the daemon's own lock. The RPC thread
  reads (and, for rule lifecycle operations, writes) `CoreStateStore` and
  `FirewallManager` while the detection thread is writing both. Neither
  class was made thread-aware: they are domain logic and have no business
  knowing a daemon runs them on several threads. Holding one lock around
  `handle()` also makes every RPC operation atomic with respect to the
  pipeline, so a `/status` response can never observe a half-applied rule
  transition.
* `pirewall.ipc.loopback.LoopbackRpcClient` — an in-process test double
  implementing the same `RpcClient` Protocol by calling the dispatcher
  directly, no socket at all. **Test-only.** The real two-process
  deployment must never use this — doing so would defeat the entire point
  of A4's process isolation (a compromised `pirewall-api` sharing memory
  with `pirewall-core` instead of talking over a narrow, typed socket).

## Known limitations — scope boundary, not an unaddressed gap

Spec §34 draws the line plainly: flow-metadata-based detection is
*strongly observable* for SYN floods, port scanning, brute-force
connection patterns, connection floods, DoS patterns, and abnormal traffic
rates — and *potentially limited* for XSS, SQL injection, and reverse-shell
payload contents, because those live in application-layer content this
project deliberately never inspects (spec §7). ADDENDUM_2.md's B1/B2 pass
(creation-time behavioral counters, the slow-rate aggregate signal) and B6
sharpen this rather than change it: B6's empirical test confirms a
realistic, intensive automated web-app probing scan (sqlmap testing
multiple SQL injection techniques against one parameter) is caught
*indirectly*, via its connection-volume/rate pattern looking like the
brute-force patterns pirewall already detects well — but a light, targeted
probe, or any scan that reuses one persistent connection across many
application-layer requests, is not, because pirewall has no visibility
into HTTP request framing at all. That is a real, structural limit of a
network-layer, per-flow detector, not a bug to fix here.

ADDENDUM_2.md's B4/B5 (the Heartbleed length check, JA3 ClientHello
fingerprinting) narrow that boundary slightly but do not move it: both
work specifically *because* TLS sends certain fields in cleartext by
protocol design (the record/heartbeat headers, the ClientHello) — they are
protocol-structure parsing, the same category as this project's TCP/IPv4
header parsing, not content inspection, and both detectors say so
explicitly in their own module docstrings. Neither one, nor anything else
in this project, can see inside a TLS application-data record, an HTTP
request body, or any other encrypted or decoded application payload.

**This is a deliberate scope decision, not an unaddressed gap.**
pirewall is the network-layer, volumetric/behavioral/adaptive firewall:
capture, flow aggregation, ML-assisted and deterministic behavioral
detection, threat scoring, and adaptive nftables enforcement, all
operating on packet/flow metadata. Application-layer content inspection —
actually recognizing a SQL injection payload, an XSS string, or a
reverse-shell's command content, the exact gap spec §34 and B6 both name —
is being deliberately addressed by a separate, complementary sibling
project, **WAFFY**, a per-host web application firewall, rather than by
expanding this project's own scope to include payload decoding. WAFFY is
referenced here only as a sibling project; nothing WAFFY-related is
implemented in this repository, and nothing here depends on it existing.
The two are meant to compose: pirewall covers the network perimeter and
the traffic patterns visible there, WAFFY covers per-host application
content the same traffic carries.

**Update (Pi deployment readiness pass):** WAFFY has since become a real,
deployment-ready sibling system (per the human operator) rather than a
referenced-but-unbuilt one — this does not change the scope-boundary
argument above, which remains the deliberate architecture decision; see
`docs/DEPLOYMENT.md` §10 for the operational coexistence notes this
prompted (where each one runs, and the open question on WAFFY's own
firewall/port footprint that only WAFFY's own docs can answer).
