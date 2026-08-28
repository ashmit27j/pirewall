# pirewall — Architecture Notes

## System pipeline (spec §51)

The complete detection/enforcement pipeline, and the one separation the
whole system must preserve — detection produces evidence, evidence is
scored into a threat assessment, a decision is made, and only *then* does
anything touch the firewall:

```text
                 NETWORK
                    |
                    v
             PACKET CAPTURE           pirewall.capture (AFPacketCapture / FakePacketCapture)
                    |
                    v
             FLOW AGGREGATION         pirewall.flow (FlowAggregator, bounded FlowTable)
                    |
                    v
            FEATURE EXTRACTION        pirewall.features (one canonical extractor)
                    |
          +---------+---------+
          |                   |
          v                   v
       LightGBM        Isolation Forest   pirewall.ml.inference, wrapped by
          |                   |            pirewall.detection.{known_attack,anomaly}
          +---------+---------+
                    |
                    v
             BEHAVIOR ANALYSIS         pirewall.detection.behavior (deterministic, no ML)
                    |
                    v
             THREAT ASSESSMENT         pirewall.engine.threat + pirewall.engine.scoring
                    |
                    v
             FIREWALL DECISION         pirewall.engine.decision
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
