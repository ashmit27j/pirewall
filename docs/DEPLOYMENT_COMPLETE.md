# pirewall — Deployment Readiness

What changed to make `systemctl start pirewall-core` and
`systemctl start pirewall-api` have something real to start, what was
actually verified, and what a human still has to check on the Pi.

Labels are the ones `CLAUDE.md` defines: **Implemented**, **Tested**,
**Mocked**, **Environment-dependent**, **Not yet validated**. Nothing here
claims a level of verification it did not get.

---

## 1. The gap this closes

Every deployment artifact in this repository — both `.service` units, all
of `docs/DEPLOYMENT.md` — targeted two entry points that did not exist:

* `pirewall/main.py` — the `pirewall-core` daemon.
* `pirewall/api/__main__.py` — the `pirewall-api` server.

Both units carried an explicit "do not start this unit until it lands"
note. Everything under `pirewall/` was a set of correct, well-tested,
mutually unaware subsystems with no process to run them in. Both entry
points now exist and have been run.

## 2. What was built

### Entry points

| Module | Role |
|---|---|
| `pirewall/main.py` | `pirewall-core`. Resolves and validates config, configures logging, runs `CoreDaemon`. Deliberately thin — all wiring is in `pirewall/runtime/`, so the daemon is testable without a `__main__` guard. |
| `pirewall/api/__main__.py` | `pirewall-api` (`python -m pirewall.api`). Validates config, credentials and TLS material, then serves `create_app` over uvicorn + TLS. |

Both accept `--config PATH` and `--check-config`. Config resolution is
`--config` → `config/local_config.toml` → `config/default_config.toml`.
Both return an exit code rather than raising, so `Restart=on-failure` and
`StartLimitBurst=` in the units see a real failure.

### `pirewall/runtime/` — the pirewall-core process

Deliberately a separate package from the subsystems it wires, and it
re-exports nothing (same reasoning as `pirewall/ipc/__init__.py`): it
imports `pirewall.capture` and `pirewall.firewall.manager`, so a stray
import of it from the API process would defeat ADDENDUM.md A4.

| Module | Role |
|---|---|
| `runtime/core.py` | `CoreDaemon` — owns every long-lived object and every thread. |
| `runtime/pipeline.py` | `FlowPipeline` — one completed flow: features → detection → threat → decision → candidate → validated enforcement. |
| `runtime/forwarder.py` | `EventForwarder` — the single sink every `SecurityEvent` passes through (store + log + Wazuh). |
| `runtime/metrics.py` | `MetricsCollector`, `RuntimeCounters` — builds a live `NetdataMetricsSnapshot`. |
| `runtime/watchdog.py` | `SystemdNotifier` — `sd_notify` `READY=1` / `WATCHDOG=1` / `STOPPING=1`. |

Threads, and why there is more than one:

| Thread | Work |
|---|---|
| `capture` | Blocks in `recv()`, parses, aggregates flows, enqueues completed ones. |
| `detection` | Drains that queue through `FlowPipeline`. |
| `sweep` | Flow timeouts and adaptive-rule TTL expiry, per `flow.cleanup_interval_seconds`. |
| `rpc` | `UnixSocketRpcServer.serve_until_stopped` — pirewall-api's only way in. |
| main | `sd_notify` heartbeats, capture-statistics refresh, Netdata export. |

Capture and detection are split because Isolation Forest scoring was
measured at ~15.6 ms/flow on the development machine and will be slower on
a Pi 4 (`docs/PROGRESS.md`); doing that inline in the capture thread would
stall `recv()` and drop packets in the kernel. The queue between them is
**bounded and drops on overflow rather than blocking** — a detection
backlog must cost detection coverage, never packet capture. Drops are
counted and reported as `SYSTEM_WARNING` events, never silent.

`CoreStateStore` and `FirewallManager` are guarded by one reentrant lock
shared with the RPC dispatcher (`_SynchronizedDispatcher`), so an RPC
response can never observe a half-applied rule transition. Neither class
was made thread-aware: they are domain logic and have no business knowing a
daemon runs them on several threads.

### `pirewall/detection/coordinator.py`

`ModelRegistry` + `load_models` + `DetectionCoordinator`. ML artifacts are
gitignored and trained separately, so a freshly provisioned Pi legitimately
has no model files. A missing file, an unreadable artifact, a missing
metadata sidecar and a feature-schema mismatch are all handled the same
way: warn, record the reason, and run **behaviour-only** detection. An
inference failure mid-run costs that one evidence field, not the flow.

It stops at evidence — no `ThreatAssessment`, no decision, no rule.
Importing `pirewall.engine` from the detection layer would invert the
`detection → engine → firewall` dependency order `CLAUDE.md` fixes;
`runtime/pipeline.py` carries the evidence onward instead.

### `pirewall/core/logging.py`

One logger setup for both processes, writing `<log_dir>/<component>.log`
(separate files — the two processes run as different users). **Failing to
open the log file is not fatal**: it degrades to stderr, which journald
captures. A firewall that refuses to start because it could not open a log
file is strictly worse than one that starts and says so.

### API additions

| Endpoint | Notes |
|---|---|
| `GET /api/v1/capture-stats` | Closes the spec §30 "network statistics" gap `docs/PROGRESS.md` recorded as blocked on `main.py`. Needed a `capture_stats` field on `CoreStateStore`, a `GET_CAPTURE_STATS` RPC operation, and a typed client method. |
| `GET /api/v1/config` | Read-only, with `admin_password_hash`, both TLS paths and the Wazuh/Netdata hostnames redacted. |
| `GET /api/v1/events/stream` | Live `SecurityEvent` push as Server-Sent Events. |

## 3. Defects found and fixed while wiring

Three real bugs surfaced only because the code was finally *run*. Each has
a regression test.

1. **`RuleStatus.EXPIRED` was unreachable; rule TTLs did nothing.**
   `CandidateRule.expires_at` is mandatory and the validation chain has an
   expiration stage, but nothing ever acted on the value: an ACTIVE rule
   stayed deployed in the backend indefinitely. Fixed with
   `FirewallManager.expire_rules`, called from the sweep thread.
   *(`tests/unit/test_rule_expiration.py`)*

2. **`AFPacketCapture.start()` raised an untyped `AttributeError` on any
   platform without `AF_PACKET`.** It caught only `OSError`, but
   `socket.AF_PACKET` does not *exist* off Linux, so the stdlib raises
   `AttributeError` — which escaped and crashed the daemon with a
   traceback, bypassing the "capture unavailable, keep serving RPC so the
   Admin PC can see why" path A6 asks for. Now a `CaptureError` with an
   actionable message. This is exactly the leak spec §44's typed-exception
   rule exists to prevent.
   *(`tests/unit/test_fake_capture.py`)*

3. **The live event stream was a WebSocket that 404s in production.**
   uvicorn has no WebSocket implementation unless `websockets` or
   `wsproto` is installed, and neither is on `CLAUDE.md`'s dependency list.
   The tests passed because Starlette's `TestClient` implements the
   WebSocket protocol in-process — it could only be caught by running the
   two real processes. Replaced with Server-Sent Events, which needs no new
   dependency, and re-verified against real uvicorn.

A related testing note worth carrying forward: **`TestClient` cannot read a
never-ending `StreamingResponse` either** — it blocks before the first
line, verified against a minimal FastAPI app. So `event_source` is public
and tested by driving the generator directly, with the wire format verified
against real uvicorn.

## 4. What was verified, and how

### Tested (automated, passing)

`ruff check .` clean, `pyright --strict` clean (194 files), **472 tests
passing** (61 new).

* **`tests/integration/test_core_daemon.py` (8 tests)** — the whole daemon:
  every thread, the real `AF_UNIX` RPC transport, the real aggregator,
  coordinator, `FirewallManager` and full validation chain, substituting
  only `FakePacketCapture` and `FakeFirewallBackend`. Covers startup and
  clean shutdown; packets → flows → threats → decisions visible over RPC;
  capture statistics published; SHADOW never touching the backend; an
  unstartable capture reported rather than fatal; backpressure draining
  capture rather than blocking it; and the `fail_open` / `fail_closed`
  shutdown behaviours.
* Unit tests for logging, the detection coordinator's degradation paths,
  `sd_notify` (against a real `AF_UNIX` datagram socket), metrics rate
  arithmetic, the event forwarder, rule expiry, both entry points'
  validation, `/config` redaction, and the SSE generator.

### Tested (manual, on the development machine — macOS)

Both processes started for real, talking over a real `AF_UNIX` socket, with
a real self-signed certificate:

* `srw-rw----` on the RPC socket — mode 0660, as A4 requires.
* TLS 1.3 negotiated; a client forced to TLS 1.2 is refused.
* `401` without a session, login, then `/status` answered through a real
  RPC round-trip to `pirewall-core`.
* `/config` returned `***redacted***` for the password hash and TLS paths.
* SSE stream delivered live events over TLS; unauthenticated `401`.
* The control panel rendered.
* Capture correctly reported as unavailable (no `AF_PACKET` on macOS) with
  **the process staying up to say so** — A6 working as designed.
* `SIGTERM` → clean shutdown, every loop exited, socket file removed.

### Environment-dependent — a human must verify on the Pi

Unchanged from before, and not claimed here:

* `AFPacketCapture` against a real interface with `CAP_NET_RAW` — packets
  actually captured, drop/malformed counters sane under real traffic.
* `NftablesBackend` against a real `nft` binary — table/chain bootstrap,
  rule translation, removal.
* **systemd supervision itself**: `Type=notify` accepting `READY=1`,
  `WatchdogSec=30s` receiving heartbeats, `Restart=on-failure` and the
  crash-loop limit, and every sandboxing directive in both units not
  breaking required functionality (spec §27).
* Real TLS from the Admin PC's browser, and the Admin-PC IP restriction
  refusing a request from any other host.
* Wazuh (syslog 514) and Netdata (StatsD 8125) actually ingesting.
* Detection *accuracy* — still requires models trained on real datasets.
  Both artifacts are absent, so pirewall currently runs behaviour-only.

## 5. Deliberately not built

**`POST /api/v1/rules`.** The validation chain's authorization stage
rejects any candidate whose `decision_id` the real decision engine did not
produce, so a hand-authored rule endpoint could only work by weakening that
stage — which `CLAUDE.md` forbids ("no shortcuts, no trusted callers that
skip validation"). Adaptive rules originate from exactly one place. The
API's role is to *review* what the pipeline proposed
(`disable`/`remove`/`approve`/`reject`, plus the A8 kill-switch) and to
maintain the A2 allowlist, which is the supported way for an operator to
state policy directly. Confirmed with the operator before omitting.

## 6. Known limitations and decisions worth knowing

* **Clean shutdown reverts the adaptive ruleset when `failure.mode =
  fail_open`** (the default). nftables rules live in the kernel and outlive
  the process, so leaving them behind would mean a stopped pirewall keeps
  blocking traffic with nothing running to expire it — the opposite of
  failing open. `fail_closed` leaves them in place. Either way it goes
  through `FirewallManager.revert_to_base`, the normal A8 path, not a
  special-cased backend call. A consequence: `systemctl restart` clears
  adaptive rules, which are then re-derived from traffic.
* **The detection queue bound (`_FLOW_QUEUE_MAX`, 10,000) is a module
  constant, not config**, following the existing precedent for plumbing
  constants (`_LISTEN_BACKLOG`, `_ACCEPT_TIMEOUT_SECONDS`). It is a
  constructor parameter, so it is tunable and testable. Promote it to
  `[flow]` in config if the Pi turns out to need tuning.
* **`api_health` in the Netdata snapshot is not a measurement of the
  pirewall-api process.** A4 gives pirewall-core no handle on it. It
  reports whether the RPC socket pirewall-api depends on is being served.
* **Anomaly scoring is still one flow per `decision_function` call** —
  ~15.6 ms each, est. 10–20 flows/s on a Pi 4. Batching remains the open
  design question `docs/PROGRESS.md` records; the queue's backpressure
  reporting now makes it *observable* rather than silent, but does not fix
  it.
* **`config/local_config.toml` is gitignored and does not travel with the
  repository** — it must be created on the Pi. That is now a single
  command: `python -m scripts.deployment.configure` detects the network
  layout with `ip` and prompts only for the Admin PC and the admin
  password. See §8 below and `docs/SETUP.md`.
* **Two control-panel rendering gaps remain open** (`docs/PROGRESS.md`):
  the "network statistics" section and the "detections" section are not
  rendered in the HTML panel. The underlying data is now reachable over
  the JSON API for both — `/api/v1/capture-stats` was the missing half —
  so what is left is `pirewall/web/render.py` work only.

## 7. Setup tooling

Added after the entry points, so that the values most likely to be mistyped
are observed rather than retyped:

| Tool | Role |
|---|---|
| `scripts/deployment/discovery.py` | Reads the live layout from `ip -j` — WAN/LAN interfaces, the LAN's CIDR, the Pi's own address, the upstream gateway, and the neighbour table. Read-only: every command is `ip ... show`. |
| `scripts/deployment/configure.py` | Writes `config/local_config.toml` from that, plus the answers only a human can give. Also `--set-admin-pc` and `--set-password` as targeted edits. |
| `scripts/deployment/make_certs.sh` | Self-signed EC P-256 TLS pair with the `subjectAltName` clients actually verify. |

The split is deliberate: `pirewall_lan_ip` and `upstream_gateway` are the
two addresses safety validation refuses to ever block (spec §24), so a typo
in either silently removes that protection — detecting them removes the
whole class of error. `admin.admin_pc_ip` is the opposite case and is
**never** auto-selected: it is a policy decision ("which machine may
administer this firewall"), and the neighbour table only answers a
different question ("which hosts have talked to the Pi recently"). Detected
hosts are offered as numbered candidates; a human chooses, and typing an
address that has not appeared on the network is always available.

Both live in `scripts/`, not `pirewall/`, so the audit's "no `subprocess`
usage outside `NftablesBackend`" property of the *runtime* stays exactly
true — this is setup-time operator tooling. And per spec §21 they write a
config file and a certificate; they never bring up an interface, touch
`/etc`, or invoke `nft`/`systemctl`.

**Tested** — 35 tests. Discovery parsing against captured `ip -j` fixtures
(default-route extraction, IPv6 skipped per A5, down interfaces excluded,
neighbour states, the ambiguous-LAN warning, and every actionable error
path); config generation (valid `PirewallConfig`, no surviving
`CHANGE_ME`, SHADOW/fail_open defaults preserved); the atomic
validate-then-write; `prompt_admin_pc_ip` driven with scripted input
(including that it never defaults to a candidate); and `--set-admin-pc` as
a genuine targeted edit that preserves hand-tuned values.

**Also verified by running it** against a stubbed `ip` reproducing a Pi 4
gateway (`eth0` uplink, `wlan0` hotspot at 192.168.100.0/24): full
interactive setup, `--detect`, `--set-admin-pc` both interactively and via
`--admin-pc-ip`, `--set-password`, cert generation, and the resulting
config passing both entry points' `--check-config` and serving real
TLS 1.3. On macOS (no iproute2) it fails with an actionable message rather
than a traceback.

## 8. Checklist for the Pi

```sh
# 1. Config — detects the network, asks for the Admin PC and password
python -m scripts.deployment.configure
python -m pirewall.main --check-config

# 2. TLS
scripts/deployment/make_certs.sh <the "This Pi's LAN IP" configure printed>
python -m pirewall.api --check-config

# 3. Units (docs/DEPLOYMENT.md §5 and §7 for users/groups first)
sudo systemctl enable --now pirewall-core.service
systemctl status pirewall-core.service
ls -l /run/pirewall/core.sock          # expect: srw-rw---- pirewall-core pirewall-ipc

sudo systemctl enable --now pirewall-api.service
systemctl status pirewall-api.service

# 4. From the Admin PC only
curl --insecure https://<pi-lan-ip>:8443/api/v1/health
curl --insecure -N https://<pi-lan-ip>:8443/api/v1/events/stream -H "Authorization: Bearer <token>"

# 5. Confirm it is actually capturing
journalctl -u pirewall-core -f       # no CAPTURE_ERROR at startup
curl --insecure https://<pi-lan-ip>:8443/api/v1/capture-stats -H "Authorization: Bearer <token>"
```

Leave `firewall.enforcement_mode = "shadow"` until you have watched the
control panel long enough to agree with the decisions being made. Move to
`"assisted"` next (A7 puts high-confidence BLOCKs in an approval queue),
and only then to `"active"`.
