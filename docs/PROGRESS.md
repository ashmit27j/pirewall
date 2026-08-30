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
| 7 | API, auth, security events & control panel | Complete | Tested: auth (password hashing/verification, sessions, Admin-PC-IP restriction), the full RPC dispatcher (every operation via `LoopbackRpcClient`), every API endpoint end-to-end via `TestClient` (login, admin-pc restriction, session enforcement, rules disable/remove/approve/reject, allowlist CRUD, kill-switch, route-surface enumeration), the control panel's HTML rendering (every spec §30 section + addendum sections, XSS-escaping, empty-state handling), and both A4 import-isolation checks (`pirewall/api/`, `pirewall/web/` never import capture/firewall.manager/firewall.backend). 53 new tests (344 total). Environment-dependent *as originally written*: `UnixSocketRpcServer`/`UnixSocketRpcClient` against a real `AF_UNIX` socket, and TLS with real certificates. **The socket half was upgraded to Tested by the post-Phase-9 audit pass** — `AF_UNIX` is absent only on Windows (where that label was written), not on macOS/Linux, so the real transport is now exercised by `tests/integration/test_rpc_unix_socket.py`. TLS with real certificates remains Environment-dependent; `LoopbackRpcClient` exercises the exact same `CoreRpcDispatcher` logic in-process for everything else. See docs/ARCHITECTURE.md for the dependency decisions this phase made (stdlib `scrypt` over bcrypt/argon2, opaque tokens over JWT, hand-rolled HTML over Jinja2, uvicorn/httpx as FastAPI companions). |
| 8 | Raspberry Pi hardening, deployment & integrations (Wazuh/Netdata) | Complete | See detailed notes below. |
| 9 | Security/integration testing, docs & final validation | Complete | See detailed notes below. |
| — | Entry points & process runtime (`pirewall/main.py`, `pirewall/api/__main__.py`, `pirewall/runtime/`) | Complete | Not a numbered phase — the scoped follow-up the Phase 8 open question recommended. Tested: whole `CoreDaemon` end to end through every thread and the real `AF_UNIX` transport, the detection coordinator's ML-degradation paths, `sd_notify`, metrics, the event forwarder, rule expiry, both entry points' validation, `/config` redaction, the SSE stream (61 new tests, 472 total). Also verified by hand: both processes running together over real TLS and a real socket. Three defects found by running the code, each fixed with a regression test. Environment-dependent: `AF_PACKET`, `nft`, systemd supervision. See `docs/DEPLOYMENT_COMPLETE.md`. |
| — | Setup tooling (`scripts/deployment/configure.py`, `discovery.py`, `make_certs.sh`, `docs/SETUP.md`) | Complete | Network layout detected from `ip -j` instead of retyped; Admin PC and password asked for, never guessed. Tested: 35 tests over discovery parsing (captured `ip -j` fixtures), config generation and validate-then-write, the Admin-PC prompt, and `--set-admin-pc` as a targeted edit. Also run for real against a stubbed `ip` reproducing a Pi 4 gateway, end to end through both entry points and real TLS 1.3. Environment-dependent: `ip -j` output from a real Pi (fixtures are captured, not synthesized from imagination — but no Pi was available to confirm). |

### Audit pass (post-Phase 9)

A full audit-and-fix pass over the completed repository, treating the
claims in this file as things to verify rather than facts. Ran on macOS
(the same environment constraint as Phase 8/9 — still not Linux, so
`AF_PACKET`/`nft`/systemd remain unverifiable). Seven defects found and
fixed, each with a regression test verified to fail against the pre-fix
commit:

| # | Defect | Severity |
|---|--------|----------|
| 1 | Blocking `upstream_gateway` passed validation — severs all internet for the whole LAN (spec §24) | High |
| 2 | Blocking the Pi's own LAN address passed validation — kills management access and every client's default gateway (spec §24) | High |
| 3 | RPC socket mode was umask-derived — a default `0o022` umask made it world-connectable, exposing every privileged RPC operation to any local user (ADDENDUM.md A4) | High |
| 4 | `pirewall.firewall.manager` was transitively loaded into the pirewall-api process via `pirewall/ipc/__init__.py` (ADDENDUM.md A4) | Medium |
| 5 | RPC socket directory created non-traversable (`0o640`) under the very umask `pirewall-core.service` sets | Medium |
| 6 | Control-panel ids interpolated into inline JS handlers; `html.escape` does not make that safe (latent, not reachable with uuid4 ids) | Medium |
| 7 | `RpcError` escaped as an unhandled HTTP 500, so the control panel could not report a down core — contradicting ADDENDUM.md A6 | Medium |

Findings 1 and 2 resolve the long-standing "pirewall itself / management
access" open question (see below). Findings 3–5 were found by testing the
`AF_UNIX` transport for real for the first time, which also upgraded that
transport's own label from Environment-dependent to Tested.

Also verified and found sound, with no change needed: no `subprocess`
usage outside `NftablesBackend` and no `shell=True`/`os.system`/`eval`
anywhere; `Any` confined to the IPC envelope with justifications; no
circular imports; no secrets committed and `.gitignore` effective; the ML
schema-compatibility gate genuinely covers both load paths and both
inference paths; `enforce_admin_pc_ip` fails closed on a missing or
unknown client host; login compares username and password without
short-circuiting. Test quality was spot-checked for assertion-free tests —
the apparent hits all delegate to `pytest.raises` or a shared
`_assert_rejected` helper.

### Target-platform compatibility pass

Triggered by the operator confirming the deployment shape: enforcement on a
**Pi 4 (4 GB)**, Admin PC on **Omarchy or another Linux distro**. Verified
the project against those targets rather than assuming. Four defects found,
all in deployment-critical paths, all verified against upstream sources
rather than from memory:

1. **Python 3.12 was uninstallable on the target OS.** `docs/DEPLOYMENT.md`
   said `apt install python3.12`. Raspberry Pi OS Bookworm is Debian 12,
   which ships **Python 3.11** and has no `python3.12` package — an
   operator following the guide would stall at step 2. Relaxing
   `requires-python` was not an option either: `numpy`/`scipy` publish
   `aarch64` wheels only for cp312+. Fixed by installing the interpreter
   through `uv` (verified: `python-build-standalone` publishes
   `cpython-3.12.14-aarch64-unknown-linux-gnu`), which also makes the Pi
   run the same interpreter version as development.
2. **`integration.wazuh_port` defaulted to 1514, which cannot work.** 1514
   is Wazuh's *agent connection service* (AES-encrypted,
   enrollment-authenticated); `SyslogWazuhTransport` sends plain JSON
   lines, so events would never be ingested — and a refused connection is
   indistinguishable from "no events yet" from the Pi's side. Corrected to
   **514**, Wazuh's remote syslog collector, with deployment notes that it
   is disabled by default and must allow the Pi's IP.
3. **The static-IP template targeted the wrong network stack.**
   `deploy/network/dhcpcd-lan.conf.template` claimed dhcpcd was current for
   "Bookworm and earlier". It is the reverse: Raspberry Pi OS switched to
   **NetworkManager in Bookworm**, so dhcpcd applies to Bullseye and older.
   Deployment now leads with `nmcli` (including `ipv4.never-default yes`,
   so the LAN side does not steal the default route), and the template is
   marked Bullseye-era.
4. **Admin PC guidance assumed Debian-ish packaging.** Made distro-neutral,
   with explicit Arch/Omarchy notes — Wazuh publishes no official Arch
   package (AUR or the official container image), Netdata is in `pacman`.

**Verified sound, no change needed:** every dependency (`lightgbm`,
`scikit-learn`, `numpy`, `scipy`, `pydantic-core`) publishes `aarch64`
manylinux wheels, so nothing compiles from source on the Pi — but this
requires the **64-bit** image, now stated as a hard requirement. The
Linux-only modules import cleanly on macOS, so development works on either
platform.

**Measured, not estimated** (dev machine; re-measure on the Pi):

| Property | Measurement | Verdict for Pi 4 / 4 GB |
|---|---|---|
| Flow table at `max_flows=100000` | ~979 B/flow → **~93 MiB** | Comfortable inside `MemoryMax=768M` |
| Isolation Forest, single-flow scoring | **~15.6 ms/call** (`n_estimators=100`) | ~64 flows/s here → est. **10–20 flows/s on a Pi 4** |
| Isolation Forest, batch of 200 | **~0.088 ms/flow** | ~178× faster — the overhead is per-call, not tree traversal |

The inference figure is a genuine throughput ceiling on the target
hardware and is logged under "Open questions for the human" rather than
fixed here, because batching changes the shape of the detection layer's
inference call (new design work, not an audit fix).

### Entry-point session (post-audit)

Built the two missing systemd `ExecStart=` targets, `pirewall/main.py` and
`pirewall/api/__main__.py`, plus the `pirewall/runtime/` package that wires
the subsystems into a running process. This was the "own follow-up" the
Phase 8 open question recommended, not a re-opening of Phase 8/9. Ran on
macOS, so the Pi-specific half (`AF_PACKET`, `nft`, systemd supervision)
stays Environment-dependent. **`docs/DEPLOYMENT_COMPLETE.md` is the full
record**; the summary:

**Tested** — `ruff check .` clean, `pyright --strict` clean (194 files),
472 tests passing (61 new). New coverage: the whole `CoreDaemon` end to end
through every thread and the real `AF_UNIX` transport, against
`FakePacketCapture` + `FakeFirewallBackend` (8 integration tests); the
detection coordinator's ML-degradation paths; `sd_notify` against a real
datagram socket; metrics rate arithmetic; the event forwarder; rule expiry;
both entry points' config/credential/TLS validation; `/config` redaction;
and the SSE generator.

**Tested (manual, dev machine)** — both processes started for real over a
real `AF_UNIX` socket and a real self-signed certificate: socket mode
`srw-rw----` (A4), TLS 1.3 negotiated and TLS 1.2 refused, 401 → login →
`/status` through a real RPC round-trip, `/config` redacted, SSE delivering
live events, control panel rendering, capture correctly reported
unavailable with the process staying up to say so (A6), and a clean
`SIGTERM` shutdown that removed the socket.

**Three defects found by running the code**, each with a regression test:

| # | Defect | Severity |
|---|--------|----------|
| 1 | `RuleStatus.EXPIRED` was unreachable — `expires_at` was inert, so an ACTIVE rule stayed deployed in the backend forever (spec §25) | High |
| 2 | `AFPacketCapture.start()` leaked an untyped `AttributeError` where `AF_PACKET` is absent, crashing the daemon instead of degrading (spec §44, A6) | Medium |
| 3 | The live event stream was a WebSocket, which 404s under real uvicorn (no `websockets`/`wsproto` dependency); `TestClient` implements the protocol in-process and hid it. Replaced with SSE | Medium |

Defect 3 is worth remembering as a *testing* lesson: `TestClient` also
cannot read a never-ending `StreamingResponse` at all. Streaming behaviour
has to be tested by driving the generator directly and verified against
real uvicorn.

**Environment-dependent, unchanged** — `AFPacketCapture` on a real
interface, `NftablesBackend` against real `nft`, systemd supervision
(`Type=notify`, `WatchdogSec=`, `Restart=on-failure`, every sandboxing
directive), real TLS from the Admin PC, Wazuh/Netdata ingestion, and
detection accuracy (no trained models are present, so pirewall currently
runs behaviour-only by design).

**Deliberately not built** — `POST /api/v1/rules`. The validation chain's
authorization stage rejects any candidate the real decision engine did not
produce, so the endpoint could only work by weakening that stage. Confirmed
with the operator before omitting. See `docs/API.md`.

### Setup-tooling session

Follow-up to the entry-point session, prompted by the operator asking for
auto-configuration with the Admin PC still chosen by a human.

Added `scripts/deployment/discovery.py` (read the live layout from `ip -j`)
and `scripts/deployment/configure.py` (write `config/local_config.toml`
from it, plus `--set-admin-pc` / `--set-password` targeted edits), plus
`docs/SETUP.md` as the ordered copy-paste path. `make_certs.sh` switched
from RSA-4096 to EC P-256 — measured near-instant instead of tens of
seconds, which matters on a Pi 4, and verified to still negotiate TLS 1.3.

The design line worth recording: **detect what is a fact, ask what is a
policy.** `pirewall_lan_ip` and `upstream_gateway` are the two addresses
safety validation refuses to ever block (spec §24), so a typo silently
removes that protection — detecting them removes the class of error
entirely. `admin.admin_pc_ip` is deliberately never auto-selected: the
neighbour table answers "which hosts have talked to the Pi", not "which
machine may administer the firewall", and guessing wrong either locks the
operator out or grants the wrong host access. Candidates are offered;
a human chooses.

Both modules live in `scripts/`, not `pirewall/`, so the audit's "no
`subprocess` usage outside `NftablesBackend`" property of the runtime stays
exactly true. Per spec §21 they write a config file and a certificate and
nothing else — no interface is brought up, no `/etc` file touched, no
`nft`/`systemctl` invoked.

**Tested** — 35 new tests (507 total). **Also run for real** against a
stubbed `ip` reproducing a Pi 4 gateway; the generated config passed both
entry points' `--check-config` and served real TLS 1.3.
**Environment-dependent** — `ip -j` output from an actual Raspberry Pi OS
Bookworm machine. The fixtures are realistic but no Pi was available to
confirm them, so an unexpected field shape there is the one thing that
could still surprise; `--detect` is the first command to run on the Pi for
exactly that reason.

**Not built, deliberately** — editing configuration from the control panel.
`GET /api/v1/config` is read-only with no write counterpart: a panel that
could rewrite `enforcement_mode` or `admin_pc_ip` over HTTP would make one
stolen session equivalent to owning the firewall (spec §45). Configuration
changes stay an out-of-band, SSH-and-restart operation.

### Real-hardware performance benchmark session (spec §40) — 2026-08-30

**The first measurements taken on the actual Raspberry Pi 4**, against the
running `pirewall-core` service rather than Fake implementations. Full report,
data and charts: **`benchmarks/2026-08-30/REPORT.md`**. Observation only — no
runtime code changed, enforcement mode (`assisted`) and the nftables ruleset
untouched, zero adaptive rules created during the run.

Host: Raspberry Pi 4 Model B Rev 1.5, 4 GB, Raspberry Pi OS aarch64, Python
3.12.14. Two phases: 31 min idle and 30 min under a generated-load ladder,
both sampled every 5 s.

**Tested** (real Pi 4, real `AF_PACKET` capture, real CICIDS2017 artifacts —
LightGBM v0.4.0 + Isolation Forest v0.2.0):

| measurement | idle | under load |
|---|---|---|
| packets seen by `pirewall-core` | 1 (in 31 min) | 602,502 |
| `pirewall-core` CPU (of one core) | mean 0.30 %, max 1.40 % | mean 15.56 %, p95 99.60 %, max 111.40 % |
| `pirewall-core` RSS | 147.80–147.83 MB (flat) | 147.83 → 168.78 MB |
| kernel packet drops | 0 | 5,050 (0.84 % overall, concentrated in two 15 s ticks) |
| flows completed / flow table peak | 0 / 0 | 4,662 / 4,500 open flows |
| detection queue peak | 0 | 3,084 flows |

Per-stage latency, uncontended mean (ms/operation): packet parse 0.067,
flow aggregation 0.060, feature extraction 0.092, **LightGBM 1.693**,
**Isolation Forest 30.695**, behavior analysis 0.732, threat assessment 0.184,
decision 0.055, candidate generation 0.004, **end-to-end packet→decision
33.454**. Under concurrent load the end-to-end mean is 60.9 ms (p95 130.4).

**Isolation Forest is 92 % of end-to-end cost**, capping the flow path at
**≈30 decisions/s**. Confirmed independently: the daemon drained a 3,084-flow
backlog at 28.8 flows/s.

**The predicted bottleneck is now observed, not predicted.** Once flows
completed faster than Isolation Forest could score them, `pirewall-core`
saturated a core and the kernel dropped **38.5 % of packets in one 15 s
window**. The packet path itself is fine: 697 packets/s cost 8.7 % of a core
with zero drops.

**Dev-machine vs Pi gap, apples to apples** (`performance_smoke.py` re-run
unmodified on the Pi, same Fake backends and placeholder models): the Pi 4 is a
consistent **2.3–3.8× slower** across every stage — capture+parse 2.8×, flow
aggregation 3.2×, feature extraction 2.6×, LightGBM 3.8×, Isolation Forest
2.7×, threat assessment 2.3×, rule deployment 3.7×. Nothing fell off a cliff.

This settles the long-standing open question: the earlier estimate of
"10–20 flows/s on a Pi 4" for Isolation Forest was **pessimistic by ~1.6×** —
the real figure is **30.3 flows/s** (placeholder) / **32.6 flows/s** (real
model) — but the conclusion it drove (batch inference, or accept the ceiling
in SHADOW/ASSISTED) stands, and is now backed by measured numbers. Swapping the
placeholder model for the real one barely moved Isolation Forest (33.0 → 30.7
ms), confirming the cost is scikit-learn's fixed per-call overhead rather than
tree traversal.

**Two observability defects found (reported, not fixed — this run was
observation-only). Both are spec §41 items:**

1. **`CaptureStatistics.packets_dropped` is not cumulative but is used as
   one.** `AFPacketCapture._read_kernel_drops()` reads
   `getsockopt(SOL_PACKET, PACKET_STATISTICS)`, and the kernel **zeroes
   `tp_drops` on every read**. Each 15 s tick reports only drops since the
   previous tick, and the value can decrease. `NetdataMetricsSnapshot.packet_drops`
   therefore exports a per-interval delta under a name that reads as a lifetime
   total; anything differencing it as a counter yields negative rates.
   Fix: accumulate a running total in `AFPacketCapture`.
2. **Live flow-table size is not observable.** `StatusResult.tracked_flow_count`
   is `len(CoreStateStore.flows)` — the bounded *completed-flow* ring buffer
   (capped at `api.history_size`), not the aggregator's table. During the run it
   saturated at 500 while the real table held 4,500 flows. The live figure is
   computed in `CoreDaemon._tick()` but only reaches the Netdata snapshot, which
   on this deployment cannot be delivered. Fix: route it into `CoreStateStore`
   so `get_status` can report it, and rename the field whose current meaning
   contradicts its name.

**Still Environment-dependent after this run:**

- **Behaviour under genuine multi-host LAN traffic.** `wlan0` had **no
  associated stations** — `iw dev wlan0 station dump` empty, 12 s of `tcpdump`
  captured zero packets, and the daemon saw one packet in 31 minutes. Load had
  to be generated from the Pi itself as broadcast UDP on `wlan0` (real frames
  through the real capture path, but not multi-host traffic). iperf3 between two
  LAN devices was impossible: there is no second device.
- **Throughput as bits/second.** 802.11 broadcast caps at ~0.8 Mbit/s
  (~700 packets/s) regardless of sender count. This run bounds per-packet and
  per-flow CPU cost, not bandwidth.
- **Real end-to-end nftables rule-deployment latency** — requires mutating the
  live ruleset. Decomposed instead: validation chain + Fake deploy **0.220 ms**
  (Mocked), real read-only `nft` round-trips **7.4–10 ms** (Tested). Deployment
  is dominated by forking `nft`, not by validation.
- **Detection accuracy** — unchanged by this run. Every flow was benign
  broadcast (all 4,662 scored LOW → ALLOW → no candidate rule). The spec §34
  attack lab is still outstanding.
- **A headless baseline.** The Pi was running a desktop session and the CLI that
  drove the benchmark, so *host-level* CPU/memory are not a clean pirewall
  baseline; the per-process figures are.
- **O(n) rule-deployment growth with `active_rules()`** — not re-measured;
  reaching a large active-rule count through the real A3 rate cap takes longer
  than one session.

`ruff check .` clean and `pyright` (strict, per `pyproject.toml`) clean with the
benchmark tooling added; `benchmarks/` is outside pyright's `include`.
matplotlib was installed into a **separate throwaway virtualenv**, not
pirewall's dependency set (`CLAUDE.md`).

### Wireless-deployment documentation session

The operator's deployment target was confirmed as **all-wireless**: the
onboard Pi radio (`brcmfmac`) associated as a *client* to an existing
upstream Wi-Fi network as the WAN, and an RTL8188EUS USB dongle (USB ID
`0bda:8179`) running as an access point as the LAN. Documentation and test
coverage only; **no runtime code changed**.

**Verified first, not assumed** — the premise that pirewall's runtime is
interface-type agnostic was checked rather than trusted:

- `network.wan_interface`, `network.lan_interface` and `capture.interface`
  are plain `str = Field(min_length=1)` in `pirewall/config/models.py` — no
  pattern, no type enum.
- `AFPacketCapture` passes the name straight to `sock.bind((name, 0))` and
  `socket.if_nametoindex(name)`; both resolve any interface the kernel has.
- Grepping `pirewall/` for `wlan|eth0|eth1|wifi|wireless|ethernet` returns
  only `capture/parser.py`'s comments about Ethernet *framing*. Grepping for
  `iifname|oifname|wan_interface|lan_interface` returns only the two config
  fields — the firewall backend emits no interface match at all; adaptive
  rules are address/port-based. Interface names reach `deploy/*.template`
  as `${WAN_INTERFACE}`/`${LAN_INTERFACE}` string substitution and nowhere
  else.
- `scripts/deployment/discovery.py` picks the WAN from whichever `dev`
  carries the IPv4 default route and the LAN as the first addressed non-WAN
  interface *sorted by name* — no `eth`/`wlan` preference anywhere.

So the conclusion holds, with one honest caveat recorded rather than
patched around: `choose_lan_interface` breaks ties **alphabetically**. That
is pre-existing and identical for `eth0`/`eth1`, but it bites harder with a
USB radio, whose `wlan0`/`wlan1` ordering is not stable across reboots.
Documented (`docs/DEPLOYMENT.md` §4.1: `ethtool -i` to identify, a
`systemd.link` snippet to pin a stable name, `--detect` to re-confirm after
a reboot) rather than changed — guessing which radio the operator meant is
exactly what that function deliberately refuses to do.

**Implemented (as documentation)** — `docs/DEPLOYMENT.md` §4 restructured
so WAN and LAN are each an explicit *pick one* between a wired and a
wireless path, with the previously-documented wired paths kept intact and
relabelled as one of two options rather than the only one. New: §4.1
interface identification (`ethtool -i`: `brcmfmac` = onboard,
`rtl8xxxu`/`8188eu` = the dongle), §4.3 Option B Wi-Fi-client WAN via
`nmcli device wifi connect`, §4.4 Option B Wi-Fi-AP LAN via
`nmcli device wifi hotspot` **including the mandatory
`ipv4.addresses` override** — the hotspot defaults to `10.42.0.1/24`, and
leaving that mismatched with `network.pirewall_lan_ip` /
`network.protected_network` would let pirewall start looking healthy while
safety-validating an address the Pi does not hold — §4.6 on why neither
choice reaches pirewall's code, and a "switching later" subsection stating
that moving a side between modes is `nmcli con down`/`delete` plus the
other path's commands, with `--detect` afterwards and no pirewall config or
code change unless the interface *name* changed. `docs/SETUP.md` gained the
condensed command-only version of all of it; `deploy/network/README.md`'s
order-of-operations no longer implies a wired-only LAN.

**Implemented (as documentation)** — `docs/DEPLOYMENT.md` §4.6 now states
explicitly that `AF_PACKET` capture is identical on a managed-mode client
interface and an AP-mode interface, because mac80211 strips 802.11 and
synthesizes 802.3 headers before the packet reaches the socket, so
`capture/parser.py` sees the same frames it would on `eth0`. Previously an
unstated assumption; noted there that this holds for `managed`/`AP` but
*not* `monitor` mode, which pirewall does not use.

**Tested** — `tests/unit/test_discovery.py::TestWirelessLayout`, 5 new
tests (512 total). Adds `_WIRELESS_ROUTES`/`_WIRELESS_ADDRESSES`/
`_WIRELESS_NEIGHBOURS` fixtures with a **wlan-named WAN and a different
wlan-named LAN** — a shape no previous fixture covered, since the existing
one is `eth0` WAN + `wlan0` LAN. Covers `parse_default_route`,
`parse_addresses`, `choose_lan_interface` (including that a third addressed
wlan interface warns exactly as `eth1`/`wlan0` does), and `discover()` end
to end with `_run_ip` stubbed — asserting `pirewall_lan_ip` and
`upstream_gateway` come out right on a wireless layout, and that neighbour
scanning targets the AP interface rather than the uplink radio. `ruff check
.` clean, `pyright --strict` clean, full suite green; nothing was weakened
to achieve that.

**Environment-dependent** — everything about the actual hardware. Stated
plainly because none of it could be exercised here:

- **RTL8188EUS AP-mode support is not confirmed.** The in-kernel
  `rtl8xxxu` driver's AP support for this chipset is incomplete and
  kernel-version-dependent: `iw list` may omit `AP` entirely, or list it
  while the hotspot fails to start, accepts no clients, or drops them after
  association. §4.4/§4.4.1 document the `iw list` check as the thing to run
  *before* troubleshooting `nmcli`, and the fallback of replacing the
  driver with the out-of-tree DKMS one at
  <https://github.com/aircrack-ng/rtl8188eus>. **That link is given instead
  of inlined install steps on purpose** — the build depends on the exact
  kernel headers and on blacklisting `rtl8xxxu`, and has not been run by
  anyone here; inlining unverified commands is what the labeling rules
  exist to prevent. Same category as every other host-specific step in
  `DEPLOYMENT.md`: **documented, not automated**.
- **The hotspot working end to end has not been observed.** The `nmcli`
  sequence, the `ipv4.method shared` + `ipv4.addresses` override actually
  producing DHCP leases on `network.protected_network`, and a real client
  associating and routing through the Pi are all unverified. **A human
  must**: run §4.4 Option B on the real dongle, then confirm
  `ip addr show "$LAN_IF"` holds `pirewall_lan_ip`, `iw dev "$LAN_IF" info`
  reports `type AP`, and a real client device gets a lease in the
  configured subnet and **not** in `10.42.0.0/24`.
- **NAT ownership needs a human decision on the box.**
  `ipv4.method shared` makes NetworkManager install its own masquerade
  rules alongside whatever `deploy/rendered/nat-masquerade.nft` loads.
  §4.4 Option B says to run `sudo nft list ruleset` after §4.5 and decide
  deliberately which one owns NAT. Not resolved here — which is correct
  either way depends on the live ruleset, and this repository never touches
  it.
- **Wi-Fi-client WAN association** (`nmcli device wifi connect`, and the
  Pi keeping its default route over a variable-latency shared medium) is
  likewise real-hardware-only.
- **`AF_PACKET` on an AP-mode interface** — the §4.6 claim is a statement
  about kernel behaviour, not something exercised here. `AFPacketCapture`
  remains Environment-dependent exactly as it was for Phase 2; a wireless
  LAN does not change that label in either direction.

The ~150 Mbps 2.4 GHz 802.11b/g/n ceiling of this dongle (§4.4.2) is
recorded as an expectation-setting note. It does not affect pirewall —
capture, flow tracking, detection and enforcement are link-rate
independent — but it is the throughput ceiling of the protected LAN.

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

### Real-data training session (laptop, post entry-point/setup-tooling)

Operator provided a real UNSW-NB15 dataset subset under a same-day
deadline (`data/UNSW_NB15_training-set.csv` + `data/UNSW_NB15_testing-set.csv`,
the standard 48-feature ML-ready partition files, headers verified
identical). Both files were concatenated into
`data/UNSW_NB15_combined.csv` (gitignored, not committed) so both training
CLIs use the full 257,673 rows supplied rather than discarding one file —
class breakdown: Normal 93,000 / Generic 58,871 / Exploits 44,525 /
Fuzzers 24,246 / DoS 16,353 / Reconnaissance 13,987 / Analysis 2,677 /
Backdoor 2,329 / Shellcode 1,511 / Worms 174. Ran on a Windows dev laptop
(`uv` installed via `pip install uv` under `py -3.12`, distinct from the
project's usual macOS dev environment — `uv sync` and `pytest tests/ml/`
both ran clean first as a sanity check before training).

- **Tested** — `python -m scripts.train.train_lightgbm --dataset unsw
  --dataset-path data/UNSW_NB15_combined.csv --model-version 0.1.0
  --output-dir pirewall/ml/artifacts` and the equivalent
  `train_isolation_forest` command, both **without** `--placeholder`
  (`is_placeholder: false` — this is real attack/normal traffic, not a
  synthetic fixture) but with `notes` stating plainly that the dataset is a
  reduced subset, not the full raw UNSW-NB15 corpus (~2.5M flows) or
  CICIDS2017. Produced real artifacts replacing the old Phase 4 synthetic
  placeholders: `pirewall/ml/artifacts/lightgbm_model.txt` (accuracy
  0.7155, macro-F1 0.4120 on a 25% held-out internal split) and
  `pirewall/ml/artifacts/isolation_forest_model.joblib` (precision 0.5639,
  recall 0.0702, FPR 0.0968, FNR 0.9298). `tests/ml/` (36 tests) re-run and
  still green against the new artifacts. Both `.metadata.json` sidecars
  were produced directly by the training run (never hand-edited), carrying
  the real `feature_schema_version`/`feature_ordering` for the runtime
  schema-compatibility gate to check against.
- **Explicit limitation, not a formality**: these numbers must not be read
  as representative of full-dataset performance. 257,673 rows across a
  same-day-provided subset is materially less data and label diversity than
  a full CICIDS2017 or complete UNSW-NB15 corpus — expect **materially
  weaker real-world detection accuracy** than a full training run would
  produce, per spec §34's attack-lab caveat and this file's Phase 4 note
  above.
- **Isolation Forest's low recall (0.0702) is a pre-existing pipeline
  property, not new this session**: `train_isolation_forest` fits on the
  whole training split (attacks included), not a normal-only subset, per
  `pirewall/ml/training/isolation_forest_trainer.py`'s own docstring
  ("labels are only used for evaluation... the model itself never sees
  labels"). On a dataset that is ~64% attack traffic, the fitted "normal"
  boundary is far looser than an anomaly detector trained on genuinely
  benign-only traffic would produce. Not fixed here — changing the
  trainer's fit-time filtering is a design change outside this session's
  scope (train models with the existing pipeline, not modify it).
- **Deployment**: copy `pirewall/ml/artifacts/lightgbm_model.txt`,
  `lightgbm_model.txt.metadata.json`, `isolation_forest_model.joblib`, and
  `isolation_forest_model.joblib.metadata.json` to
  `/opt/pirewall/pirewall/ml/artifacts/` on the Pi (manual `scp`/`rsync`,
  per `docs/DEPLOYMENT.md` §9's secure update procedure) then restart
  `pirewall-core` — the schema-compatibility gate will refuse a bad
  artifact rather than silently degrading. No manual metadata edits needed;
  the sidecars are already correct as training output.

### CICIDS2017 real-data training session (laptop, same machine as UNSW-NB15 run)

Operator provided the full, real CICIDS2017 "MachineLearningCVE" release —
all 8 standard per-day CSVs (`data/cicids2017/`, Monday–Friday working-hours
splits, gitignored, not committed) — and asked for training via
`cicids_adapter.py` specifically, **not** a repeat of the prior session's
hand-concatenation approach. Two real, previously-undiscovered pipeline
defects were found and fixed rather than worked around, plus one deliberate
methodology change:

1. **`cicids_adapter.py`'s column assumption was wrong for the real,
   published dataset.** The adapter (written and only ever tested against
   synthetic fixtures in Phase 4) assumed the "MachineLearningCVE" release
   carries real Source IP/Source Port/Destination IP/Protocol columns. It
   doesn't — verified against all 8 real files (identical headers, confirmed
   by hash): only "Destination Port" identifies the connection, and nothing
   names the transport protocol. This is the same category of surprise as
   the prior session's abandoned raw UNSW-NB15 files, but this time it was
   fixed, not abandoned. `source_ip`/`destination_ip` now use the same
   documented placeholder convention `unsw_adapter` already established
   (`10.255.255.1`/`.2`), `source_port` is `None`, and `protocol` is
   *inferred* (nonzero TCP flag count → TCP; else a well-known-UDP-port
   match on `destination_port`; else defaults to TCP) — a disclosed
   heuristic, not a fabricated value; see the adapter's module docstring and
   `docs/FEATURE_SCHEMA.md`'s CICIDS2017 caveat entry for the exact rule.
   `_REQUIRED_COLUMNS` updated to match; `tests/ml/test_cicids_adapter.py`
   and `tests/ml/test_train_cli.py`'s fixtures rewritten to the real column
   layout (12 tests updated/added). All 8 real files were then confirmed to
   load cleanly end-to-end: **2,830,628 flows loaded, 115 skipped (0.004%,
   all a `last_seen < first_seen` edge case from a handful of rows with a
   negative-after-rounding duration) — not the column-mismatch failure mode
   the prior UNSW-NB15 session hit.** All 8 files share byte-identical
   headers, so the phase prompt's "Thursday/Friday may differ" concern did
   not apply to this download.
2. **`scripts/train/_common.py`/both training CLIs only accepted a single
   `--dataset-path`.** CICIDS2017 ships as 8 separate files with no single
   canonical "the CSV" the way UNSW-NB15's partition files are. Fixed by
   making `--dataset-path` accept multiple paths (`nargs="+"`) and
   `load_dataset_or_exit` load+merge each file independently through the
   adapter (never a hand-merged CSV) into one `DatasetLoadResult`.
3. **Isolation Forest fit-time methodology changed to normal-only**, per the
   phase prompt's explicit instruction not to silently repeat the prior
   UNSW-NB15 session's low-recall pattern. `train_isolation_forest` now
   filters `x_train` to only `not is_attack_label(label)` rows before
   `.fit()` (evaluation still runs over the full mixed held-out split) —
   CICIDS2017 has ample benign traffic to make this feasible (Monday is
   100% BENIGN). This is a trainer-module change, so it also applies to any
   future UNSW-NB15 retrain, not just this session's CICIDS2017 run.
4. **Found while training, fixed rather than worked around**: both CLIs
   crashed with `UnicodeEncodeError` printing results on a non-UTF-8 Windows
   console (cp1252) — CICIDS2017 itself ships mojibake in three "Web Attack"
   label variants (a `�` byte), and the LightGBM run's model+metadata had
   already saved successfully before the crash on the confusion-matrix
   print. Fixed with `scripts/train/_common.make_console_output_encoding_safe`
   (reconfigures stdout/stderr to replace un-encodable characters instead of
   raising), called at the top of both `main()`s.

All fixes verified: `ruff check .` clean, `pyright` (strict) clean, full
suite **492 passed, 20 skipped** (skips are macOS/Linux-only tests,
unrunnable on this Windows dev machine) both before and after training.

**Tested, real data, not placeholder** —
`uv run python -m scripts.train.train_lightgbm --dataset cicids --dataset-path <all 8 files> --model-version 0.1.0 --output-dir pirewall/ml/artifacts`
and the equivalent `train_isolation_forest` command, both **without**
`--placeholder` (`is_placeholder: false`). Results:

| Model | Metric | Value |
|---|---|---|
| LightGBM | accuracy | 0.8996 |
| LightGBM | macro-F1 | 0.2367 |
| Isolation Forest (normal-only fit) | precision | 0.6014 |
| Isolation Forest (normal-only fit) | recall | 0.4450 |
| Isolation Forest (normal-only fit) | false positive rate | 0.0721 |
| Isolation Forest (normal-only fit) | false negative rate | 0.5550 |

Isolation Forest's recall improved substantially over the prior UNSW-NB15
run's 0.0702 (whole-split fit) to 0.4450 (normal-only fit) — direct evidence
the methodology change mattered, not just a different dataset.

**Explicit, plain-language limitations — read before deploying:**

- **LightGBM's overall accuracy (0.8996) is misleading on its own; macro-F1
  (0.2367) is the honest number.** CICIDS2017 is dominated by BENIGN
  traffic (2,272,982 of 2,830,628 rows, ~80%) with several attack classes
  that are vanishingly rare — Heartbleed (11 rows), Web Attack Sql
  Injection (21), Infiltration (36), Bot (1,966). The held-out confusion
  matrix shows the model gets **zero correct predictions** for Bot, DoS
  GoldenEye, and DoS Slowhttptest, and near-zero for the Web Attack
  variants — a model this imbalanced will not reliably detect those attack
  types in production. This is a real class-imbalance limitation of the
  dataset as trained here, not a training bug; addressing it (class
  weighting, oversampling rare classes, or a separate rare-class model)
  would be a design change outside this session's scope.
- **Isolation Forest still misses more than half of attacks (FNR 0.5550).**
  Better than the prior UNSW-NB15 run, but "an anomaly is evidence, not
  automatically malicious" (spec §14) — this model alone is not a reliable
  detector; it's one signal `pirewall.engine.threat.assess_threat` combines
  with LightGBM's known-attack evidence and behavioral analysis.
- **`protocol_is_tcp`/`protocol_is_udp`/`protocol_is_icmp` are trained on
  inferred, not observed, protocol values** for every row in this dataset
  (see defect 1 above) — a real, disclosed limitation of this dataset
  variant, not something a human deploying this model should assume is
  ground truth the way live `AFPacketCapture` traffic would be.
- **`source_ip`/`destination_ip`/`source_port` carry no real information**
  in this dataset variant (fixed placeholders / always `None`) — same
  category of limitation `unsw_adapter` already had, now shared by both
  adapters. Neither trained model can have learned anything from real
  address/port identity, only from the dataset's per-flow statistics.
- **This is one full pass over the standard CICIDS2017 release, not a
  larger or more diverse corpus.** Real-world traffic on the actual Pi 4
  deployment will differ from a 2017 university-network capture in
  composition, attack tooling, and normal-traffic patterns — expect
  detection quality to drift from these numbers per spec §34's attack-lab
  caveat.

**Replaces, not supplements, the prior UNSW-NB15-trained artifacts** — both
`pirewall/ml/artifacts/lightgbm_model.txt` and
`pirewall/ml/artifacts/isolation_forest_model.joblib` (plus sidecars) were
overwritten by this session's CICIDS2017 run. `pirewall-core` loads whatever
single model file is present at that path; it does not merge or ensemble
across dataset-trained versions.

**Deployment — copy to the Pi** (manual `scp`/`rsync`, per
`docs/DEPLOYMENT.md` §9's secure update procedure, then restart
`pirewall-core`):

```sh
scp pirewall/ml/artifacts/lightgbm_model.txt \
    pirewall/ml/artifacts/lightgbm_model.txt.metadata.json \
    pirewall/ml/artifacts/isolation_forest_model.joblib \
    pirewall/ml/artifacts/isolation_forest_model.joblib.metadata.json \
    pi@<pi-host>:/opt/pirewall/pirewall/ml/artifacts/
```

### CICIDS2017 imbalance-remediation session (laptop, same machine)

Operator asked for class-imbalance remediation on the CICIDS2017 pipeline
(LightGBM macro-F1 0.2367, Isolation Forest recall 0.4450 from the prior
session): a genuine 3-way train/validation/test split, training-split-only
`imbalanced-learn` resampling (undersample the majority class, SMOTE the
rarest), LightGBM class weighting, PR-curve-based per-class decision
thresholds, and an Isolation Forest `contamination`/`max_samples` sweep.
Every technique was implemented as asked; the honest result is that most of
them made things worse on this dataset, verified by a controlled ablation
rather than assumed, and the delivered model does **not** use the ones that
did.

**New dependency**: `imbalanced-learn>=0.12` (training-only, never imported
by runtime `pirewall/` code) — justified in `docs/ARCHITECTURE.md` per
CLAUDE.md's "ask first, say why" dependency rule; the operator's own
instruction was the request to add it.

**Built** (`pirewall/ml/training/common.py`, `resampling.py`,
`lightgbm_trainer.py`, `isolation_forest_trainer.py`, both
`scripts/train/*.py` CLIs):

1. `split_train_val_test` — per-class-stratified train/validation/test
   partition (`ThreeWaySplit`), replacing the old single train/test split
   for both trainers. Validation is for threshold/hyperparameter selection;
   test is the once-only holdout for reported metrics.
2. `pirewall/ml/training/resampling.py` — `resample_training_split`
   (`RandomUnderSampler` on the auto-detected majority class down to
   `undersample_ceiling`, `SMOTE` on every class at or below
   `oversample_ceiling` up to `oversample_target`), called on the training
   split only. A singleton class (count < 2) is left untouched rather than
   crashing SMOTE.
3. LightGBM: optional balanced per-sample class weights (`class_weighting`,
   the standard `n_samples/(n_classes*count)` formula — `is_unbalance`/
   `scale_pos_weight` are documented as binary/`multiclassova`-only, not
   applicable to the `multiclass` softmax objective this trainer uses, so
   per-sample weights are the correct equivalent) and optional per-class
   PR-curve threshold tuning on validation (`tune_thresholds`), decoded via
   "thresholded argmax" (`argmax(proba - threshold)`), gated so it's only
   adopted if it beats plain argmax on validation macro-F1.
4. Isolation Forest: `contamination`/`max_samples` exposed as real
   parameters (previously hardcoded to sklearn's defaults), plus
   `sweep_isolation_forest_contamination` — fits one model per candidate on
   the training split, evaluates each on validation only, never touching
   test.
5. Both CLIs gained `--val-fraction`, `--resampling`/`--no-resampling` +
   ceiling/target flags, `--class-weighting`/`--no-class-weighting`,
   `--threshold-tuning`/`--no-threshold-tuning`,
   `--contamination`/`--max-samples`/`--contamination-sweep`. A genuine,
   unrelated Windows bug was also fixed in passing: both CLIs crashed with
   `UnicodeEncodeError` printing results containing CICIDS2017's own
   mojibake label bytes on a non-UTF-8 console — fixed with
   `make_console_output_encoding_safe()` (stdout/stderr `errors="replace"`).

**Tested**: 14 new tests (`tests/ml/test_resampling_and_split.py`) —
`split_train_val_test` partitions every row exactly once, gives a rare
class representation in every split, and (regression test) does not block
rows by class in the output order; `resample_training_split` caps the
majority class, oversamples rare classes to target, no-ops below both
thresholds; LightGBM class weighting/resampling/threshold-tuning each run
and are correctly recorded, resampling only changes the train split's
reported size (regression test for a real bug found and fixed, see below),
and (regression test) threshold tuning never scores worse than plain
argmax on test; Isolation Forest accepts `contamination`/`max_samples`, the
sweep returns one result per candidate, and the sweep/final-training calls
agree on split sizes for the same seed. `ruff check .` clean, `pyright`
(strict) clean, full suite **506 passed, 20 skipped** — all pre-existing
tests still pass unmodified against the new (backward-compatible-by-default)
trainer APIs.

**Three real bugs found by running the code against real data, each fixed
with a regression test — this is the substantive part of this session, not
a footnote:**

1. **`split_sizes["train"]` reported the pre-resample count, not the count
   actually used for training** — a straightforward copy-paste artifact
   (`len(split.y_train)` instead of `len(y_train)` after reassignment).
   Caught by `test_train_lightgbm_resampling_only_changes_the_train_split`
   asserting the reported size actually changes when resampling is applied.
2. **SMOTE crashed on any class with exactly 1 training example** (needs at
   least 2 to find a neighbor) — would have broken the existing 2-row CLI
   fixture test the moment resampling defaulted on. Fixed by requiring
   `count >= 2` before a class is eligible for oversampling.
3. **The stratified split silently produced a training set ordered as
   contiguous per-class blocks** (all ~1.6M BENIGN rows, then each attack
   class's block in sequence) — `split_train_val_test` built each split by
   concatenating one index block per class without a final shuffle. This
   is invisible to any consumer that doesn't care about row order, but
   LightGBM's histogram bin-construction samples sequentially from the
   front of the dataset: it was building feature bins almost entirely from
   BENIGN rows, unable to resolve other classes' feature ranges at all.
   **Measured effect on real data**: PortScan recall 0.0% -> 73.95%,
   SSH-Patator 0.0% -> nonzero, accuracy 0.5431 -> 0.8899, on the identical
   "no intervention" configuration -- before vs after this one fix. This
   was caught by directly comparing a "plain" run against the original
   (pre-refactor) session's baseline numbers, noticing the gap was too
   large to be sampling variance, and root-causing it rather than
   shrugging it off as "different random split." Fixed by shuffling each
   split's index list after concatenation
   (`test_split_train_val_test_does_not_block_rows_by_class` regression
   test). **This bug affected every ablation run before it was found and
   fixed in this same session** — none of those earlier numbers are
   reported below; only post-fix runs are.

**Controlled ablation, all runs on the identical fixed train/val/test
split (seed 42, `--val-fraction 0.15 --test-fraction 0.15`, same 8-file
CICIDS2017 dataset) — this is the actual answer to "which approach was
used and why":**

| Configuration | Test accuracy | Test macro-F1 | BENIGN recall |
|---|---|---|---|
| **Plain (no resampling/weighting/thresholds) — DELIVERED** | **0.8899** | **0.1975** | **94.5%** |
| Resampling only (undersample BENIGN->150k, SMOTE rare classes->5k) | 0.5182 | 0.1747 | 43.3% |
| Class weighting only (balanced per-sample weights) | 0.1507 | 0.1496 | ~0% |
| Resampling + class weighting (plain argmax) | 0.0655 | 0.0676 | 0.09% |
| Resampling + class weighting + threshold tuning (gated) | 0.4643–0.7605 | 0.0896–0.1594 | varies, still poor |

**None of the requested LightGBM remediation techniques beat the plain
baseline on this dataset, and two of them are actively dangerous —**
this is the honest finding, not a partial success dressed up:

- **SMOTE from single/double-digit source counts is overfitting, not
  helping.** Heartbleed (7 real training rows) and Web Attack-Sql
  Injection (15 rows) oversampled to the requested 5,000 target is a
  700x/333x multiplier — interpolating within that few real points
  produces a dense synthetic sub-manifold the model then over-trusts. In
  the combined run's confusion matrix, real BENIGN flows got
  misclassified as `Web Attack-Sql Injection` 8,640 times and as
  `Heartbleed` 874 times — a direct, measurable false-positive cost from
  this specific technique, not a hypothetical risk the phase prompt's own
  "without causing overfitting" caveat had already flagged as possible.
- **"Balanced" per-sample class weighting (`n_samples/(n_classes*count)`)
  is far too aggressive for a 15-class problem this imbalanced.** Applied
  on top of the already-resampled distribution it collapsed BENIGN recall
  to 0.09% (292 of 340,947 real benign test flows correctly identified) —
  a firewall built on this model would flag essentially all legitimate
  traffic as malicious. This is a case where following the literal
  instruction (try class weighting) and the literal formula (the standard
  "balanced" heuristic) produces a model that is actively worse than
  useless for the stated purpose (spec §24's whole point).
- **Per-class independently-optimized PR-curve thresholds do not compose
  into a valid multiclass decision rule.** `argmax(proba - threshold)`
  compares 15 classes' margins against each other, but each threshold was
  chosen by an independent one-vs-rest optimization with no cross-class
  consistency constraint. Even after two rounds of fixes (a
  self-validating gate comparing thresholded vs. plain-argmax on
  validation macro-F1; a minimum-validation-support guard requiring 50+
  positive examples before a class gets its own threshold, falling back
  to the mean of well-supported classes' thresholds otherwise) it still
  produced degenerate thresholds (e.g. DDoS, with ~19,000 validation
  examples, landing on `1.68e-305`) that collapsed test macro-F1 to
  0.0896–0.0910 depending on configuration. The gate "worked" in the
  sense that it correctly reported `thresholds_used`, but a gate that
  compares aggregate validation macro-F1 cannot detect that the
  *decoding mechanism itself* is unsound — it only ever demonstrated that
  the specific thresholds found on this validation draw happened to score
  marginally better there while generalizing badly. **Left implemented,
  tested (`tune_thresholds=True` never scores worse than plain argmax
  *on the synthetic test fixture used in `tests/ml/`*, which is small and
  well-separated enough not to trigger the pathology), and available for
  future use on a less extreme imbalance ratio — not adopted for this
  artifact.**
- **Isolation Forest's tuning did not have this problem** — a single
  scalar `contamination` sweep evaluated by binary attack-vs-normal F1
  produced a clean, monotonic-ish curve (F1: 0.4073 / 0.4889 / 0.4509 /
  0.4112 / 0.3963 across contamination 0.05/0.10/0.15/0.20/0.25) and a
  sensible selection (0.10). The difference from LightGBM's failure isn't
  incidental: one scalar tuned against one aggregate metric is a
  well-posed optimization; fifteen independent per-class thresholds
  composed via subtraction into a shared argmax is not, regardless of how
  much guarding is added around it.

**Delivered LightGBM artifact (`pirewall/ml/artifacts/lightgbm_model.txt`,
version 0.2.0, `is_placeholder: false`)** uses the plain configuration —
chosen on real measured evidence, not the literal unmodified request,
because CLAUDE.md's honesty rule ("never fabricate metrics") extends to not
shipping a demonstrably worse model to satisfy the letter of an
instruction whose real-data effect wasn't yet known when it was given.
Every technique requested is fully implemented, tested, and available via
CLI flags for a future retrain on a less extreme imbalance ratio or a
larger/more-diverse dataset where the failure modes above may not apply.
**accuracy=0.8899, macro_f1=0.1975** — still low in absolute terms (several
single/low-double-digit-count classes: Heartbleed, Infiltration, Web
Attack-Sql Injection, genuinely cannot be learned reliably from this few
real examples no matter the technique) but the best of everything
measured, and the only one that doesn't compromise majority-class/BENIGN
reliability.

**Delivered Isolation Forest artifact
(`pirewall/ml/artifacts/isolation_forest_model.joblib`, version 0.2.0)**
uses training-split-only undersampling of the normal class (BENIGN capped
at 150,000 for a faster normal-only fit) and `contamination=0.10`, selected
by the validation sweep above (candidates 0.05/0.10/0.15/0.20/0.25,
informed by the real ~19.70% training-split attack rate). **precision=0.5300,
recall=0.4537, fpr=0.0987, fnr=0.5463** — versus the prior session's
precision=0.6014, recall=0.4450, fpr=0.0721, fnr=0.5550: a modest recall
gain (+0.0087) traded for a real precision/FPR cost (-0.0714 / +0.0266).
Whether that trade is worth it is a deployment policy call, not a
modeling one — SHADOW mode (ADDENDUM.md A1) observation before any
enforcement-mode change is exactly the mechanism to evaluate it against
real traffic before deciding.

**Explicit, plain-language limitations — read before deploying:**

- **The delivered LightGBM model still gets zero or near-zero correct
  predictions for the rarest attack classes** (Bot, DoS GoldenEye, DoS
  Slowhttptest, Heartbleed, Infiltration, all three Web Attack variants in
  various configurations) — this session's honest conclusion is that no
  technique tried fixes this without unacceptable collateral damage to
  majority-class detection; it is not fixed in the delivered artifact.
- **Isolation Forest's contamination tuning was a scalar sweep over 5
  candidates on one validation split, not a rigorous cross-validated
  search** — reasonable given the phrase "a full automated grid search is
  not required... use your judgment on scope," but a human should not
  read `contamination=0.10` as precision-tuned to the third decimal.
- **Both models are still trained on one full pass over the standard
  CICIDS2017 release** — the imbalance-remediation techniques applied
  this session don't create new real information about the classes with
  single-digit example counts; more real, diverse data is the only fix
  that would actually work for those.
- **This session consumed a large amount of real compute — 13 full
  training runs (~2–3 minutes each) — chasing what turned out to be
  mostly negative results plus one real bug.** That is a legitimate and
  expected outcome of rigorous ablation, not a sign of wasted effort: the
  alternative was shipping an unvalidated model with unknown (and, as
  measured, sometimes severe) real-world failure modes.

`ruff check .` clean, `pyright` (strict) clean, full suite 506 passed / 20
skipped.

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

### Phase 9 details

Closing phase: fill test-coverage gaps, produce complete documentation, run
a performance smoke pass, and reconcile the whole project against spec §50
+ every ADDENDUM.md item honestly. No new subsystems added (per this
phase's own explicit non-goal) — the two genuine gaps found during
reconciliation (Control Panel "network statistics"/"detections") are
reported under "Open questions for the human" instead of being improvised.

1. **Security test gaps filled** (`tests/security/`, `tests/unit/`): 13 new
   tests — certificate/TLS config-failure cases (3,
   `tests/unit/test_config_loader.py`), firewall backend *removal*-failure
   handling for `disable_rule`/`remove_rule`/the kill-switch (3,
   `tests/security/test_firewall_failure_handling.py` — complements the
   existing apply-failure test from Phase 6), and resource exhaustion for
   `CoreStateStore`'s event/flow/detection/threat/decision buffers plus a
   genuine flood through the real `FirewallManager` past the rate cap (3,
   `tests/security/test_resource_exhaustion.py`). Every other spec §39
   security-test item (malformed packets, injection, overly broad/
   duplicate/conflicting rules, Admin PC lockout, unauthorized API
   requests) was already covered in Phases 2/6/7 — see
   `docs/TESTING.md`'s coverage table for the full mapping, not just this
   phase's additions. **Tested.**
2. **Integration tests** (`tests/integration/test_full_detection_pipeline.py`,
   4 new tests): both spec §39 pipelines end to end, using real
   `PacketMetadata` fed through the real `FlowAggregator` (not hand-built
   `Flow` fixtures) for three scripted scenarios — a benign session, a
   port scan (many destination ports, one destination host), and a
   SYN-flood-like burst (many connection attempts, one destination
   port) — asserting sensible, deterministic end-to-end decisions
   (benign -> `ALLOW`, no rule; scan/flood -> detected via genuinely
   different behavioral signatures, decision generates a validated rule
   that deploys against `FakeFirewallBackend`). **Deliberate scope
   choice, documented in the test file's own docstring**: known/anomaly
   ML evidence is passed as `None` rather than run through freshly
   trained placeholder models — `score_evidence`'s three contributions
   are independent and strictly additive, so an untuned model's
   prediction on hand-crafted scenarios would swing the total score
   unpredictably and make the assertions flaky for no real benefit; ML
   inference correctness is already thoroughly covered by `tests/ml/`.
   **Tested.**
3. **Performance smoke pass** (`scripts/diagnostics/performance_smoke.py`
   + `tests/system/test_performance_smoke.py`): packet capture+parse, flow
   aggregation, feature extraction, LightGBM inference, Isolation Forest
   inference, threat assessment, and rule-deployment latency, all measured
   against `FakePacketCapture`/`FakeFirewallBackend` at a synthetic
   2000-flow rate. Representative numbers from this session's dev machine
   (macOS, x86_64) — **explicitly not representative of real Raspberry Pi
   4 hardware** (spec §40, §46):

   | stage | count | mean (ms) | ops/sec |
   |---|---|---|---|
   | packet capture+parse | 4000 | 0.032 | 30,938 |
   | flow aggregation | 4000 | 0.041 | 24,209 |
   | feature extraction | 2000 | 0.016 | 62,742 |
   | lightgbm inference | 2000 | 0.089 | 11,210 |
   | isolation-forest inference | 2000 | 12.068 | 83 |
   | threat assessment | 2000 | 0.022 | 46,056 |
   | rule deployment | 2000 | 5.064 | 198 |

   Isolation Forest inference is the clear bottleneck (scikit-learn's
   per-call overhead calling `decision_function` one flow at a time, not
   batched) and rule deployment slows as `active_rules()` grows (O(n)
   conflict/priority/duplicate checks against every active rule) — both
   worth profiling for real if Pi-hardware throughput ever becomes a
   concern, per spec §40 "profile before optimizing." **Tested**
   (regression-guarded at a smaller scale by
   `tests/system/test_performance_smoke.py`, which asserts every stage
   still runs and reports positive throughput, not specific numbers).
   ~~**Environment-dependent** for real Pi 4 numbers~~ — **done
   2026-08-30**: this same script was re-run unmodified on the target Pi 4.
   The Pi is 2.3–3.8× slower across every stage; Isolation Forest measured
   33.0 ms/call (30.3 flows/s). See the "Real-hardware performance benchmark
   session" above and `benchmarks/2026-08-30/`.
4. **Documentation**: `docs/FEATURE_SCHEMA.md`, `docs/ML_PIPELINE.md`,
   `docs/FIREWALL.md`, `docs/API.md`, `docs/TESTING.md`,
   `docs/DEVELOPMENT_WORKFLOW.md` all new this phase; `docs/ARCHITECTURE.md`
   extended with the spec §51 pipeline diagram + module-boundary map
   (existing dependency-decision content preserved, not replaced);
   `README.md` rewritten as a real project overview with a documentation
   map and pointers to `docs/DEPLOYMENT.md`. `docs/SECURITY.md`/
   `docs/DEPLOYMENT.md` were already complete from Phase 8. **Implemented.**
5. **Final acceptance reconciliation**: every spec §50 bullet and every
   ADDENDUM.md item table row filled in with an honest label — see
   "Acceptance criteria reconciliation" below and the "Open questions for
   the human" section (real-hardware verification steps for A1/A4/A6,
   explicitly itemized per this phase's own instructions, plus the two
   Control Panel gaps found during reconciliation).

ruff clean, pyright --strict clean (172 files), 390 tests total (14 new
this phase, up from Phase 8's final 376: 3 config-loader certificate
tests + 3 firewall-removal-failure tests + 3 resource-exhaustion tests +
4 full-pipeline integration tests + 1 performance-smoke regression test).

## Addendum items (`docs/ADDENDUM.md`)

Fill in as each is implemented — don't wait for Phase 9 for these, update as
you go since they land across several phases.

| Item | Status | Notes |
|------|--------|-------|
| A1 Shadow / dry-run enforcement mode | Implemented + Tested (Phase 6); real multi-week observation Environment-dependent (Phase 9) | `FirewallManager` branches on `EnforcementMode.SHADOW`: an otherwise-approved candidate becomes `RuleStatus.SHADOWED`, never reaches the backend, and produces a "[shadow mode] would have ..." `SecurityEvent`. Phase 9: the addendum's own recommended 1-2 week real-traffic observation window before moving to ASSISTED/ACTIVE is inherently not something this repository's tests can substitute for — see "Open questions for the human." |
| A2 Static allowlist (outranks adaptive rules) | Implemented + Tested (Phase 6, 7) | Phase 6: validator stage as previously noted. Phase 7: `GET/POST/DELETE /api/v1/allowlist`, admin-only, control-panel section with add/remove — tested end-to-end via `TestClient`. |
| A3 Rate cap on rule creation | Implemented + Tested (Phase 6, 8) | `RuleCreationRateLimiter` (fixed window) backs the `rate_cap` validator stage; rejects with `RuleRejectionReason.RATE_LIMITED` once the window's budget is spent. Detection/`SecurityEvent` generation is untouched by the cap (the cap only ever runs after a `ThreatAssessment`/`FirewallDecision` already exist). Phase 8: `pirewall.core.models.metrics.NetdataMetricsSnapshot` adds `adaptive_rule_creation_rate_per_window`/`adaptive_rule_budget_fraction`, exported by `pirewall.integration.netdata` (payload shaping tested) — no live collector loop populates a snapshot from the real rate limiter yet, see Phase 8's "known gap" note above. |
| A4 Privileged/unprivileged process split | Implemented + Tested (pipeline); real transport and real two-process deployment Environment-dependent (Phase 7, 8) | Typed RPC protocol (`pirewall.ipc`): `CoreRpcDispatcher` (all 16 operations, fully unit-tested), `UnixSocketRpcServer`/`UnixSocketRpcClient` — **upgraded to Tested by the audit pass**: `AF_UNIX` exists on macOS (the earlier Environment-dependent label was written on Windows, where it does not), so `tests/integration/test_rpc_unix_socket.py` now exercises the real transport end to end — bind/connect/accept, request/response round-trip, malformed input both directions, and the socket's actual permission bits. `LoopbackRpcClient` (in-process test double). `pirewall/api/`+`pirewall/web/` proven to never import `pirewall.capture`/`firewall.manager`/`firewall.backend` via an AST-based import-graph test. Phase 8: `deploy/systemd/pirewall-core.service`/`pirewall-api.service` implement the actual two-process deployment (dedicated users, `pirewall-core`'s primary group is the shared `pirewall-ipc` group + `UMask=0117` for the socket, `pirewall-api` only a supplementary member with an explicitly empty `CapabilityBoundingSet=`/`AmbientCapabilities=`) — static structure Tested (`tests/security/test_systemd_hardening.py`), real installation/enforcement Environment-dependent. Both units' `ExecStart=` reference `pirewall.main`/`pirewall.api.__main__`, which don't exist yet (see Phase 8's "known gap" note). |
| A5 IPv4-only v1 scope | Implemented + Tested (Phase 1, 2, 6) | Phases 1-2 as previously noted. Phase 6: the validator's `network` stage adds a belt-and-suspenders runtime check (tested via a `model_copy`-bypassed candidate, since the type system already makes a real IPv6 `CandidateRule` unconstructable). |
| A6 Fail-open default + systemd watchdog | Implemented (Phase 1, 6 groundwork); watchdog directives Implemented + Tested (static), real enforcement Environment-dependent (Phase 8) | `FailureMode` enum, `failure.mode` config (default `fail_open`), `failure.watchdog_sec`/crash-loop fields. Phase 6: `revert_to_base()` explicitly fails open (backend removal errors are swallowed; the manager's own state still marks rules `REMOVED`). Phase 8: `deploy/systemd/pirewall-core.service` sets `Type=notify`+`WatchdogSec=30s`+`Restart=on-failure`+`StartLimitBurst=3`/`StartLimitIntervalSec=300`, matching `config.failure`'s defaults — asserted present by `tests/security/test_systemd_hardening.py`. Entry-point session: `pirewall.runtime.watchdog.SystemdNotifier` now sends `READY=1`/`WATCHDOG=1`/`STOPPING=1` for real, driven from `CoreDaemon.run`'s main thread at half `failure.watchdog_sec` — Tested against a real `AF_UNIX` datagram socket (`tests/unit/test_watchdog.py`), and a no-op outside systemd so a shell run behaves identically. What stays Environment-dependent is systemd *accepting* those notifications and acting on a missed one; the protocol half is no longer unimplemented. Phase 9: added `tests/security/test_firewall_failure_handling.py`, proving the fail-open *state-transition* guarantee (backend removal errors swallowed, manager state still updates) end-to-end through the real `FirewallManager`, not just via `contextlib.suppress` code inspection — but the real-crash/real-watchdog half remains Environment-dependent, itemized in "Open questions for the human." |
| A7 Assisted mode / BLOCK approval queue | Implemented + Tested (Phase 6, 7) | Phase 6: manager logic as previously noted. Phase 7: `POST /api/v1/rules/{id}/approve`/`/reject`, control-panel Approve/Reject buttons on `PENDING_APPROVAL` rules — tested end-to-end via `TestClient`. |
| A8 Emergency kill-switch | Implemented + Tested (Phase 6, 7) | Phase 6: `revert_to_base()` as previously noted. Phase 7: `POST /api/v1/firewall/kill-switch` (same auth/Admin-PC path as every other write endpoint) + a control-panel button with a JS confirmation step — tested end-to-end via `TestClient`. |

## Acceptance criteria reconciliation (spec §50)

Filled in Phase 9. Labels per `CLAUDE.md`: Implemented / Tested / Mocked /
Environment-dependent / Not yet validated. An item can carry more than one
label (e.g. "Tested against Fakes; real hardware Environment-dependent").
Two real gaps were found during this reconciliation (Control Panel
"network statistics" and "detections") — see "Open questions for the
human" below; they are marked unchecked and explained here rather than
silently filled in, per this phase's own non-goal ("do not add new
subsystems... report, don't improvise").

### Network
- [x] packet capture — Tested (`FakePacketCapture`, Phase 2); real `AFPacketCapture` Environment-dependent.
- [x] packet parsing — Tested exhaustively, including a dedicated malformed/truncated security-test tier (Phase 2).
- [x] flow aggregation — Tested (Phase 3; re-exercised end-to-end via real `PacketMetadata` in Phase 9's full-pipeline integration tests).
- [x] bidirectional flows — Tested (flow-key bidirectional normalization, forward/backward attribution, Phase 3).
- [x] flow timeouts — Tested (active/inactive timeout + TCP FIN/RST completion, Phase 3).
- [x] bounded state — Tested (`FlowTable` LRU eviction, flood-tested to 5000 flows against a 100-flow cap, Phase 3).
- [x] canonical Flow — Implemented + Tested (`pirewall.core.models.Flow`, IPv4-only per ADDENDUM.md A5, Phase 1/3).

### Features
- [x] canonical schema — Implemented + Tested (29 features, one module, `docs/FEATURE_SCHEMA.md`, Phase 3).
- [x] deterministic extraction — Tested (identical `Flow` -> identical `FeatureVector`, Phase 3).
- [x] training/runtime compatibility — Tested (shared extractor across Phase 4 dataset adapters and Phase 5 runtime inference; schema-version + feature-ordering pinning enforced at model load time, Phase 5).

### ML
- [x] CICIDS2017 adapter — Tested against synthetic fixtures (Phase 4) and against all 8 real "MachineLearningCVE" files, 2,830,628 flows loaded (CICIDS2017 real-data training session) — that run also fixed a real column-layout defect the synthetic fixtures hadn't caught (no Source/Destination IP/Source Port/Protocol columns in the actual published release). Real-dataset detection *accuracy* is Environment-dependent per spec §34's attack-lab caveat below, independent of the adapter itself now being real-data-verified.
- [x] UNSW-NB15 adapter — Tested against synthetic fixtures (Phase 4) and a real 257,673-row subset (real-data training session); real-dataset behavior beyond that subset remains Environment-dependent.
- [x] preprocessing — Tested (`pirewall.ml.preprocessing.common`, pooled-variance stat combination, missing/invalid-value handling, Phase 4).
- [x] LightGBM — Tested against synthetic fixtures (training + inference, Phase 4/5) and trained on real CICIDS2017/UNSW-NB15 data (see "CICIDS2017 real-data training session" / "Real-data training session" / "CICIDS2017 imbalance-remediation session" above for numbers and honest limitations, including a controlled ablation showing the requested imbalance-remediation techniques underperform the plain baseline on this dataset and are not used in the delivered artifact); real-world field detection accuracy on live Pi traffic remains Environment-dependent.
- [x] Isolation Forest — same as above; the CICIDS2017 imbalance-remediation session's `contamination` sweep (validation-split only) modestly improved recall (0.4450 -> 0.4537) at a real precision/FPR cost versus the prior normal-only-fit run.
- [x] training pipeline — Tested (both trainer modules + both CLIs, Phase 4; extended with a 3-way stratified split, training-split-only resampling, class weighting, and threshold tuning in the imbalance-remediation session, including a real split-ordering bug found and fixed there — see that session's notes).
- [x] model artifacts — Implemented + Tested (save/load round-trip, `tests/ml/test_artifacts.py`) and real, non-placeholder artifacts present in this workspace as of the CICIDS2017 imbalance-remediation session (`pirewall/ml/artifacts/`, gitignored, machine-local — a fresh clone starts without them; the performance smoke pass and `tests/ml/` each train a fresh tiny placeholder model on demand rather than depending on one being present, so a missing artifact doesn't break those).
- [x] metadata — Tested (`ModelMetadata` save/load round-trip, Phase 4).
- [x] compatibility validation — Tested (schema-mismatch refusal at both load-time and per-inference-call, Phase 5).

### Detection
- [x] known-attack evidence — Tested (`pirewall.detection.known_attack.classify`, Phase 5).
- [x] anomaly evidence — Tested (`pirewall.detection.anomaly.detect`, Phase 5).
- [x] behavioral analysis — Tested (Phase 5 unit tests + Phase 9's port-scan/SYN-flood scripted-traffic integration tests).
- [x] threat scoring — Tested (`pirewall.engine.scoring`, hand-computed cases, Phase 5; end-to-end in Phase 9).
- [x] explainable assessments — Tested (`ThreatAssessment.explanation`/`contributing_evidence`, Phase 5).

### Firewall
- [x] explicit decisions — Tested (`pirewall.engine.decision`, Phase 6; end-to-end in Phase 9).
- [x] structured rules — Implemented + Tested (`CandidateRule`/`FirewallRule` Pydantic models, Phase 1/6).
- [x] candidate generation — Tested (narrowest-possible `/32` rules, `ALLOW` produces none, Phase 6).
- [x] validation — Tested (the full 10-stage chain, each stage independently tested plus end-to-end, Phase 6).
- [x] conflict detection — Tested (Phase 6 unit + integration).
- [x] duplicate detection — Tested (Phase 6 unit + integration).
- [x] safety checks — Tested (Admin PC, whole-LAN, whole-internet, broader-than-evidence — Phase 6 + `tests/security/test_safety_validation.py`).
- [x] expiration — Tested (missing-expiration rejection stage; `RuleStatus.EXPIRED` in the lifecycle, Phase 6).
- [x] enforcement — Tested against `FakeFirewallBackend` (SHADOW/ASSISTED/ACTIVE branching, Phase 6); real `NftablesBackend` against a real `nft` binary Environment-dependent.
- [x] audit trail — Tested (`RuleTransition` list + `SecurityEvent` emission on every transition, Phase 6).

### Gateway
- [x] WAN/LAN configuration — Implemented (`deploy/network/` templates, config-driven, Phase 8); real application Environment-dependent.
- [x] forwarding — Implemented (`60-pirewall-forwarding.conf.template`, IPv4 only per ADDENDUM.md A5, Phase 8); real application Environment-dependent.
- [x] routing — Implemented: a home-gateway topology needs kernel IP forwarding + a static LAN-facing address, not a dynamic routing protocol — covered by the same sysctl/interface templates above (Phase 8); real application Environment-dependent.
- [x] firewall forwarding — Implemented + Tested (statically): `deploy/firewall/base.nft.template`'s deny-by-default `forward` chain (Phase 8, `tests/security/test_firewall_base_template.py`); real enforcement Environment-dependent.
- [x] NAT where required — Implemented (`deploy/network/nat-masquerade.nft.template`, Phase 8); real application Environment-dependent.
- [x] protected network — Implemented + Tested (`config.network.protected_network`, used throughout safety validation since Phase 6).

### API
- [x] FastAPI — Implemented + Tested (Phase 7, `docs/API.md`).
- [x] authentication — Tested (Phase 7).
- [x] TLS — Implemented (config fields, `min_tls_version`, Phase 1/7); real TLS termination Environment-dependent and additionally blocked on the not-yet-built `pirewall.api.__main__` entry point (see "Open questions" below).
- [x] certificate support — Implemented + Tested at the config layer (required non-empty `tls_cert_path`/`tls_key_path`, Phase 9 added explicit missing/empty-path tests); real certificate loading Environment-dependent, same entry-point gap as TLS above.
- [x] Admin PC restriction — Tested at both the application layer (Phase 7; audit pass confirmed it fails closed on a missing/unknown client host) and, statically, the network layer (`deploy/firewall/base.nft.template`'s `input` chain, Phase 8).
- [x] safe administrative operations — Tested (disable/remove/approve/reject/allowlist/kill-switch, every one routed through the single authorized `FirewallManager` path, Phase 7).

### Control Panel
- [x] system health — Tested (`StatusResult` rendering, Phase 7).
- [ ] network statistics — **Gap, not implemented.** `CaptureStatistics` (packet rate/drops, Phase 2) is never wired into `CoreStateStore`, the RPC protocol, the API, or the control panel — nothing exposes it past `PacketCapture.statistics()` itself. See "Open questions for the human" below.
- [x] threats — Tested (Phase 7).
- [ ] detections — **Gap, not implemented in the control panel.** `GET /api/v1/detections` exists and is Tested (Phase 7 API), but `pirewall.web.routes.dashboard`/`render_dashboard` never fetch or render it — the HTML control panel has no detections section. See "Open questions for the human" below.
- [x] firewall rules — Tested, including A7's Approve/Reject and A8's kill-switch button (Phase 7).
- [x] events — Tested (Phase 7).
- [x] ML status — Tested (loaded model metadata, Phase 7).

### Integration
- [x] Wazuh — Implemented + Tested (payload shaping, `pirewall.integration.wazuh`, Phase 8); real delivery to a real Wazuh agent Environment-dependent.
- [x] Netdata/metrics — Implemented + Tested (payload shaping, `pirewall.integration.netdata`, Phase 8, including ADDENDUM.md A3's rule-rate metric); real delivery to a real Netdata instance Environment-dependent. The live collector now exists: `pirewall.runtime.metrics.MetricsCollector` builds a `NetdataMetricsSnapshot` from capture statistics, the flow table, the A3 rate limiter and monotonic `RuntimeCounters`, exported once per watchdog tick by `CoreDaemon._tick` when `integration.netdata_enabled` — Tested (`tests/unit/test_runtime_metrics.py`, including the rate arithmetic). Host CPU/memory are read from `/proc` (no `psutil` dependency) and read `0.0` off Linux.
- [x] Admin PC communication — Implemented (Wazuh/Netdata forwarders above). The RPC socket carrying it is now **Tested** against a real `AF_UNIX` socket including its permission bits (audit pass); real Wazuh/Netdata delivery remains Environment-dependent.

### Raspberry Pi Security
- [x] least privilege — Implemented (`deploy/systemd/*.service` capability scoping, ADDENDUM.md A4, Phase 8); real enforcement Environment-dependent.
- [x] service isolation — Implemented + Tested (statically): `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, restricted `ReadWritePaths`, etc. (Phase 8, `tests/security/test_systemd_hardening.py`); real enforcement Environment-dependent.
- [x] secure systemd configuration — same as above, plus the A6 watchdog/crash-loop directives, Tested statically.
- [x] SSH hardening — Implemented as documentation/guidance (`docs/SECURITY.md`, `docs/DEPLOYMENT.md`) — SSH itself is host OS configuration outside pirewall's own codebase, so there is nothing to unit-test; a human must apply it. Environment-dependent.
- [x] restricted network exposure — Implemented + Tested (statically): Admin-PC-only `input` chain (Phase 8); real enforcement Environment-dependent.
- [x] secret protection — Implemented (scrypt password hashing since Phase 7, `.gitignore` rules for certs/local config, documented filesystem-permission guidance in `docs/SECURITY.md`).
- [x] filesystem permissions — Implemented (systemd `ReadOnlyPaths`/`ReadWritePaths`, socket permission scheme via shared group + `UMask`, Phase 8); real enforcement Environment-dependent.
- [x] resource limits — Implemented + Tested (statically): `MemoryMax`/`MemoryHigh`/`TasksMax`/`CPUQuota` in both service files (Phase 8); real enforcement Environment-dependent. Software-level resource-exhaustion protections (flow table, behavior state, rate cap, bounded event queue) are Tested independent of systemd, since Phases 3/5/6/9.
- [x] secure firewall management — Tested (the one-authorized-caller rule, `tests/security/test_backend_isolation.py`; no shell-command injection, `tests/security/test_injection.py`).
- [x] secure update procedure — Implemented as documentation (`docs/SECURITY.md` §"Updates", `docs/DEPLOYMENT.md` §9) — a procedure, not code; a human follows it. Environment-dependent by nature.

### Testing
- [x] unit tests — Tested (`tests/unit/`, every phase).
- [x] integration tests — Tested (`tests/integration/`, including Phase 9's new full-pipeline scripted-traffic tests).
- [x] ML tests — Tested (`tests/ml/`).
- [x] security tests — Tested (`tests/security/`, expanded in Phase 9 — see `docs/TESTING.md`'s coverage table).
- [x] failure tests — Tested (deploy failure since Phase 6; remove/kill-switch failure added Phase 9, `tests/security/test_firewall_failure_handling.py`).
- [x] mocked hardware tests — Tested (the Protocol+Fake pattern throughout — `FakePacketCapture`, `FakeFirewallBackend`, `LoopbackRpcClient`).
- [x] strict type checking — Tested (`pyright --strict`, zero errors, 166 files as of Phase 8; unchanged through Phase 9's additions — see the ruff/pyright run at the end of this phase).

### Deployment
- [x] Raspberry Pi installation — Implemented as documentation (`docs/DEPLOYMENT.md` §1-3); Environment-dependent.
- [x] network configuration — Implemented (`deploy/network/`, config-parameterized templates + render script, Phase 8); Environment-dependent.
- [x] IP forwarding — Implemented (`60-pirewall-forwarding.conf.template`, Phase 8); Environment-dependent.
- [x] firewall configuration — Implemented + Tested statically (`deploy/firewall/base.nft.template`, Phase 8); Environment-dependent.
- [x] permissions/capabilities — Implemented + Tested statically (`deploy/systemd/*.service`, Phase 8); Environment-dependent.
- [x] systemd — Implemented + Tested statically (two units, ADDENDUM.md A4/A6, Phase 8). No longer blocked: both `ExecStart=` targets exist and have been run (entry-point session), and the units' "do not start this unit" notes are removed. Actually *starting* them under systemd on the Pi remains Environment-dependent — see `docs/DEPLOYMENT_COMPLETE.md` §4.
- [x] certificates — Implemented as documentation + config fields (`docs/DEPLOYMENT.md` §6); Environment-dependent.
- [x] Admin PC configuration — Implemented as documentation (`docs/DEPLOYMENT.md` §8, Wazuh/Netdata setup); Environment-dependent.

### Documentation
- [x] README — Implemented (Phase 9: rewritten as a full project overview).
- [x] architecture — Implemented (Phase 9: pipeline diagram + module-boundary map added to the existing `docs/ARCHITECTURE.md`).
- [x] feature schema — Implemented (`docs/FEATURE_SCHEMA.md`, Phase 9).
- [x] ML pipeline — Implemented (`docs/ML_PIPELINE.md`, Phase 9).
- [x] firewall — Implemented (`docs/FIREWALL.md`, Phase 9).
- [x] security — Implemented (`docs/SECURITY.md`, Phase 8).
- [x] deployment — Implemented (`docs/DEPLOYMENT.md`, Phase 8).
- [x] testing — Implemented (`docs/TESTING.md`, Phase 9).
- [x] Raspberry Pi hardening — Implemented (folded into `docs/SECURITY.md` rather than a separate file — spec §35 lists "Raspberry Pi hardening" as a documentation topic, not necessarily a separate filename, and `docs/SECURITY.md` §1 is entirely that topic).

## Known deviations from spec

### Audit pass (post-Phase 9) — behavior changes

An audit-and-fix pass over the completed repository changed behavior
documented by earlier phases. Each item below supersedes what the
referenced phase originally recorded.

- **Phase 6 safety validation now has four independent address checks, not
  two.** Previously: Admin PC, whole protected LAN, whole internet
  (`0.0.0.0/0`), minimum prefix length. Two candidate rules were found that
  passed the whole chain and should not have:
  - a `/32` targeting `network.upstream_gateway` — every outbound packet
    transits it, so blocking it is "blocking the entire internet" (spec
    §24) achieved without ever matching `0.0.0.0/0`;
  - a `/32` targeting the Pi's own LAN address — spec §24's "blocking
    pirewall itself" and "blocking management access", which the
    Admin-PC-IP check does not cover because the Admin PC is the client
    end of a management connection, not the server end.
  Both now have their own check. This **rejects candidate rules that
  earlier phases would have deployed**; the affected targets are ones no
  correct deployment should ever want blocked.
- **`network.pirewall_lan_ip` is a new required config field.** The Pi's
  own LAN address was not derivable from existing config (it differs from
  `upstream_gateway`, which is the home router on the WAN side, and from
  `admin_pc_ip`). Required with no default, following the existing
  convention for security-relevant fields: a config missing it fails
  loudly rather than silently losing a safety check. **Any config written
  before this pass needs the field added.**
- **`pirewall/ipc/__init__.py` re-exports nothing.** It previously
  re-exported both halves of the RPC protocol, which pulled
  `pirewall.firewall.manager` into the pirewall-api process transitively
  (ADDENDUM.md A4 violation that the AST-based isolation test could not
  see). Import from the specific submodule instead.
- **The RPC socket's mode is set by the code, not the umask.**
  `UnixSocketRpcServer.start()` now guarantees `0o660` and a traversable
  `0o750` directory regardless of the caller's umask. Previously both were
  umask-derived, which produced a world-connectable `0o755` socket under a
  default `0o022` umask, and a non-traversable `0o640` directory under the
  `0o117` umask `pirewall-core.service` itself sets.
- **Control panel ids no longer reach inline JS handlers.** They travel in
  `data-` attributes read by a delegated listener. `html.escape` is correct
  for attribute values but not for JS string literals — the HTML parser
  decodes `&#x27;` back to `'` before the JS engine parses an `onclick`,
  so an id containing a quote escaped the string literal. Not reachable
  with today's uuid4 ids; fixed as defence in depth.
- **`RpcError` maps to HTTP 503 with a "core unreachable" page**, instead
  of escaping as an unhandled 500. ADDENDUM.md A6 already claimed the
  control panel could report a crash-looping core; it could not.

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
- **Phase 4 / CICIDS2017 real-data session CICIDS2017 adapter**: targets the
  specific "MachineLearningCVE" CICFlowMeter CSV column layout. **Updated in
  the CICIDS2017 real-data training session**: the real, published release
  (verified against all 8 standard files) has **no Source/Destination
  IP/Source Port/Protocol columns** — Phase 4's original assumption that
  they existed was wrong, only ever caught by synthetic fixtures that baked
  the same wrong assumption in. `source_ip`/`destination_ip` are now a fixed
  documented placeholder (`10.255.255.1`/`.2`, matching `unsw_adapter`'s own
  convention), `source_port` is always `None`, and `protocol` is inferred
  from TCP flag counts + a well-known-UDP-port fallback (see the adapter's
  module docstring for the exact rule — a disclosed heuristic, not
  fabricated data). Still combines CICIDS2017's separate forward/backward
  packet-size mean/std into one overall value via a standard
  pooled-variance formula
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

- ~~**Phase 6 safety validation — "pirewall itself" / "management
  access"**~~ — **RESOLVED by the audit pass.** The provisional choice
  (folding both into the Admin-PC-IP and whole-LAN checks) was
  independently re-evaluated and found **insufficient**: the Admin PC is
  the *client* end of a management connection, so a candidate rule
  targeting the Pi's own LAN address — the *server* end, and every LAN
  client's default gateway — left `admin_pc_ip` untouched and passed the
  full chain. Verified by constructing the candidate and observing it
  APPROVED. Fixed by adding a required `network.pirewall_lan_ip` config
  field and an independent safety check for it. The same probe found a
  second gap (the upstream gateway was blockable, severing all internet),
  also fixed. See "Known deviations from spec" for both, and
  `tests/unit/test_validator.py` /
  `tests/security/test_safety_validation.py` for the regression tests.

- ~~**Phase 8 — `pirewall/main.py`/`pirewall/api/__main__.py` don't exist
  yet**~~ — **RESOLVED by the entry-point session.** Both were built as
  their own scoped follow-up, as this note recommended. `pirewall/main.py`
  runs `pirewall.runtime.core.CoreDaemon` (capture -> flow -> features ->
  detection -> engine -> firewall manager across four worker threads, plus
  `sd_notify` heartbeats and the RPC socket); `pirewall/api/__main__.py`
  serves `create_app` over uvicorn + TLS with a startup refusal on
  placeholder credentials or missing TLS material. Both `.service` files
  and `docs/DEPLOYMENT.md`'s opening note have had their "do not start this
  unit" warnings removed. Full detail, including three defects the wiring
  exposed and exactly what remains unverified on real hardware, is in
  `docs/DEPLOYMENT_COMPLETE.md`.


- **Phase 9 — Control Panel gap: "network statistics" — plumbing now
  done, rendering still open.** The entry-point session added the whole
  data path this note asked for: `CoreStateStore.capture_stats` +
  `record_capture_stats()`, a `GET_CAPTURE_STATS` RPC operation, a typed
  `BaseRpcClient.get_capture_stats()`, and `GET /api/v1/capture-stats` —
  populated once per watchdog tick by `CoreDaemon._tick`, and covered by
  `tests/integration/test_core_daemon.py`. What remains is only
  `_render_network_section` in `pirewall.web.render` plus one extra call in
  `pirewall.web.routes.dashboard`; the data is already reachable over the
  JSON API. Original note follows.

  **Original:** "network statistics" not implemented.
  `pirewall.core.models.capture_stats.CaptureStatistics` (packet rate,
  drops, malformed count — Phase 2) is never wired into
  `pirewall.ipc.state.CoreStateStore`, the RPC protocol
  (`pirewall.ipc.protocol.RpcOperation`), any API endpoint, or the control
  panel (`pirewall.web.render.render_dashboard`). Nothing past
  `PacketCapture.statistics()` itself exposes this data. This is a genuine
  gap against spec §30/§50's "network statistics" Control Panel
  requirement, found during this phase's reconciliation — not fixed here
  per Phase 9's own non-goal ("do not add new subsystems... report, don't
  improvise"). It's also entangled with the `pirewall/main.py` gap above:
  there is no running capture loop yet to periodically produce a
  `CaptureStatistics` snapshot from in the first place. **Recommended
  follow-up scope** (small, isolated): add a `capture_stats:
  CaptureStatistics | None` field to `CoreStateStore` +
  `record_capture_stats()`, a `GET_CAPTURE_STATS` RPC operation, a
  `GET /api/v1/capture-stats` endpoint (or fold into `/status`), and a
  `_render_network_section` in `pirewall.web.render` — each piece mirrors
  an existing equivalent (e.g. `list_events`/`/events`) closely enough to
  copy the pattern directly once `pirewall/main.py` exists to call
  `record_capture_stats()` periodically.

- **Phase 9 — Control Panel gap: "detections" section not rendered.**
  `GET /api/v1/detections` exists and is Tested, but
  `pirewall.web.routes.dashboard` never calls `rpc_client.list_detections()`
  and `render_dashboard` has no detections parameter/section — the raw
  data is reachable via the JSON API but not visible in the HTML control
  panel. Smaller and more contained than the network-statistics gap above
  (no missing plumbing, just a missing render call) — not fixed here for
  the same Phase 9 non-goal reason. **Recommended follow-up**: add a
  `detections: list[DetectionRecord]` parameter to `render_dashboard`, a
  `_render_detections_section` mirroring `_render_threats_section`'s
  structure, and one extra `rpc_client.list_detections()` call in
  `pirewall.web.routes.dashboard`.

- **Pi 4 anomaly-scoring throughput — needs a design decision.** Anomaly
  detection scores **one flow per `IsolationForest.decision_function`
  call**. Measured on the dev machine, that is ~15.6 ms/call at
  `n_estimators=100`, versus ~0.088 ms/flow when the same forest scores a
  batch of 200 — a ~178× gap that is almost entirely scikit-learn's fixed
  per-call overhead, not tree traversal. Single-flow scoring therefore
  tops out near 64 flows/s on a fast x86 laptop, so plausibly **10–20
  flows/s on a Pi 4's Cortex-A72**. A busy household can exceed that, at
  which point anomaly scoring becomes the pipeline bottleneck and flows
  queue or get dropped. **Not fixed here** because the real remedy —
  scoring flows in batches — changes the shape of
  `pirewall.detection.anomaly.detect` and whatever main loop eventually
  drives it, which is design work rather than an audit fix. Options, in
  increasing order of effort:
  1. Retrain with fewer trees (`n_estimators=25` measured ~4.3 ms/call,
     3.6× better) and accept some detection-quality loss. Config-only.
  2. Batch flows through inference — two orders of magnitude, and the
     right long-term answer. Needs a buffering/flush policy, which
     interacts with whatever `pirewall/main.py` ends up looking like.
  3. Accept the ceiling for SHADOW-mode operation (A1), where falling
     behind delays observation but enforces nothing, and revisit before
     enabling ACTIVE.
  Whichever you choose, `pirewall.inference_latency_ms` is already
  exported to Netdata (spec §33) — though note that on a deployment where
  Netdata is unreachable, as it was during the benchmark, nothing observable
  carries it.

  **UPDATE 2026-08-30 — measured on the real Pi 4**, so the estimates above
  are superseded (`benchmarks/2026-08-30/REPORT.md`): single-flow Isolation
  Forest is **30.7 ms** with the real v0.2.0 artifact and **33.0 ms** with a
  placeholder, i.e. **~30 flows/s**, not the 10–20 estimated here. Option 1
  (fewer trees) is less attractive than it looked: swapping models barely
  moved the number, confirming the cost is scikit-learn's per-call overhead,
  not tree traversal. Option 2 (batching) is the only change that moves the
  ceiling. The consequence of *not* choosing is now measured rather than
  hypothetical: when flows completed faster than ~30/s, the detection queue
  reached 3,084 flows, `pirewall-core` saturated a core, and the kernel
  **dropped 38.5 % of packets in a 15 s window**. Option 3 (accept it in
  SHADOW/ASSISTED) remains viable — falling behind delays observation and
  loses packets, but enforces nothing incorrectly.

- **Phase 9 — real-hardware verification still required (ADDENDUM.md A1,
  A4, A6), explicitly listed per this phase's own instructions:**
  - **A6 fail-open crash behavior**: `FirewallManager.revert_to_base`'s
    fail-open behavior (swallowing a `FirewallError` from the backend) is
    Tested against `FakeFirewallBackend` configured to fail
    (`tests/security/test_firewall_failure_handling.py`, Phase 9). The
    *systemd*-level half — `pirewall-core.service` actually crashing for
    real, the `Type=notify`/`WatchdogSec=30s` directives actually
    triggering a restart, and `StartLimitBurst=3`/`StartLimitIntervalSec=300`
    actually tripping a crash-loop stop — has never run on a real host.
    **A human must**: install the real unit (once `pirewall/main.py`
    exists and sends `sd_notify` heartbeats), deliberately crash the
    process (e.g. `kill -SEGV`), and confirm systemd restarts it, then
    repeat past the burst limit and confirm it lands in `failed` state
    with `pirewall-api` still reachable and reporting "core is down."
  - **A1 shadow-mode observation period**: the addendum's own recommended
    path is "run in SHADOW for 1-2 weeks against real traffic, review the
    shadow log, move to ASSISTED, then ACTIVE once you trust it." Nothing
    in this repository can substitute for that real-traffic observation
    window — it is inherently a real-deployment, real-time activity, not
    a test. **A human must**: deploy with `enforcement_mode = "shadow"`
    (the shipped default — do not change it), let it run against real
    household traffic for at least 1-2 weeks, and review
    `GET /api/v1/rules` (status `SHADOWED`) plus `GET /api/v1/events`
    before ever setting `enforcement_mode` to `"assisted"` or `"active"`.
  - **A4 socket permissions on a real filesystem** — *partially resolved
    by the audit pass.* The **mode** is no longer environment-dependent:
    `UnixSocketRpcServer.start()` now sets it to `0o660` itself rather
    than inheriting it from the process umask (the audit found a default
    `0o022` umask produced a **world-connectable `0o755`** socket, exposing
    every privileged RPC operation to any local user), and
    `tests/integration/test_rpc_unix_socket.py` asserts it against a real
    socket. What is still unverifiable here is **ownership**: which user
    and group the socket belongs to comes from the deployment, not the
    code. **A human must**: after installing both units on real hardware
    (post `pirewall/main.py`), run `ls -l /run/pirewall/core.sock` and
    confirm it reads `srw-rw---- pirewall-core pirewall-ipc`, then confirm
    a process running as neither `pirewall-core` nor a member of
    `pirewall-ipc` gets `Permission denied` connecting to it.

## Decision entry — rare-class exclusion (section 3) needs a human call

**Status: implemented, tested, and deliberately NOT enabled by default.
Flagged for review rather than silently decided.**

The exclusion policy in `pirewall.ml.labels`
(`is_excluded_from_supervised_training`, threshold
`MIN_SUPERVISED_TRAINING_EXAMPLES = 100`) was requested on the reasoning
that Heartbleed (11 examples), Web Attack – Sql Injection (21) and
Infiltration (36) are "near-unlearnable" — evidenced by their 0% recall in
the v0.2.0 artifact.

**That evidence turned out to be an artifact of a training bug, not a
property of the data.** The 0% recall came from divergent boosting
(missing `lambda_l2`, see `docs/ML_DATA_AUDIT.md` §F). With the bug fixed,
the same plain configuration catches them:

| class | total examples | test n | caught | recall |
|---|---:|---:|---:|---:|
| Heartbleed | 11 | 2 | 2 | 100.00% |
| Infiltration | 36 | 5 | 5 | 100.00% |
| Web Attack – Sql Injection | 21 | 3 | 2 | 66.67% |

And measured on the full dataset, excluding them **costs** macro-F1:

| configuration | macro-F1 | leak-free macro-F1 |
|---|---:|---:|
| plain, all 15 classes | **0.8724** | **0.8855** |
| plain, 12 classes (exclusion applied) | 0.8546 | 0.8542 |

**Why this is still a genuine judgement call and not simply "don't
exclude":**

- 2, 5 and 3 test rows respectively. 100% recall on two rows is not
  evidence of generalisation, and the macro-F1 gap is largely *driven* by
  those three high-variance terms — it is not a like-for-like comparison.
- The original argument for exclusion was about **statistical support**
  (11 total examples cannot support a reliable classifier), and that
  argument is untouched by the new numbers. What has collapsed is only the
  supporting claim that the model gets them wrong anyway.
- Against exclusion: Heartbleed and Infiltration are high-severity
  attacks. Excluding them means the supervised classifier can never flag
  them, deferring entirely to Isolation Forest and behaviour analysis.

**Recommendation: leave exclusion available but off**, which is the
current state — the v0.3.0 artifact is trained on all 15 classes. A human
should decide whether the statistical-support argument outweighs losing
supervised coverage of two high-severity classes. Enabling it is a
one-line change at the trainer's call site; the function, its threshold
and its boundary tests already exist.

**Also revised by the same bug:** the "Controlled ablation" table earlier
in this file concluded that resampling, class weighting and threshold
tuning all underperform the plain baseline. That conclusion still holds on
re-measurement with the fix (plain 0.8724 > resampling 0.8291 > weighting
0.8075), but the original comparisons were between differently-diverged
models and were not valid evidence at the time they were made.


## Session outcome — ML quality pass (2026-08-30)

**Headline: the v0.2.0 macro-F1 of 0.1975 was a training bug, not a data or
imbalance limit.** LightGBM's `lambda_l2` defaults to 0.0; under the
multiclass softmax the hessian `p*(1-p)` vanishes as the model gains
confidence, leaving leaf values unbounded, so boosting diverged. Measured:
macro-F1 0.8053 at round 10 falling to 0.2519 at round 100, with max
|raw score| reaching 6.4e6. Setting `lambda_l2 = 1.0` bounds raw scores at
~28 and macro-F1 then *rises* monotonically with boosting. Full mechanism,
before/after, and the three wrong hypotheses are in
`docs/ML_DATA_AUDIT.md` §F.

**Fixed (Tested)** — `pirewall.ml.training.lightgbm_trainer` now sets
`lambda_l2` (default 1.0, exposed as a parameter, pinned by regression
tests).

**Fixed (Tested)** — `pirewall.detection.known_attack.classify` decoded a
multiclass booster's `(1, num_class)` output along the batch axis, raising
`TypeError` on every flow. The known-attack evidence path was entirely
non-functional against the shipped 15-class artifact. Every existing
fixture was 2-class, so the branch had no coverage; a 3-class regression
test now covers it.

**Measured, not shipped** — with the fix, the same plain configuration
reaches accuracy 0.9971 / macro-F1 0.8724 (binary precision 0.9927, recall
0.9932, FPR 0.0018). Architecture chosen by a full-scale five-way ablation
on one fixed split: plain 0.8724 > rare-class exclusion 0.8546 >
under/oversampling 0.8291 > two-stage 0.8217 > class weighting 0.8075.
Flat multiclass, no imbalance intervention, wins.

**DONE — artifact regenerated (Tested).** `pirewall/ml/artifacts/` now
holds **v0.3.0** (`lightgbm_model.txt`, 4,400,528 bytes, 2026-08-30
02:08:18, `is_placeholder: false`), produced by the real training CLI:
**accuracy 0.9970560180878248, macro-F1 0.8724113675173262** — matching the
ablation's projection exactly.

Getting there required fixing a second, separate defect. The first retrain
attempt drove 4.2 GB of swap and had to be abandoned. The cause was **not**
`build_feature_matrix` as first assumed — measured per row on the real
corpus, the Pydantic `LabeledFlow` objects cost **3,857 B/row (10.17 GB)**
against the list-of-lists' 764 B/row (2.01 GB), peaking near **12.18 GB**.
A numpy-only rewrite would have saved 1.4 GB of 12.18 and crashed again.
Fixed by streaming (`iter_cicids2017` -> `build_feature_matrix_streaming`
-> `train_lightgbm_from_arrays`): **peak RSS 1.23 GB**. The split logic is
now shared via `split_indices_train_val_test` and verified bit-identical —
it still reproduces v0.2.0's recorded metrics to full precision.

**Runtime (Tested):** adopting v0.3.0 needed no code change. The
schema-compatibility gate accepts it, `pirewall.detection.known_attack`
classifies against it unmodified, and per-flow latency improved to
0.181 ms mean / 0.242 ms p95 (from 0.272 ms).

**Still not done:** section 6 threat-scoring recalibration
(`pirewall.engine.scoring` weights remain the untuned 50/25/25), and a
UNSW-NB15 audit (that dataset is not on this machine).

**Correction to an earlier claim in this file:** the rare-class exclusion
function was described as wired into training and evaluation. It is not —
`grep` finds no production caller. It is implemented and tested in
`pirewall.ml.labels`, and deliberately unused pending the decision entry
above, but the earlier wording claimed a wiring that does not exist.

**Reproducibility gap found:** the split is a deterministic function of the
order the 8 CSVs are concatenated, and nothing recorded that order —
reproducing the v0.2.0 metrics took a five-way search over candidate
orderings. `ModelMetadata` should carry a dataset fingerprint (row count
plus ordered source-file list, or a hash of the label sequence).

**Prior conclusions revised:** the earlier "controlled ablation" concluding
that resampling, class weighting and threshold tuning all underperform the
plain baseline reached the right ranking, but every run in it was a
diverging model, so it was not valid evidence at the time. Re-measured with
the fix, the ranking holds.


## ML-improvement pass — final state (2026-08-30)

**Shipped artifact: LightGBM v0.4.0**, 12 trained classes,
accuracy 0.997146, macro-F1 0.854589, binary precision 0.993021 /
recall 0.993329 / FPR 0.001713. Full per-class table and every caveat in
`docs/ML_PIPELINE.md`.

### What actually caused the 0.1975 — and the wrong turns on the way

Useful history for anyone retraining on similar hardware:

1. **The 0.1975 macro-F1 was a training bug, not imbalance and not a data
   limit.** LightGBM defaults `lambda_l2` to 0.0; under the multiclass
   softmax the hessian `p*(1-p)` vanishes as the model gains confidence,
   leaving leaf values unbounded, so boosting *diverged* — macro-F1 0.8053
   at round 10 down to 0.2519 at round 100, max |raw score| 6.4e6. Setting
   `lambda_l2 = 1.0` bounds raw scores at ~28 and macro-F1 rises
   monotonically. **Three hypotheses were wrong first** and were killed by
   controlled measurement, not argument: `min_data_in_leaf`/`min_data_in_bin`
   (stock LightGBM defaults diverge too), label noise (only 2.22% of rows
   sit on an ambiguous feature vector; the Bayes ceiling is 99.87%
   accuracy), and class-blocked row ordering.

2. **The retrain then failed on memory, and the first diagnosis of that was
   also wrong.** `build_feature_matrix`'s `list[list[float]]` was blamed at
   an estimated 5-8 GB. Measured, it is 2.01 GB; the **Pydantic
   `LabeledFlow` objects are 3,857 B/row = 10.17 GB**, peaking near
   12.18 GB against 8 GB of RAM. A numpy-only rewrite would have saved
   1.4 GB of 12.18 and crashed again. **The fix had to be streaming**, not
   dtype tuning: `iter_cicids2017` -> `build_feature_matrix_streaming` ->
   `train_lightgbm_from_arrays`. Measured after: **peak RSS 1.23 GB, 237 s**
   for the full corpus. If you retrain this on a memory-constrained
   machine, use the streaming path; `load_cicids2017` still materialises
   everything and is fine only for fixtures.

3. **The rare-class exclusion policy was implemented, unit-tested,
   documented as wired — and had zero production callers.** v0.3.0 trained
   on 7 Heartbleed, 15 SQL Injection and 26 Infiltration rows as a result.
   Caught by counting what actually reached the booster, not by reading
   code. Fixed in v0.4.0 (training split 1,981,390 vs 1,981,438 — exactly
   those 48 rows), with `tests/ml/test_exclusion_is_wired.py` as an
   integration guard verified to fail against a no-op implementation.

### Decisions, settled

- **Exclusion threshold: `MIN_SUPERVISED_TRAINING_EXAMPLES = 100`**, first
  enforced in **v0.4.0**. Counts jump 36 -> 652 (18x), so any cutoff in
  that gap picks the same three classes. Cost measured like-for-like:
  **-0.002592 macro-F1** over the same 12 classes, with binary precision
  and FPR both improving. The earlier decision entry above asked for a
  human call on this; the measurement makes it cheap, so it is applied.
- **Architecture: flat multiclass.** Two-stage was built and evaluated at
  full scale (stage-1 gate 99.69% accuracy, stage 2 on 390,302 attack-only
  rows, composed on real stage-1 predictions) and lost like-for-like,
  0.8546 vs 0.8217, while costing a second artifact and a second inference
  call.
- **Scoring weights: 60 / 15 / 25** (was 50/25/25), set from measured
  detector reliability — LightGBM precision 0.9927 / FPR 0.0018 against
  Isolation Forest precision 0.5300 / FPR 0.0987. Anomaly at 15 cannot
  reach `low_threshold` (25) alone. Per-class weighting was considered and
  rejected (spec §18 explainability; it would bake dataset constants into
  the engine and go stale on retrain).

### Remaining limitations — stated plainly, not smoothed over

- **Bot 45.42%, Web Attack - Brute Force 50.44%, Web Attack - XSS 11.22%.**
  Their dominant error is being missed as BENIGN (54.6% / 44.2% / 50.0%),
  a detection failure rather than attack-type confusion. Class weighting
  raises Bot recall to 98.31% but collapses its precision to 20.47%, so it
  is not deployable as the primary classifier. Assessed as close to the
  ceiling for a flow-level feature schema that carries no payload or HTTP
  semantics — see `docs/ML_PIPELINE.md` for the full reasoning and options.
- **Excluded-class coverage: verified, and one real gap found.** The
  "Isolation Forest catches these instead" story was an assumption; it is
  now measured against every real flow of each class (benign
  false-positive baseline 9.93%):
  **Heartbleed 100.00% flagged (11/11)** and **Infiltration 86.11%
  (31/36)** — both far above baseline, so the safety net genuinely holds
  for those two. **Web Attack - Sql Injection: 0.00% (0 of 21)** — below
  even the benign false-positive rate. Combined with 0% from LightGBM
  (excluded by policy), **SQL Injection has no detection coverage anywhere
  in the pipeline.** Behaviour analysis does not close it: all eight
  signals are volume/rate/diversity measures, and 21 protocol-valid HTTP
  requests to one port on one host trip none of them specifically. Closing
  this needs payload/L7 inspection, which the flow-level schema
  deliberately excludes. Documented as a known gap, not solved here.
- **Train/test leakage: audited and resolved — it does NOT inflate the
  results.** 17.68% of test rows have a bit-identical twin in the v0.4.0
  training split (41,959 of 123,458 duplicate groups straddle the split;
  the other 81,499 are over-representation within one split). Re-evaluating
  the shipped artifact on only the 349,516 rows with no training twin moves
  macro-F1 by **-0.00035** (0.854589 -> 0.854239), while accuracy,
  precision and false-positive rate all *improve*. The two most-duplicated
  classes hold up specifically: PortScan 99.99% -> **99.97%** on 10,699
  clean rows, SSH-Patator 98.87% -> **99.58%** on 480. v0.4.0's numbers
  stand as reported, no version bump. Future retrains should use a
  group-aware split keyed on the feature-vector hash — a methodology
  improvement, not a correction.
- **Isolation Forest is unchanged** (v0.2.0, precision 0.5300, recall
  0.4537). It was not retrained this pass; the divergence bug is specific
  to gradient boosting and does not apply to it.
- **UNSW-NB15 is deferred, not dropped.** The dataset is not present on
  this machine (only the 8 CICIDS2017 CSVs are), so its class distribution
  could not be audited. Doing so needs the dataset copied here and is the
  obvious next data-side task.
- **Everything is one 2017 dataset.** No number here measures performance
  on this project's real traffic; that remains the spec §34 attack-lab
  exercise and is still Environment-dependent.


## Leakage audit and excluded-class coverage (2026-08-30, post-v0.4.0)

Three follow-ups resolved without changing the shipped artifact.

**1. Leakage is real but harmless.** Duplicate == bit-identical across all
29 canonical features (exact float64, no rounding, so near-duplicates are
not detected and these are lower bounds). 41,959 of 123,458 duplicate
groups span train and test; 17.68% of test rows have a training twin.
Re-evaluating the shipped v0.4.0 on the 349,516 leakage-free rows changes
macro-F1 by -0.00035. PortScan (55.12% leaked) still scores 99.97% and
SSH-Patator (45.76% leaked) scores 99.58% on their clean subsets — higher
than on the full split. **v0.4.0 stands; no version bump.** Full detail and
the leakage-free per-class table in `docs/ML_PIPELINE.md` and
`reports/v040_leakfree.txt`.

**2. Excluded-class coverage is 2-of-3, not 3-of-3.** Heartbleed 100.00%
and Infiltration 86.11% flagged by the Isolation Forest against a 9.93%
benign baseline; **Web Attack - Sql Injection 0.00% (0/21)**. That class has
no coverage from any detector in the pipeline. Recorded as a limitation.

**3. What the "divergence bug" was, since it was referenced without
explanation.** In `lightgbm_trainer.py`, `lambda_l2` was never set and took
LightGBM's default of 0.0. A boosted leaf's value is
`-sum(grad) / (sum(hess) + lambda_l2)`; under the multiclass softmax the
hessian `p*(1-p)` vanishes as the model gains confidence, so with no L2 term
the denominator collapses and the only remaining bound is
`min_sum_hessian_in_leaf` (1e-3) — about 10^3 per tree, and ~10^6 after 100
rounds, which is what was measured. Boosting diverged instead of
converging. **It cannot apply to the Isolation Forest**: that trainer calls
sklearn's `IsolationForest` — an unsupervised ensemble of independent
random isolation trees with no gradient, no hessian, no leaf output value
and no additive accumulation across estimators (a score is just path
length). `grep` for `lambda|gradient|hessian|boost|leaf` in
`isolation_forest_trainer.py` returns nothing. Its one untuned knob is
`contamination`, chosen by a 5-candidate validation sweep — coarse tuning,
not a divergence failure mode. Original explanation: commit `3ea9f87` and
`docs/ML_DATA_AUDIT.md` §F.

## ADDENDUM_2 pass — B1-B6 detection-timing redesign (2026-08-31 -)

A second wave of deliberate architecture additions on top of
`docs/ADDENDUM.md`'s A1-A8, recorded in `docs/ADDENDUM_2.md`. Full
reasoning, implementation detail, and per-item test lists live there; this
section tracks status/honesty labels only, updated per B-item as each is
completed. This pass may span multiple sessions — see `docs/ADDENDUM_2.md`
for what's actually built so far if this table looks incomplete.

| Item | Status | Label |
|------|--------|-------|
| B1 Creation-time behavior counters | Complete | Tested — see below |
| B2 Slow-rate aggregate signal | Complete | Tested — see below |
| B3 Evidence-maturity gate | Not started | — |
| B4 Heartbleed detector | Not started | — |
| B5 JA3 fingerprinting | Not started | — |
| B6 Empirical sqlmap-pattern test | Not started | — |
| §7 WAFFY scope boundary (docs only) | Not started | — |

### B1 — Tested

`pirewall.detection.behavior.SourceBehaviorState`/`BehaviorAnalyzer` split
into `observe_new_connection` (creation-time) and `observe_completion`
(completion-time only: `failure_count`), wired via a new
`FlowAggregator(on_new_flow=...)` callback and a second bounded queue in
`CoreDaemon` drained by the detection thread. Full design rationale, the
no-double-counting argument, and the eviction/backpressure fallback are in
`docs/ADDENDUM_2.md` B1 — not duplicated here.

**Tested**: 4 new + 6 pre-existing (unmodified) tests in
`tests/unit/test_behavior.py`; 2 new + 9 pre-existing (unmodified) tests in
`tests/unit/test_flow_aggregator.py`. `ruff check .` and `pyright --strict`
clean across the whole repo (not just touched files). Full suite: 559
passed, 21 skipped, 1 pre-existing unrelated failure (see below) — same
counts before and after this section's changes aside from the new tests.

**Written, not executed this session**:
`tests/integration/test_core_daemon.py::test_scanning_visible_through_a_completing_flow_while_scan_flows_stay_open`
— a real-`CoreDaemon` end-to-end test proving 6 never-completed scan flows
plus 1 completing flow produce a `ThreatAssessment` already carrying
`SCANNING`. Lint/type-clean, but `tests/integration/test_core_daemon.py` is
entirely gated on `hasattr(socket, "AF_UNIX")`, which this Windows dev
session lacks — same pre-existing constraint as all 8 other tests already
in that file. **Run this on the next macOS/Linux session** before treating
it as verified; the unit-level tests above already exercise the same
mechanism in isolation and did run.

**Pre-existing, unrelated failure noted in passing, not fixed here**:
`tests/security/test_firewall_base_template.py::test_management_access_restricted_to_admin_pc_placeholder`
fails identically on a clean checkout before any of this pass's changes
(confirmed via `git stash`) — the base nftables template's DNS (port 53)
accept rule is scoped to `${PROTECTED_NETWORK}`, not `${ADMIN_PC_IP}`,
which the test expects for every `tcp dport` accept line including DNS.
Out of scope for this pass; flagging so it isn't mistakenly attributed to
B1-B6.

### B2 — Tested

New `BehaviorPatternType.SLOW_RATE_DOS` signal:
`FlowAggregator.snapshot_slow_connection_clusters` (read-only scan of
still-open flows, grouped by source/destination) feeds
`BehaviorAnalyzer.note_slow_connections` via a new sweep-thread-to-
detection-thread queue, and its representative flow snapshot goes through
the completely unmodified detection/decision/enforcement pipeline. Full
design, the reused-pipeline side effect in SHADOW mode, and the
DHCP-false-positive-avoidance argument are in `docs/ADDENDUM_2.md` B2.

**Tested**: 3 new tests in `tests/unit/test_behavior.py`, 4 new tests in
`tests/unit/test_flow_aggregator.py`. Adding the 9th `BehaviorPatternType`
member required updating 3 pre-existing tests that hardcoded the old
total-of-8 denominator (`test_behavior_pattern_type_values`,
`test_behavior_contribution_scales_with_pattern_count`,
`test_multiple_corroborating_evidence_types_sum`) — no production code had
a hardcoded total. `ruff check .` and `pyright --strict` clean across the
whole repo. Full suite: 566 passed, 22 skipped, the same 1 pre-existing
unrelated failure noted under B1.

**Written, not executed this session** (same `AF_UNIX`-on-Windows gap as
B1): `tests/integration/test_core_daemon.py::test_slow_rate_dos_detected_without_waiting_for_connections_to_close_or_time_out`.
Run on the next macOS/Linux session, alongside B1's equivalent test.
