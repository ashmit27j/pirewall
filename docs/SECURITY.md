# pirewall — Security Hardening (spec §27, §45, ADDENDUM.md)

This document is the single place that pulls together every security
control pirewall relies on: what's already built and tested against Fakes
in this repository, and what a human must still configure by hand on real
Raspberry Pi hardware. Nothing here is applied automatically — spec §21 /
`CLAUDE.md`: never auto-modify network configuration, systemd state, or the
nftables ruleset during a Claude Code session.

## 1. The Raspberry Pi itself is a security boundary (spec §27)

### Operating system

- Use a current, supported Raspberry Pi OS (64-bit) release. Keep it
  updated (see §6 below).
- Disable unnecessary services on first boot: Bluetooth (if unused),
  Avahi/mDNS (if unused), any pre-installed desktop-environment services —
  pirewall is a dedicated gateway appliance, not a general-purpose Pi.
- `deploy/network/60-pirewall-forwarding.conf.template` documents the
  required kernel network settings (IPv4 forwarding on, IPv6 forwarding
  deliberately left off per ADDENDUM.md A5, redirect/source-route
  rejection, reverse-path filtering).

### Least privilege and service isolation — the two-process split

ADDENDUM.md A4 is the concrete answer to spec §45's "a compromised control
panel must not automatically provide unrestricted root access":

| | `pirewall-core.service` | `pirewall-api.service` |
|---|---|---|
| Runs | capture, flow, features, detection, engine, firewall manager/backend, RPC server | FastAPI, control panel, RPC client |
| User | `pirewall-core` | `pirewall-api` (different user) |
| Capabilities | `CAP_NET_RAW`, `CAP_NET_ADMIN` only | **none** — `CapabilityBoundingSet=`/`AmbientCapabilities=` explicitly empty |
| Reaches the other | n/a | only via the `AF_UNIX` RPC socket, never a direct import |

`tests/security/test_api_process_isolation.py` proves at the import-graph
level (AST-scanned, not just convention) that `pirewall/api/` and
`pirewall/web/` never import `pirewall.capture`, `pirewall.firewall.manager`,
or `pirewall.firewall.backend`. `tests/security/test_backend_isolation.py`
proves `pirewall.firewall.manager` is the *only* importer of
`pirewall.firewall.backend` anywhere in the codebase. `deploy/systemd/`'s two
unit files and `deploy/systemd/README.md` document the concrete user/group/
capability/socket-permission setup; `tests/security/test_systemd_hardening.py`
statically asserts the required directives are present in those files.

### SSH

- Key-based authentication only; disable `PasswordAuthentication` in
  `sshd_config`.
- `PermitRootLogin no`.
- Restrict to trusted networks: `deploy/firewall/base.nft.template`'s
  `input` chain only accepts TCP port 22 from `admin.admin_pc_ip` — SSH is
  not reachable from the rest of the LAN or the WAN at all by default.
- Use a non-default port only if your threat model calls for it; it is not
  a substitute for the above, only obscurity on top of it.

### Network exposure

- The control panel/API (`api.port`, default 8443) is bound to
  `api.host` (default `127.0.0.1` in the checked-in placeholder config —
  set it to the LAN-facing address for real use) and additionally
  restricted at the nftables level to `admin.admin_pc_ip` only
  (`deploy/firewall/base.nft.template`'s `input` chain) and at the
  application level (`config.security.restrict_to_admin_pc`,
  `pirewall.api.auth.enforce_admin_pc_ip`, Phase 7, tested).
- No port is exposed to the WAN by default. `deploy/firewall/base.nft.template`'s
  `forward` chain policy is `drop`: new inbound WAN connections are refused
  unless a deployment explicitly adds a narrow exception.

### Secrets

- `admin_password_hash` (`config/default_config.toml` `[authentication]`) is
  a `hashlib.scrypt` hash (see `docs/ARCHITECTURE.md`), never a plaintext
  password — generate it with the Phase 7 admin-password tooling, never
  hand-write one.
- TLS private keys (`api.tls_key_path`) must never be committed; `.gitignore`
  already excludes common cert/key patterns under `deploy/certificates/`.
  Real certificate files live only on the deployed Pi, with filesystem
  permissions restricting read access to the `pirewall-api` user (the
  process that actually terminates TLS).
- `config/local_config.toml` (the real, filled-in config, as opposed to the
  checked-in `config/default_config.toml` placeholder) must never be
  committed either — it contains the real Admin PC IP, real interface
  names, and the real password hash.

### Filesystem

- Configuration, model artifacts (`pirewall/ml/artifacts/`), certificates,
  and firewall/rule state should be read-only to the service that doesn't
  need to write them and writable only by the one that does — see each
  `.service` file's `ReadOnlyPaths=`/`ReadWritePaths=` and
  `ProtectSystem=strict`.
- Logs (`logging.log_dir`, default `/var/log/pirewall`) should be writable
  only by `pirewall-core` (and a separate `/var/log/pirewall-api` for the
  API process, per its own service file) — not world-readable, since a
  security-event log is itself sensitive.

### Updates

See §6 below.

### Resource exhaustion (spec §27 "Resource exhaustion")

Already built and tested in earlier phases, not new to Phase 8 — this
section summarizes what exists rather than introducing it:

| Protection | Where | Bound |
|---|---|---|
| Flow-table exhaustion | `pirewall.flow.aggregator.FlowTable` | LRU-evicted, capped at `flow.max_flows` (Phase 3, flood-tested to 5000 flows against a 100-flow cap) |
| Behavioral-state exhaustion | `pirewall.detection.behavior.BehaviorAnalyzer` | capped at `detection.max_tracked_sources`/`max_tracked_destinations_per_source`/`max_tracked_ports_per_source` (Phase 5, flood-tested to 5000 sources) |
| Excessive rule creation | `pirewall.firewall.rate_limiter.RuleCreationRateLimiter` (ADDENDUM.md A3) | `firewall.max_adaptive_rules_per_window` per `firewall.rate_window_seconds`; detection/event generation is *not* suppressed by the cap, only rule creation (Phase 6) |
| Unbounded rule accumulation | `firewall.max_active_rules`, rule expiration (`RuleStatus.EXPIRED`) | Phase 6 |
| Recent-history memory growth | `pirewall.ipc.state.CoreStateStore` | every buffer is a bounded `deque(maxlen=api.history_size)` (Phase 7) |
| API abuse | session expiry (`authentication.token_expiry_seconds`/`security.session_timeout_seconds`), Admin-PC-IP restriction on every write endpoint | Phase 7 |
| Excessive logging | `logging.max_bytes`/`backup_count` (rotating handler config) | Phase 1 |
| CPU/memory exhaustion (process-level) | `MemoryMax`/`MemoryHigh`/`CPUQuota`/`TasksMax` in both `.service` files | Phase 8, Environment-dependent (systemd cgroup enforcement requires a real host) |

## 2. Threat model notes

- **Compromised `pirewall-api`**: cannot capture packets, cannot modify
  nftables, cannot read/write anything `pirewall-core` doesn't expose over
  the narrow RPC protocol (`pirewall.ipc.protocol.RpcOperation`'s fixed,
  typed operation set) — no shell execution, no arbitrary file access
  beyond its own `ReadWritePaths=`.
- **Compromised `pirewall-core`**: has real capture/firewall capabilities
  by design (it has to, to do its job) but cannot reach the network beyond
  `AF_PACKET`/`AF_UNIX`/`AF_INET`/`AF_INET6`/`AF_NETLINK`
  (`RestrictAddressFamilies=`), cannot escalate (`NoNewPrivileges=true`,
  no `CAP_SYS_ADMIN`), and its own crash/restart behavior is bounded and
  observable (ADDENDUM.md A6 — fail-open, watchdog, crash-loop detection
  surfaced to `pirewall-api`'s `/status`, which stays up independently).
- **A malicious/compromised LAN client**: cannot reach the control panel
  (Admin-PC-IP restriction, both at nftables and application level), cannot
  cause unbounded rule creation (A3), and any single flow's adaptive rule
  can never be broader than that flow's own evidence (spec §24 Safety,
  `pirewall.firewall.validator`, tested) or target the static allowlist
  (ADDENDUM.md A2).
- **Kill-switch (ADDENDUM.md A8)**: the one deliberately fast, destructive,
  easy-to-reach administrative action. Still goes through the same
  authentication/Admin-PC restriction as everything else — there is no
  lower-security bypass path (Phase 6/7, tested).

## 3. What's Tested vs. Environment-dependent here

Per `CLAUDE.md`'s labeling rules:

- **Tested**: `pirewall.integration.wazuh`/`pirewall.integration.netdata`
  payload shaping (Phase 8); every import-isolation/backend-isolation test
  (Phases 6/7); rule validation's safety stage, allowlist, rate cap
  (Phase 6); Admin-PC-IP restriction, session handling (Phase 7); the
  static structure of `deploy/systemd/*.service` and
  `deploy/firewall/base.nft.template` (Phase 8,
  `tests/security/test_systemd_hardening.py`,
  `tests/security/test_firewall_base_template.py`).
- **Environment-dependent** (a human must verify on real Pi hardware — see
  `docs/DEPLOYMENT.md` for the exact steps): real user/group creation and
  socket permission enforcement; real systemd capability/namespace
  sandboxing actually applying without breaking capture/nftables (spec §27
  explicitly warns against blind restrictions); real SSH hardening; real
  TLS certificate deployment; the real fail-open crash/watchdog behavior
  under an actual crash (not a Fake); real `nft -c -f` syntax validation of
  `deploy/firewall/base.nft.template` and `deploy/network/nat-masquerade.nft.template`.
