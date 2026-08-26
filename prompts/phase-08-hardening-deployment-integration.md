# Phase 8 — Raspberry Pi hardening, deployment templates & Wazuh/Netdata integration

Read `CLAUDE.md` and `docs/MASTER_SPEC.md` sections 21, 27, 32, 33, 45 before
starting. Then read `docs/ADDENDUM.md` items **A3, A4, A6** — A4 in
particular means "one systemd unit" from the base spec becomes two.
Confirm Phase 7 is marked complete in `docs/PROGRESS.md`.

## Goal

Produce the deployment artifacts and hardening documentation needed to run
pirewall securely on real Pi hardware, and wire the event/metrics
integrations to the Admin PC — without actually touching any real host's
network config, systemd state, or nftables ruleset during this session (spec
§21: never auto-modify network configuration; `CLAUDE.md`: don't touch real
host state without explicit confirmation).

## Deliverables

1. **`pirewall/integration/wazuh.py`** — forwards structured `SecurityEvent`s
   (Phase 7) to Wazuh on the Admin PC. Do not build a second SIEM — this is a
   forwarder, not a store/query layer (spec §32).

2. **`pirewall/integration/netdata.py`** — exposes the operational metrics
   listed in spec §33 (CPU, memory, packet rate, packet drops, active flows,
   flow creation/expiration, inference count, inference latency, detection
   count, block count, rule count, rule rejection count, API health, capture
   health, firewall health), **plus one new metric for addendum A3**:
   adaptive-rule creation rate (and how close it is to
   `firewall.max_adaptive_rules_per_window`), in a form Netdata can scrape.

3. **`deploy/network/`** — documented templates (not auto-applied) for: IP
   forwarding, routing, firewall forwarding, NAT/masquerading, WAN/LAN
   interface config — parameterized by the config from Phase 1 (interface
   names, protected network, upstream gateway, Admin PC IP). Include a
   README in this directory explaining these are templates a human reviews
   and applies manually.

4. **`deploy/systemd/`** — **two** unit files per addendum A4, not one:
   - `pirewall-core.service` — capture, flow, features, detection, engine,
     firewall manager/backend, and the RPC socket server from Phase 7.
     `NoNewPrivileges=true`, `PrivateTmp=true`, a restricted
     `CapabilityBoundingSet`/`AmbientCapabilities` limited to exactly what
     packet capture and nftables operations need (document which
     capabilities and why), restricted `ReadWritePaths`, resource limits
     (`MemoryMax`, etc.), a dedicated non-root service user. Also
     **addendum A6**: `Type=notify`, `WatchdogSec=<configured value>`,
     `Restart=on-failure`, and a `RestartStartLimitBurst`/
     `StartLimitIntervalSec` pair tuned to detect a crash-loop — when that
     limit trips, the service should end up in a state Phase 9's tests can
     assert on and that `pirewall-api` can observe and surface.
   - `pirewall-api.service` — FastAPI + control panel + the RPC client from
     Phase 7. A **different**, more restricted non-root user. No raw-socket
     or firewall-related capabilities in its `CapabilityBoundingSet` at
     all — verify this is actually absent, not just unused.
   - The Unix domain socket file connecting them: create it with
     filesystem permissions restricting access to exactly these two service
     users/groups (document the `umask`/group ownership approach used).
   Note in comments that these must be tested on real hardware before
   trusting them in production (don't apply overly aggressive restrictions
   blindly per spec §27's "do not apply systemd restrictions that break
   required networking functionality without testing").

5. **`deploy/firewall/`** — base nftables ruleset template establishing the
   default posture (deny-by-default forwarding except explicitly allowed,
   management access restricted) that pirewall's dynamic rules layer on top
   of.

6. **`docs/SECURITY.md`** — SSH hardening (key-based auth, disable password
   auth, disable root login, restrict to trusted networks), secrets handling
   (never plaintext, filesystem permissions, never committed), least-
   privilege/capability split between the privileged capture+firewall
   component and the unprivileged API/control-panel component, resource-
   exhaustion protections already built in earlier phases (flow table bounds,
   behavior-state bounds, rule validation) summarized here.

7. **`docs/DEPLOYMENT.md`** — step-by-step for a human to actually deploy to
   a real Pi 4: OS setup, required packages, applying `deploy/network/`
   templates, installing `deploy/systemd/` units, applying
   `deploy/firewall/` base ruleset, certificate setup, Admin PC-side Wazuh/
   Netdata configuration, secure update procedure for OS/dependencies/
   pirewall/ML artifacts.

## Explicit non-goals for this phase

Do not run any command that modifies this session's host network
configuration, systemd services, or firewall rules. Do not attempt to
actually connect to a real Wazuh/Netdata instance — build against the
`FakeFirewallBackend`-style pattern (a fake/mock transport) for tests.

## Tests (`tests/unit/`, `tests/security/`)

- `wazuh.py`/`netdata.py` payload shaping tested against a fake transport
  (assert correct structure/fields sent for representative events/metrics).
- A static test that parses `deploy/systemd/*.service` files and asserts the
  required hardening directives (`NoNewPrivileges`, `PrivateTmp`, a non-root
  `User=`, resource limits) are present — this is a file-content assertion,
  not a live deployment test.
- A static test asserting `pirewall-core.service` has `Type=notify` and a
  `WatchdogSec=` set (addendum A6), and that `pirewall-api.service`'s
  `CapabilityBoundingSet` does **not** contain any raw-socket/net-admin-style
  capability (addendum A4).
- A static test that the nftables base template in `deploy/firewall/`
  defaults to deny-by-default forwarding.

## Definition of done

Everything in `CLAUDE.md` → "Definition of done for a phase". Update
`docs/PROGRESS.md` row for Phase 8. Label essentially everything in this
phase as **Environment-dependent** except the integration payload-shaping
logic, which should be **Tested** — be explicit in `docs/PROGRESS.md` that
real hardware deployment, real SSH hardening, and real capability tuning
still need to happen by hand on the actual Pi, and list exactly what the
human needs to do.
