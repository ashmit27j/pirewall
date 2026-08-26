# Phase 7 — API, authentication, security events & control panel

Read `CLAUDE.md` and `docs/MASTER_SPEC.md` sections 28, 29, 30, 31, 45 before
starting. Then read **all of `docs/ADDENDUM.md`** — item **A4** changes this
phase's architecture significantly (two processes, not one), and A2/A7/A8
each add an API endpoint and a control-panel affordance. Confirm Phase 6 is
marked complete in `docs/PROGRESS.md`.

## Goal

Expose everything built so far through a locked-down FastAPI service and a
plain HTML/CSS/minimal-JS control panel — read access to state, plus the
explicitly-allowed write operations (disable/remove/approve rule, allowlist
management, kill-switch). No new execution surface.

## Architecture note (addendum A4 — read this before writing any code)

This phase's API/control-panel process is **`pirewall-api`**, and it is a
separate process from everything built in Phases 2–6 (which together make up
**`pirewall-core`**). `pirewall-api` must never import `firewall.backend`,
`firewall.manager`, or `capture` directly. Instead:

1. Define a small, typed RPC protocol (`pirewall/core/models/` — add a
   request/response model set, or a dedicated `pirewall/ipc/` module — your
   call, but keep it typed and Pydantic-validated like everything else) for
   the operations `pirewall-api` needs: read flows/detections/threats/
   decisions/rules/events/models; disable/remove/approve a rule; manage the
   allowlist; trigger the kill-switch.
2. Implement the **server** half inside `pirewall-core` (it listens on a
   Unix domain socket, filesystem-permissioned to the two service users —
   the actual permission-setting happens in Phase 8's systemd units, but the
   socket path/format is defined here) and the **client** half inside
   `pirewall-api`.
3. Every route in `pirewall/api/routes/` talks to `firewall/manager.py`
   (Phase 6) *only* through this client — never a direct import.
4. This also means Phase 6's `pirewall/main.py`/entrypoint needs a small
   addition: start the RPC server alongside the existing startup sequence.
   Keep this addition minimal and clearly separated from core logic.

## Deliverables

1. **`SecurityEvent` finalization** — confirm/extend Phase 1's model to cover
   every event type in spec §31 (`THREAT_DETECTED`, `FIREWALL_BLOCK`,
   `FIREWALL_ALLOW`, `RULE_CREATED`, `RULE_DEPLOYED`, `RULE_REJECTED`,
   `RULE_EXPIRED`, `MODEL_ERROR`, `CAPTURE_ERROR`, `FLOW_ERROR`,
   `FIREWALL_ERROR`, `AUTHENTICATION_FAILURE`, `SYSTEM_WARNING`). Wire event
   emission into the relevant Phase 2–6 modules where it's missing (capture
   errors, flow errors, model errors, firewall blocks/rejections/expirations)
   — a full event trail is the point of this model.

2. **`pirewall/api/auth.py`** — username/password auth, securely hashed
   passwords (e.g. `bcrypt`/`argon2`, not a hand-rolled hash), single admin
   role only (no RBAC per spec §29), session/token handling, TLS support
   (config-driven cert paths from Phase 1's `security`/`api` config
   sections). Admin PC IP restriction: reject admin API access from any
   source other than the configured Admin PC IP when configured, and emit a
   `SYSTEM_WARNING`/clear control-panel-visible error if that IP is unset or
   unreachable-looking, per spec §29's "clearly report the configuration
   problem" requirement.

3. **`pirewall/api/app.py`, `schemas.py`, `routes/`** — implement the
   endpoints listed in spec §28, **plus the addendum additions**:
   - `GET /api/v1/health`, `/status`, `/flows`, `/detections`, `/threats`,
     `/decisions`, `/rules`, `/events`, `/models`
   - `POST /api/v1/rules/{id}/disable`, `/rules/{id}/remove` (spec §28)
   - `POST /api/v1/rules/{id}/approve` — addendum A7, approves a
     `PENDING_APPROVAL` rule (a reject can reuse the existing
     `/rules/{id}/remove`-style pattern, or add `/rules/{id}/reject` if that
     reads more clearly — pick one and document it)
   - `GET/POST/DELETE /api/v1/allowlist` — addendum A2
   - `POST /api/v1/firewall/kill-switch` — addendum A8
   All of these call through the RPC client into `firewall/manager.py` (the
   one authorized path) — never touch the firewall backend directly from a
   route. No endpoint executes arbitrary commands or accepts arbitrary
   shell/rule text.

4. **`pirewall/web/`** — server-rendered control panel (HTML + CSS +
   minimal JS, no frontend framework, per spec §30) showing the sections in
   spec §30 (System, Threats, Firewall, Events, ML) **plus**:
   - the shadow-mode log (addendum A1) — what would have been blocked, when
     `EnforcementMode` is `SHADOW`
   - a Pending Approvals view with one-click Approve/Reject (addendum A7)
   - an Allowlist management view (addendum A2)
   - a prominent, hard-to-misclick-but-easy-to-find kill-switch button
     (addendum A8), with a confirmation step
   - current `EnforcementMode` and `failure.mode`, clearly displayed (both
     addendum A1/A6)
   Read-only except for the actions already exposed by the API — the control
   panel must not become a privileged execution interface (spec §30, §45).

## Explicit non-goals for this phase

No Wazuh/Netdata wiring (Phase 8), no systemd/deployment hardening (Phase 8),
though this phase should document what privilege level the API process
itself needs so Phase 8 can apply it (spec §45: "the API/control-panel
process must not receive unnecessary privileges").

## Tests (`tests/unit/`, `tests/security/`)

- Auth: correct credentials succeed; incorrect credentials fail and emit
  `AUTHENTICATION_FAILURE`; passwords are never stored/logged in plaintext.
- Admin PC IP restriction: requests from the configured IP succeed, requests
  from any other source IP are rejected; unset/misconfigured Admin PC IP
  produces the documented clear error, not a silent bypass.
- Endpoint-surface test: enumerate the app's registered routes and assert
  the set matches exactly what's specified — catches any accidental
  extra/dangerous route.
- `rules/{id}/disable`, `/remove`, and `/approve` correctly call through the
  RPC client → `firewall/manager.py`, and are rejected/blocked for an
  unauthenticated caller.
- **Import-graph test (addendum A4):** assert nothing under `pirewall/api/`
  or `pirewall/web/` imports `pirewall.firewall.backend`,
  `pirewall.firewall.manager`, or `pirewall.capture` — this should be a real,
  automated check (e.g. inspect module imports), not just a code-review
  note, since it's the concrete mechanism behind spec §45.
- Allowlist endpoints: add/remove entries correctly, admin-only.
- Kill-switch endpoint: calls `manager.revert_to_base()` and is rejected for
  an unauthenticated or non-Admin-PC caller exactly like every other
  write endpoint.
- `SecurityEvent` serialization never includes passwords, private keys, or
  other secrets even if such data is present in an underlying error.
- Control panel renders each required section (including the new addendum
  sections) from fixture state without executing any state-changing action
  on page load.

## Definition of done

Everything in `CLAUDE.md` → "Definition of done for a phase". Update
`docs/PROGRESS.md` row for Phase 7. Label TLS/cert handling as
**Environment-dependent** until exercised with real certificates on real
hardware; the auth/authorization logic itself should be **Tested**.
