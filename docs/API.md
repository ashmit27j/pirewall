# pirewall — API & Control Panel (spec §28-30, ADDENDUM.md A4)

`pirewall-api` is a FastAPI application (`pirewall.api.app.create_app`)
running as a **separate OS process** from `pirewall-core`
(ADDENDUM.md A4 — see `docs/SECURITY.md`, `deploy/systemd/README.md`). It
never imports `pirewall.capture`, `pirewall.firewall.manager`, or
`pirewall.firewall.backend` — enforced at the import-graph level by
`tests/security/test_api_process_isolation.py`. Every route reaches
`pirewall-core` exclusively through an injected `BaseRpcClient`
(`pirewall.ipc`), over a Unix domain socket in the real deployment.

## Authentication model (spec §29)

Single-admin, no RBAC — `config.authentication.admin_username`/
`admin_password_hash` is the only account. `pirewall.api.auth`:

- **Password hashing**: stdlib `hashlib.scrypt` (a memory-hard KDF), never
  bcrypt/argon2 (not on `CLAUDE.md`'s dependency list — see
  `docs/ARCHITECTURE.md`). Stored as `"<salt_hex>$<hash_hex>"`; verified
  with a constant-time `hmac.compare_digest`.
- **Sessions**: opaque `secrets.token_urlsafe` tokens, not JWTs. Held
  server-side in an in-memory `SessionStore` with an expiry
  (`authentication.token_expiry_seconds`). No cross-restart persistence —
  a `pirewall-api` restart invalidates every session, which is fine for a
  single-admin system.
- **Session transport**: an `httponly`, `samesite=strict` cookie
  (`pirewall_session`), or a `Bearer` token in the `Authorization` header.
- **Admin PC restriction** (spec §29): every non-`/health` route requires
  the connecting client's IP to equal `config.admin.admin_pc_ip` — checked
  independently of session validity, via `pirewall.api.auth.enforce_admin_pc_ip`.
  Controlled by `config.security.restrict_to_admin_pc` (default `true`).
  This is enforced *both* here at the application level and again at the
  network level by `deploy/firewall/base.nft.template`'s `input` chain
  (defense in depth, not redundant).

## TLS (spec §28)

`config.api.tls_cert_path`/`tls_key_path` are required, non-empty config
fields (`ConfigurationError` if missing — see
`tests/unit/test_config_loader.py`'s certificate tests). Minimum TLS
version is `config.security.min_tls_version` (default `TLSv1.3`). Actually
terminating TLS with a real certificate happens in the not-yet-built
`pirewall.api.__main__` entry point (uvicorn's TLS options) — see
`docs/PROGRESS.md` Phase 8/9's "known gap" note and `docs/DEPLOYMENT.md` §6
for real certificate setup.

## Route surface

All routes are prefixed `/api/v1` except the control panel itself
(`/control-panel`). `tests/unit/test_api_routes.py::test_registered_route_surface_matches_spec`
enumerates every registered route and asserts it matches this list exactly
— treat that test as the authoritative source if this table ever drifts.

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/v1/health` | none | Liveness of `pirewall-api` itself only — not a check of `pirewall-core`. |
| POST | `/api/v1/auth/login` | Admin PC only | Returns a session token; emits `AUTHENTICATION_FAILURE` on failure. |
| POST | `/api/v1/auth/logout` | session + Admin PC | Invalidates the session. |
| GET | `/api/v1/status` | session + Admin PC | `StatusResult` — enforcement mode, failure mode, rule/flow counts, model-loaded flags. |
| GET | `/api/v1/flows` | session + Admin PC | Recent `Flow`s (`CoreStateStore`'s bounded buffer). |
| GET | `/api/v1/detections` | session + Admin PC | Recent `DetectionRecord`s. |
| GET | `/api/v1/threats` | session + Admin PC | Recent `ThreatAssessment`s. |
| GET | `/api/v1/decisions` | session + Admin PC | Recent `FirewallDecision`s. |
| GET | `/api/v1/rules` | session + Admin PC | Every rule the manager knows about, any status. |
| GET | `/api/v1/events` | session + Admin PC | Recent `SecurityEvent`s. |
| GET | `/api/v1/models` | session + Admin PC | Loaded `ModelMetadata` (LightGBM/Isolation Forest). |
| POST | `/api/v1/rules/{id}/disable` | session + Admin PC | `ACTIVE` -> `DISABLED`. 404 if not in an actionable state. |
| POST | `/api/v1/rules/{id}/remove` | session + Admin PC | `ACTIVE` -> `REMOVED`. |
| POST | `/api/v1/rules/{id}/approve` | session + Admin PC | ADDENDUM.md A7: `PENDING_APPROVAL` -> deploy through the normal path. |
| POST | `/api/v1/rules/{id}/reject` | session + Admin PC | ADDENDUM.md A7: `PENDING_APPROVAL` -> `REJECTED`, never deploys. |
| GET | `/api/v1/allowlist` | session + Admin PC | ADDENDUM.md A2. |
| POST | `/api/v1/allowlist` | session + Admin PC | Add an entry; `created_by` is the authenticated session's username. |
| DELETE | `/api/v1/allowlist/{id}` | session + Admin PC | 404 if not found. |
| POST | `/api/v1/firewall/kill-switch` | session + Admin PC | ADDENDUM.md A8: SHADOW mode + every active adaptive rule removed. |
| GET | `/control-panel/login` | Admin PC only | The login page itself (unauthenticated by design — can't log in otherwise). |
| GET | `/control-panel` | session + Admin PC | The rendered control panel (spec §30, see below). |

## Control panel (spec §30)

`pirewall.web.render` builds every page as a plain Python function
returning an HTML string, escaping all dynamic content via stdlib
`html.escape` — no Jinja2 (not on the allowed dependency list; spec §30
"not a large frontend framework" — see `docs/ARCHITECTURE.md`). Sections,
each reading from the same RPC client as the JSON API:

- System health (`/status`)
- Network statistics
- Threats / detections
- Firewall rules — including `PENDING_APPROVAL` Approve/Reject buttons
  (A7) and a kill-switch button with a JS confirmation step (A8)
- Events
- ML status (loaded model versions/metadata)
- Allowlist (A2) — add/remove

## RPC transport (ADDENDUM.md A4)

`pirewall-api` never talks to `FirewallManager`/`FirewallBackend`/capture
directly. Every route's `RpcClientDep` is one of:

- `pirewall.ipc.client.UnixSocketRpcClient` — the real transport, talks to
  `pirewall.ipc.server.UnixSocketRpcServer` running inside `pirewall-core`
  over `config.api.rpc_socket_path`. Requires `socket.AF_UNIX` (absent on
  Windows only) and is **Tested** end to end against a real socket by
  `tests/integration/test_rpc_unix_socket.py`, including the socket's
  permission bits.
- `pirewall.ipc.loopback.LoopbackRpcClient` — an in-process test double
  calling `pirewall.ipc.dispatcher.CoreRpcDispatcher` directly, no socket
  at all. **Test-only** — never used in the real two-process deployment.

`CoreRpcDispatcher` implements every operation the table above needs
(`pirewall.ipc.protocol.RpcOperation`) against `CoreStateStore` +
`FirewallManager`, fully unit-tested independent of the transport.

## Testing

- **Tested**: auth (password hashing/verification, sessions, Admin-PC-IP
  restriction), the full RPC dispatcher, every endpoint end-to-end via
  FastAPI's `TestClient` + `LoopbackRpcClient` (login, restriction, session
  enforcement, every write endpoint, route-surface enumeration), control
  panel HTML rendering (every section, XSS-escaping, empty-state handling),
  both A4 import-isolation checks.
- **Environment-dependent**: TLS with real certificates, and the socket's
  real *ownership* under systemd (its mode is code-guaranteed and tested).
  Both need a real Linux host.
