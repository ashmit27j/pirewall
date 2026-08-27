# pirewall — Architecture Notes

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
functions returning strings, escaping all dynamic content via stdlib
`html.escape` — this is a real, if unglamorous, choice to stay within the
dependency policy rather than reach for the default.

### `uvicorn` and `httpx` alongside FastAPI (Phase 7)

`CLAUDE.md` lists FastAPI itself as allowed, but a bare `pip install
fastapi` has no ASGI server to actually run it, and FastAPI's own
`TestClient` (needed to test the app per this phase's test requirements)
requires `httpx`. Both are treated as necessary companions of the
already-approved FastAPI dependency, not new independent choices — the
same reasoning already applied to `joblib` (scikit-learn) and `numpy`
(lightgbm/scikit-learn) in Phases 4/5.

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
  inside `pirewall-core`. Linux-only (`socket.AF_UNIX`); see
  `docs/PROGRESS.md` for its Environment-dependent label.
* `pirewall.ipc.client.UnixSocketRpcClient` — the real transport's client
  half, runs inside `pirewall-api`. Same Environment-dependent label.
* `pirewall.ipc.loopback.LoopbackRpcClient` — an in-process test double
  implementing the same `RpcClient` Protocol by calling the dispatcher
  directly, no socket at all. **Test-only.** The real two-process
  deployment must never use this — doing so would defeat the entire point
  of A4's process isolation (a compromised `pirewall-api` sharing memory
  with `pirewall-core` instead of talking over a narrow, typed socket).
