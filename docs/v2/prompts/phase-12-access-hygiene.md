# Phase 12: Access hardening and hygiene (the P0 items)

**Read first:**
- `CLAUDE.md`, including its v2 section
- `docs/ADDENDUM_4.md`
- `docs/V2_CONTRACTS.md`
- `docs/KNOWN_ISSUES.md` items 4, 7, 9, 15, 17 and 23
- `docs/v2/PLAN_FINAL.md` §4.9
- `pirewall/api/`, `pirewall/portal/`, `scripts/deployment/portal_users.py`, `scripts/deployment/make_certs.sh`

This phase can run in parallel with phases 13 and 15. **It owns only:** `pirewall/api/**`, `pirewall/portal/**`, `scripts/deployment/portal_users.py`, `scripts/deployment/make_certs.sh`, `config/*` comments, and their tests.

## Goal
Close the cheap, high-value access holes that v2 doesn't otherwise touch.

## Deliverables
1. **Admin login throttle.** In `pirewall/api`, fail per client IP and globally. Mirror the portal's `max_failed_logins_per_ip` / `failed_login_window_seconds` pattern, using new keys `[authentication] max_failed_logins_per_ip`, `max_failed_logins_global` and `failed_login_window_seconds`, all additive. Return 429 with Retry-After. Every lockout emits an AUTHENTICATION_FAILURE event.
2. **Portal throttle per account and global**, in addition to the existing per-IP throttle.
3. **Allowlist re-authentication.** `POST /api/v1/allowlist` requires the admin password again in the body. It only accepts a /32 plus an optional MAC, with a mandatory reason. It emits a WARNING event that is forwarded to Wazuh.
4. **Demo accounts.**
   - `portal_users.py remove-demo` removes all `demo-*` accounts, is idempotent, and prints what it removed.
   - Core startup refuses ASSISTED/ACTIVE while demo accounts exist (SHADOW is allowed, with the existing warning) unless `portal.allow_demo_accounts = true` is set explicitly.
   - Remove the demo passwords from `docs/SETUP.md`.
5. **`make_certs.sh`** accepts several IPs and DNS names and writes them all as SANs (KNOWN_ISSUES #9).
6. **API log directory.** Add `[api] log_dir` (default `/var/log/pirewall-api`) and use it (KNOWN_ISSUES #15).
7. **`security.session_timeout_seconds`** becomes a real idle timeout, distinct from `token_expiry_seconds`, which stays the absolute lifetime (KNOWN_ISSUES #17).
8. **Admin-PC check.** `enforce_admin_pc_ip` gains an optional interface check. Pass the server's bound interface or address. The real interface+MAC pin happens in nft (phase 16); here, document that the IP check is defence-in-depth only.

## Tests
- Throttle unit tests: the window, global vs per-IP, and the Retry-After header.
- Portal per-account throttle.
- Allowlist re-auth: wrong password, missing reason, /24 rejected.
- `remove-demo` is idempotent.
- The ASSISTED-with-demo-accounts refusal.
- SAN generation, checked by parsing the output with `openssl x509 -text` if available, otherwise skipped with a reason.
- Idle timeout.

## Non-goals
No nft changes and no MAC binding of portal sessions (that is phase 14). Don't touch the files listed for other phases.

## Definition of done
- ruff, pyright strict and pytest all green.
- KNOWN_ISSUES items 4 (the tooling; the deployment action is still the human's), 9, 15 and 17 are marked fixed, each with the evidence.
- PROGRESS updated.
