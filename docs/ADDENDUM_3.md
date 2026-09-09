# ADDENDUM_3 — LAN captive portal and local console access

A third set of agreed additions, on top of `MASTER_SPEC.md`, `ADDENDUM.md`
(A1–A8) and `ADDENDUM_2.md` (B1–B6). Where this file conflicts with any of
those, **this file wins** — it is the newest and most specific.

Read it alongside `CLAUDE.md`: the architecture rules there are written
against A1–A8 and B1–B6, and this addendum adds a **third process**, a
**second RPC socket**, a **new trust boundary**, and a **new nftables
table**. Leaving that undocumented would make the project's own contract
silently wrong.

## Why this exists

Phases 1–9 produced a working adaptive firewall with no notion of *who* is
on the protected network. Any device that associated with the AP got a DHCP
lease and full forwarding with no identity at all, and a device the adaptive
pipeline blocked saw a dead network with no explanation — an nftables `drop`
is silent by construction.

C1–C6 close both gaps: authentication before forwarding, and a channel back
to a blocked client.

---

## C1 — The portal is a third process, behind a second RPC socket

`pirewall-portal` serves the sign-in page to clients on the protected
network. It is a separate OS process from `pirewall-api` for the reason A4
already spent a process boundary on, applied to a wider exposure:
`pirewall-api` holds admin session tokens in memory and is reachable only
from the Admin PC, while the portal is reachable by anything that can
associate with the AP.

**The socket split is the security-critical part.** `/run/pirewall/core.sock`
serves `CoreRpcDispatcher`, whose surface includes `KILL_SWITCH`,
`ADD_ALLOWLIST_ENTRY`, and every rule mutation. Putting the LAN-facing
process into that socket's group would hand those operations to the process
most likely to be attacked. So pirewall-core serves **two** sockets:

| Socket | Directory mode | Group | Dispatcher | Consumer |
|---|---|---|---|---|
| `/run/pirewall/core.sock` | `0750` | `pirewall-ipc` | `CoreRpcDispatcher` (24 ops) | `pirewall-api` |
| `/run/pirewall-portal/portal.sock` | `2750` | `pirewall-portal-ipc` | `PortalRpcDispatcher` (4 ops) | `pirewall-portal` |

`PortalRpcDispatcher` is a **separate class with its own `_HANDLERS`
table**, not a runtime filter over the existing one. A filtered view would
be one missing branch away from full privilege; with a separate table there
is no `kill_switch` handler present to reach. `pirewall-portal` is a member
of `pirewall-portal-ipc` only, never `pirewall-ipc`.

The two sockets live in **different directories** because a directory at
mode `0750` gates traversal by *its* group, whatever the socket's own
permissions say. The portal directory is **setgid** (`2750`), so the socket
inherits `pirewall-portal-ipc` on `bind()` — pirewall-core never calls
`chown`, which its own `SystemCallFilter=~@privileged` correctly forbids.
`UnixSocketRpcServer` *verifies* the resulting group and refuses to serve on
a mismatch, so a missing `tmpfiles` entry is a loud startup failure rather
than an unreachable socket.

The portal binds an **unprivileged** port (`portal.listen_port`, default
8080). Port 80 reaches it through the nat redirect in C2, so the process
holds no capabilities at all — including no `CAP_NET_BIND_SERVICE`.

`client_ip` always comes from the peer address of the TCP connection, never
from a header, and uvicorn runs with `proxy_headers=False`. That value
decides who gets forwarded.

**Import-graph rule**, extending A4: nothing under `pirewall/portal/` may
import `pirewall.capture`, `pirewall.firewall.backend`, or
`pirewall.firewall.manager`. The core-side portal logic that *does* need
`FirewallManager` lives in `pirewall/ipc/portal_service.py`, outside that
tree, so the rule can hold. Enforced by
`tests/security/test_api_process_isolation.py`, both by AST scan and by a
subprocess probe of what is actually resident.

## C2 — A session is an nftables set element, not a rule

`table inet pirewall_portal` holds `set authed { type ipv4_addr; flags
timeout; }`. A successful sign-in adds one element carrying the session TTL
as its own `timeout`; **the kernel expires it**. There is no timer thread,
no polling loop, no `nft` subprocess firing to log anyone out, and no
per-client rule accumulation. Auto-logout costs nothing at runtime.

Portal elements are deliberately **not** `FirewallRule`s. They never enter
the `RuleStatus` lifecycle, never consume the A3 rate cap, and are never
derived from ML output — they encode "this address signed in", which is
additive and admin-vouched, the opposite of an ML-driven restriction. The
§24 safety properties are about *restrictive* rules being broader than their
evidence; an additive grant scoped to one `/32` inside the protected network
cannot lock anyone out.

They still go through `FirewallManager`, because it holds the only reference
to a `FirewallBackend` (`CLAUDE.md`: "exactly one authorized code path may
deploy to the firewall backend"). `FirewallBackend` gains
`authorize_portal_client` / `deauthorize_portal_client` /
`list_portal_clients`, implemented by both the nftables and Fake backends.

**Chain ordering at the `forward` hook is the whole design:**

```
pirewall_portal / forward   priority -10   (evaluated FIRST)
pirewall        / adaptive  priority   0
pirewall_base   / forward   priority  10
```

Portal gating is a *precondition*, not a threat response. An unauthenticated
client is rejected outright before anything else runs; an authenticated one
falls through **without a verdict** so the adaptive chain still gets its
say. An authenticated device is not a trusted device.

`reject with icmpx admin-prohibited`, not `drop`: a reject makes captive-
portal detection fail immediately and show the sign-in sheet, where a silent
drop leaves the client retransmitting into a black hole — worse for the user
and more work for the Pi.

Established flows `return` before the set is consulted, so a session
expiring mid-download stops the *next* new connection rather than severing
the current one.

**Discovery** uses two mechanisms, neither of which hijacks DNS. DHCP option
114 (RFC 8910) hands modern clients the portal URL in their lease, and a
single nat `prerouting` rule redirects port 80 for everything older. Port
443 is deliberately *not* redirected: intercepting TLS presents a
certificate for the wrong name and produces a security warning instead of a
sign-in page. Hijacking DNS would break DoH/DoT clients, poison caches with
answers that become wrong the moment a client signs in, and require
per-client DNS views dnsmasq cannot express cleanly.

## C3 — The user store, and its single writer

LAN accounts live in `portal.user_store_path`
(`/var/lib/pirewall/portal_users.json`, mode `0600`), holding scrypt hashes
and never a plaintext password. Writes are temp-file-then-`os.replace`, so a
crash or a full disk cannot leave a truncated user file.

**pirewall-core is the only reader and writer.** The portal process never
opens the file — it asks core to verify a credential over the portal socket.
That keeps a single writer, with no two-process race, and makes
allowlist-driven provisioning automatically consistent with what the portal
will accept. `pirewall-portal.service` lists `/var/lib/pirewall` under
`InaccessiblePaths=`.

The file is plain JSON and meant to be hand-editable, with
`scripts/deployment/portal_users.py` as the supported way to edit it without
writing a scrypt hash by hand.

`hash_password`/`verify_password` moved to `pirewall/core/passwords.py` so
`api`, `portal`, core and `scripts` share **one** scrypt implementation —
`CLAUDE.md`'s "one canonical module" rule applied to credentials.
`pirewall.api.auth` re-exports them, since that was their original home.

**Allowlist → account provisioning.** An allowlist entry is a CIDR and a
portal account is a credential, so the mapping is not one-to-one: a gateway
or a printer belongs on the allowlist and can never sign in. The control
panel's allowlist form therefore carries an **optional** `portal_username`.
When filled, an account is provisioned alongside the entry and its generated
password is returned **once**, in that response, for the admin to record. It
is never persisted in readable form, never logged, and never recoverable.
Left empty, behaviour is exactly as before.

**Brute-force protection**, which the admin panel never needed because §29
keeps it Admin-PC-only: a per-source-IP sliding-window failure limiter
(`max_failed_logins_per_ip`, `failed_login_window_seconds`), bounded in both
dimensions. Online password guessing against a login anything on the AP can
reach is cheap, and scrypt alone only slows it down.

## C4 — Telling a blocked client why

When the adaptive pipeline blocks a LAN device, the portal's keepalive poll
answers `status: "blocked"` with a message naming the condition and the
configured `contact_message`, the device is dropped from `@authed`
immediately, and it cannot sign back in while the rule stands — otherwise a
device could log its way out of an adaptive block.

**This works because adaptive rules live on the `forward` hook while the
portal lives on `input`.** The device's internet is gone but the Pi is still
talking to it. That falls out of the existing architecture; the only thing
it required was an explicit `input` accept for the portal port in
`pirewall_base`.

Detection is a scan of `manager.active_rules()` on each poll rather than an
event pushed at the portal: it is stateless, cannot miss a transition, and
costs an `O(active rules)` walk bounded by `firewall.max_active_rules`.

"Targets this client" means a side of the rule **names LAN addresses** and
covers it — `rules_targeting()` requires `network.subnet_of(protected)`, not
mere containment. A plain containment check reads
`source=<other client>/32 destination=0.0.0.0/0` as blocking everybody,
because every address is inside `0.0.0.0/0`, so one misbehaving device would
show the malicious-activity notice to every client on the network. Spec §24
refuses `0.0.0.0/0` today, so the pipeline cannot currently produce that
shape; the predicate is defensive about it anyway, because the cost of being
wrong is telling innocent users their device is infected.

Only `ACTIVE` `BLOCK`/`RATE_LIMIT` rules count. A `SHADOWED` (A1) or
`PENDING_APPROVAL` (A7) rule has not taken effect, and saying otherwise
would be a fabricated claim of enforcement — spec §46 applied to what the
product tells a user.

## C5 — The portal serves plaintext HTTP, deliberately

A self-signed certificate on a captive portal breaks OS captive-portal
detection and trains users to click through certificate warnings. Every
mainstream implementation serves the sign-in page over HTTP for this reason.

**Portal credentials therefore cross the LAN in the clear.** That is why
they are low-value network-access credentials, deliberately distinct from
the admin password, why `docs/SETUP.md` states it plainly, and why the
control panel — which does carry privilege — remains HTTPS-only and
Admin-PC-restricted.

This is a genuine limitation, recorded rather than papered over. A
deployment that needs confidential LAN authentication should terminate that
elsewhere (802.1X/WPA-Enterprise), not by putting a warning-generating
certificate in front of this page.

## C6 — Local console access to the control panel

`admin.allow_local_console` (default **false**) additionally permits
loopback — `127.0.0.0/8` and `::1` — to pass `enforce_admin_pc_ip`, so an
operator at the Pi's own desktop can open the control panel without
widening access to a routable address.

Loopback is the only addition, on purpose: it cannot be reached from any
network, so it grants nothing to a LAN or WAN attacker. Permitting the Pi's
own LAN address would expose the panel to anything that can occupy or spoof
that segment. The check parses the peer address and **fails closed** — a
hostname such as `localhost`, a malformed value, or a missing peer is never
treated as loopback.

---

## What this addendum changed elsewhere

Two latent faults were found while deploying this and are fixed here, both
in code that predates it:

1. **`deploy/firewall/base.nft.template` dropped DHCP.** It accepted the
   server side with `ip saddr ${PROTECTED_NETWORK} udp dport 67`, which
   cannot match a `DHCPDISCOVER` — that arrives from `0.0.0.0`, before the
   client has an address. Under the chain's `policy drop`, no new LAN client
   could ever get a lease, while renewals from already-addressed clients
   kept working, so it would have looked intermittent. It also had no
   `udp dport 68` accept, so the reply to the Pi's *own* WAN lease renewal
   could be dropped and the upstream address lost hours after a deploy that
   looked fine. Both are now interface-scoped accepts, with regression tests.

2. **`StartLimitIntervalSec=`/`StartLimitBurst=` were under `[Service]`** in
   all three unit templates. systemd reads them only in `[Unit]` and
   silently ignores them elsewhere, so the crash-loop bound A6 asks for was
   never actually armed — every unit *looked* like it bounded its own
   restart loop while restarting forever. Moved to `[Unit]`, with a
   section-aware test so a text-only assertion cannot pass over it again.

A third was found on the deployment itself rather than in the repository: a
hand-written `/etc/logrotate.d/pirewall` recreated the log files as a user
neither service runs as, so both daemons had silently lost file logging and
fallen back to stderr. pirewall rotates its own logs via
`RotatingFileHandler`, bounded by `logging.max_bytes`/`backup_count`; a
second rotator is redundant and harmful. `deploy/systemd/pirewall-tmpfiles.conf`
now says so.
