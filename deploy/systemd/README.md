# `deploy/systemd/` — the two-process split (ADDENDUM.md A4)

**Not installed by anything in this repository.** These are template unit
files a human copies to `/etc/systemd/system/`, edits paths/users for their
real deployment, and enables/starts by hand after real hardware testing
(spec §27: "do not apply systemd restrictions that break required
networking functionality without testing").

## Why two units, not one

Spec §45/ADDENDUM.md A4: "a compromised control panel must not
automatically provide unrestricted root access." A single shared process
hardened with systemd flags is still one process with every capability it
was ever granted, for as long as it runs. Splitting into two lets
`pirewall-api` (FastAPI, control panel, all user-facing surface area) run
with **zero** raw-socket/firewall capabilities — not "unused," genuinely
absent from its `CapabilityBoundingSet` — while `pirewall-core` (capture,
firewall manager/backend) holds exactly `CAP_NET_RAW`/`CAP_NET_ADMIN` and is
never directly reachable from the network.

```text
pirewall-api.service                    pirewall-core.service
(FastAPI + control panel)               (capture, flow, features,
  User=pirewall-api                      detection, engine, firewall
  Group=pirewall-api                     manager/backend, RPC server)
  no net/firewall capabilities             User=pirewall-core
        |                                  Group=pirewall-ipc
        | AF_UNIX RPC only                 CAP_NET_RAW, CAP_NET_ADMIN
        v                                        |
  /run/pirewall/core.sock  <--------------------- creates + owns
  (mode 0660, group pirewall-ipc)
```

## Users and groups — the umask/group-ownership approach

Create these before installing the units (exact commands are
distro-specific `useradd`/`groupadd` invocations a human runs on the real
Pi — not run by this repository):

- `pirewall-core` — system user, no login shell, primary group **is the
  shared `pirewall-ipc` group** (not a dedicated `pirewall-core` group).
- `pirewall-api` — system user, no login shell, primary group `pirewall-api`
  (dedicated), plus membership in the shared `pirewall-ipc` group.
- `pirewall-ipc` — the shared group. Membership is the *only* thing that
  lets `pirewall-api` reach the socket `pirewall-core` creates.

Mechanism, concretely:

1. `pirewall-core.service` sets `RuntimeDirectory=pirewall` +
   `RuntimeDirectoryMode=0750`, so systemd creates `/run/pirewall` owned
   `pirewall-core:pirewall-ipc` mode `0750` (owner rwx, group r-x, world
   nothing) before the process starts.
2. `pirewall-core.service` sets `UMask=0117`. Because its primary group
   *is* `pirewall-ipc`, every file/socket it creates — including the RPC
   socket bound inside `/run/pirewall` — is automatically group-owned
   `pirewall-ipc`, and `UMask=0117` makes it mode `0660` (owner rw, group
   rw, world nothing). No application-level `chown`/`chmod` is required.
3. `pirewall-api.service` sets `SupplementaryGroups=pirewall-ipc`. Group
   `r-x` on `/run/pirewall` lets it traverse into the directory (it cannot
   list arbitrary contents by name-guessing alone, but it only ever needs
   the one well-known socket path from `config.api.rpc_socket_path`), and
   group `rw` on the socket file itself lets it connect and exchange RPC
   traffic. It never becomes a member of `pirewall-core`'s primary group
   and never gets any of `pirewall-core`'s capabilities.

This whole chain — real users/groups, real `RuntimeDirectory` behavior,
real socket permission bits — is **Environment-dependent**: it requires a
real Linux host with real systemd and cannot be verified by this
repository's test suite. What *is* verified here:
`pirewall.ipc.server.UnixSocketRpcServer`/`pirewall.ipc.client.UnixSocketRpcClient`
implement the `AF_UNIX` transport itself (Phase 7), and
`tests/security/test_systemd_hardening.py` statically parses both `.service`
files and asserts the directives described above are actually present
(`NoNewPrivileges`, `PrivateTmp`, non-root `User=`, resource limits,
`pirewall-core`'s `Type=notify`+`WatchdogSec=`, and `pirewall-api`'s empty
`CapabilityBoundingSet=`/`AmbientCapabilities=`).

## Entry points these units reference

Both `ExecStart=` lines reference Python entry-point modules
(`pirewall.main`, `pirewall.api.__main__`) that **do not exist yet** in this
repository — see the `NOTE:` comment in each `.service` file and
`docs/PROGRESS.md` Phase 8. Building the actual running main-loop process
(wiring capture → flow → features → detection → engine → firewall manager
into one loop, sending `sd_notify` watchdog heartbeats, serving the RPC
socket) and the API-side equivalent (load config, build a
`UnixSocketRpcClient`, call `pirewall.api.app.create_app`, serve with
uvicorn+TLS) is follow-up implementation work, not something this phase's
explicit deliverable list (deployment *templates* and hardening
*documentation*) asked for. Do not enable either unit until that lands.

## Install steps (human, on real hardware only)

1. Create the users/groups above.
2. Copy both `.service` files to `/etc/systemd/system/`, adjusting
   `ExecStart=`/`WorkingDirectory=`/`ReadWritePaths=`/`ReadOnlyPaths=` paths
   to match where pirewall is actually installed (`/opt/pirewall` here is a
   placeholder, same convention as `deploy/network/`'s `${TOKEN}`
   placeholders — substitute for real).
3. `sudo systemctl daemon-reload`.
4. Start `pirewall-core` first, confirm it reaches an active/healthy state
   (once its entry point exists — see above) and the socket appears at
   `/run/pirewall/core.sock` with the expected `0660 pirewall-core:pirewall-ipc`
   permissions (`ls -l` after start).
5. Start `pirewall-api`, confirm it can reach the socket and serve the
   control panel to a request from `admin.admin_pc_ip`.
6. Confirm `systemctl status pirewall-api` still shows a normal running
   state after deliberately stopping `pirewall-core` (proves the two
   processes are genuinely independent, per ADDENDUM.md A4/A6).
