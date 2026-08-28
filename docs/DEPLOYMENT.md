# pirewall — Deployment Guide (spec §27, §35, ADDENDUM.md)

Step-by-step for a human deploying pirewall to a real Raspberry Pi 4.
Nothing in this repository runs any of these steps automatically — spec
§21/`CLAUDE.md`: never auto-modify network configuration, systemd state, or
the nftables ruleset during a Claude Code session. Read `docs/SECURITY.md`
alongside this file.

**Before you start:** both entry points now exist — `pirewall/main.py`
(`pirewall-core`) and `pirewall/api/__main__.py` (`pirewall-api`, run as
`python -m pirewall.api`) — so every step below is executable end to end.
What has *not* been verified is the Pi-specific half: `AF_PACKET` capture
on a real interface, `nft` against a real ruleset, and systemd supervision
itself. `docs/DEPLOYMENT_COMPLETE.md` lists exactly what was verified, how,
and what you need to check on the hardware.

Both entry points accept `--check-config`, which validates everything they
can without binding a socket or opening a capture handle. Run it after
every configuration change — it is much faster than diagnosing a failed
unit:

```sh
python -m pirewall.main --check-config    # config shape and values
python -m pirewall.api  --check-config    # the above, plus credentials and TLS material
```

**For the short version**, see `docs/SETUP.md` — the same steps as ordered
commands with minimal prose. This file is the reasoning behind them. In
particular, steps 3 and 6 below are now largely automated:

```sh
uv run python -m scripts.deployment.configure     # writes config/local_config.toml
scripts/deployment/make_certs.sh <pi-lan-ip>      # writes the TLS pair
```

## 1. OS setup

1. Flash the current 64-bit Raspberry Pi OS Lite (headless, no desktop
   environment — pirewall is a dedicated gateway appliance) to the Pi's
   storage.
2. Boot, set a strong password or (preferred) disable password auth
   entirely in favor of SSH keys from first boot (`raspi-config` or the
   Raspberry Pi Imager's advanced options can pre-seed this).
3. `sudo apt update && sudo apt full-upgrade`, then reboot.
4. Confirm your two NICs (or one NIC + USB Ethernet adapter, a common Pi 4
   gateway setup) and note their real interface names: `ip link show`.
   These are what `network.wan_interface`/`network.lan_interface` must
   match exactly — do not guess or reuse the placeholder `eth0`/`eth1` from
   `config/default_config.toml`.

## 2. Required packages

**Use the 64-bit (arm64) Raspberry Pi OS image.** This is not optional:
`numpy`, `scipy`, `scikit-learn`, and `lightgbm` publish prebuilt
`manylinux` wheels for `aarch64` but not for 32-bit `armv7l`. On a 32-bit
image pip would fall back to compiling them from source on the Pi, which
takes hours and frequently fails for lack of RAM.

```sh
sudo apt update && sudo apt install nftables
```

`nftables` (not `iptables`) is required —
`pirewall.firewall.backend.nftables.NftablesBackend` talks to the `nft`
binary directly via its JSON interface (spec §20).

### Python 3.12+ — do not use `apt` for this

pirewall requires Python **3.12 or newer** (`pyproject.toml`), and the
`numpy`/`scipy` versions it pins ship `aarch64` wheels only for CPython
3.12+. Raspberry Pi OS Bookworm is Debian 12, which ships **Python 3.11**
and has no `python3.12` package — `apt install python3.12` fails outright.

Install `uv`, and let it manage the interpreter:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh   # aarch64 Linux build published upstream
source "$HOME/.local/bin/env"
uv python install 3.12                            # standalone build, no apt involved
```

This is the same mechanism used on the development machine, so the Pi runs
the interpreter version the project is actually tested against rather than
whatever the distro happens to ship. (If you are on a Trixie-based image,
its system Python is 3.13 and would also satisfy the requirement — but
using `uv`'s pinned interpreter everywhere keeps dev and Pi identical.)

## 3. Install pirewall

```sh
sudo mkdir -p /opt/pirewall
sudo chown "$USER" /opt/pirewall
git clone <your-repo-url> /opt/pirewall   # or copy a release tarball
cd /opt/pirewall
uv sync --no-dev   # production install, skips pytest/ruff/pyright
```

Copy `config/default_config.toml` to `config/local_config.toml` and fill in
every `CHANGE_ME` with your real values: interface names (step 1.4), your
protected network CIDR, upstream gateway, the Pi's own LAN address
(`pirewall_lan_ip` — safety validation refuses to ever block it, so it must
be accurate), Admin PC IP, and TLS cert/key paths.

Generate `admin_password_hash` with pirewall's own hasher — never
hand-write one, and never put the plaintext in the file:

```sh
uv run python -c "from pirewall.api.auth import hash_password; \
    import getpass; print(hash_password(getpass.getpass()))"
```

**Never commit `config/local_config.toml`.**

## 4. Render and apply the network templates

```sh
uv run python -m scripts.deployment.render_templates --config config/local_config.toml
```

This writes substituted files to `deploy/rendered/` — review every one
before applying it by hand:

1. `sudo cp deploy/rendered/60-pirewall-forwarding.conf /etc/sysctl.d/60-pirewall-forwarding.conf && sudo sysctl --system`
2. Give the LAN interface its static address — the value you set as
   `network.pirewall_lan_ip`. **Raspberry Pi OS Bookworm and later use
   NetworkManager**, so this is `nmcli`, not `/etc/dhcpcd.conf`:

   ```sh
   sudo nmcli con add type ethernet ifname "$LAN_IF" con-name pirewall-lan \
       ipv4.method manual \
       ipv4.addresses "$PIREWALL_LAN_IP/$PREFIX" \
       ipv4.never-default yes          # the LAN side is not our default route
   sudo nmcli con up pirewall-lan
   ```

   `ipv4.never-default yes` matters: the Pi's own default route must stay
   on the WAN side (toward `network.upstream_gateway`). Leave the WAN
   interface on DHCP from the home router unless your setup needs
   otherwise. Verify with `ip addr show "$LAN_IF"` and `ip route`.

   Only on Bullseye or older (which predate the NetworkManager switch) use
   `deploy/rendered/dhcpcd-lan.conf`, appended to `/etc/dhcpcd.conf`.
3. `sudo nft -c -f deploy/firewall/base.nft.template` to check syntax
   (note: this file has no config tokens needing rendering beyond what's
   already substituted the same way — confirm the rendered copy in
   `deploy/rendered/base.nft` if you rendered it), then
   `sudo nft -f deploy/rendered/base.nft` to load it for real.
4. `sudo nft -f deploy/rendered/nat-masquerade.nft` to load NAT.
5. Confirm forwarding actually works from a test LAN client before
   proceeding (e.g. `ping` and a real outbound connection through the Pi).

See `deploy/network/README.md` and `deploy/firewall/README.md` for the full
rationale behind each template and the load order.

## 5. Create service users/groups

```sh
sudo groupadd --system pirewall-ipc
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
  --gid pirewall-ipc pirewall-core
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
  --user-group -G pirewall-ipc pirewall-api
sudo mkdir -p /var/log/pirewall /var/log/pirewall-api
sudo chown pirewall-core:pirewall-ipc /var/log/pirewall
sudo chown pirewall-api:pirewall-api /var/log/pirewall-api
```

See `deploy/systemd/README.md` for exactly why `pirewall-core`'s primary
group is the shared `pirewall-ipc` group and `pirewall-api` only holds it
as a supplementary group.

## 6. Certificates

Generate a TLS certificate/key for the control panel/API
(`api.tls_cert_path`/`tls_key_path`). A private CA or a Let's Encrypt
certificate both work if the Pi has a resolvable name; a self-signed
certificate is acceptable for a LAN-only admin panel restricted to one
Admin PC. Whichever you choose:

For a self-signed pair, use the script in this repository rather than a
hand-written `openssl` command. It sets the `subjectAltName` to the Pi's
LAN IP, which is what modern clients actually verify (a certificate with
only a Common Name fails verification even after you accept the warning),
and it generates an EC P-256 key rather than RSA-4096 — near-instant on a
Pi 4 instead of tens of seconds, cheaper to handshake, and supported by
every TLS 1.3 client:

```sh
scripts/deployment/make_certs.sh 192.168.100.1   # your network.pirewall_lan_ip
sudo mkdir -p /opt/pirewall/deploy/certificates
sudo chown pirewall-api:pirewall-api /opt/pirewall/deploy/certificates
sudo chmod 700 /opt/pirewall/deploy/certificates
# then place pirewall.crt / pirewall.key here, key mode 600, owned by pirewall-api
```

Confirm pirewall-api accepts them before enabling the unit — it refuses to
start on a missing, unreadable, or still-placeholder certificate path:

```sh
python -m pirewall.api --check-config
```

Never commit the real cert/key. `min_tls_version = "TLSv1.3"` is the
config default (`config.security.min_tls_version`) — don't lower it without
a specific reason.

## 7. Install and start systemd units

```sh
sudo cp deploy/systemd/pirewall-core.service deploy/systemd/pirewall-api.service \
  /etc/systemd/system/
# edit ExecStart=/WorkingDirectory=/ReadWritePaths=/ReadOnlyPaths= if you
# installed pirewall somewhere other than /opt/pirewall
sudo systemctl daemon-reload
sudo systemctl enable --now pirewall-core.service
```

Confirm before proceeding:

```sh
sudo systemctl status pirewall-core.service
ls -l /run/pirewall/core.sock   # expect: srw-rw---- pirewall-core pirewall-ipc
```

Then:

```sh
sudo systemctl enable --now pirewall-api.service
sudo systemctl status pirewall-api.service
```

From the Admin PC (and only from the Admin PC — confirm a request from any
other host is refused): `curl -v https://<pi-lan-ip>:8443/api/v1/health`.

## 8. Admin PC-side Wazuh/Netdata configuration

The Admin PC is any Linux box on the protected LAN — this repository
assumes nothing about its distribution. Both integrations are plain network
protocols (TCP syslog, UDP StatsD), so anything that speaks them works. The
notes below flag where distro packaging differs, since an Arch-based Admin
PC (Omarchy and friends) is a common choice and Wazuh does not publish
official Arch packages.

- **Wazuh** — pirewall is **not** a Wazuh agent and deliberately does not
  install one (that would add another privileged daemon to the enforcement
  box, against spec §45). It forwards to the Wazuh server's **remote
  syslog collector**, which needs two things done explicitly:

  1. **Use port 514, not 1514.** 1514 is the agent connection service,
     which speaks Wazuh's AES-encrypted, enrollment-authenticated agent
     protocol; plain JSON sent there is not ingested. `integration.wazuh_port`
     now defaults to `514` for this reason.
  2. **Enable the collector and allow the Pi.** It is disabled by default.
     In the manager's `ossec.conf`:

     ```xml
     <remote>
       <connection>syslog</connection>
       <port>514</port>
       <protocol>tcp</protocol>
       <allowed-ips>PI_LAN_IP/32</allowed-ips>
     </remote>
     ```

     then restart the manager. Without `allowed-ips` covering the Pi, the
     connection is refused.

  `pirewall.integration.wazuh.SyslogWazuhTransport` then sends one JSON
  object per line per `SecurityEvent` to `wazuh_host:wazuh_port`. Confirm
  events arrive after triggering a test detection — check the manager's
  `archives.log`/alerts rather than assuming, since a silently refused
  connection looks identical to "no events yet" from the Pi's side.

  *On Arch/Omarchy*: Wazuh has no official Arch package; it is available
  via AUR, or run the manager in Docker/Podman (the official
  `wazuh/wazuh-manager` image), which sidesteps packaging entirely and is
  the lower-maintenance option for a single-host lab. Either way, publish
  514/tcp and apply the `<remote>` block above.

- **Netdata**: enable its StatsD collector, listening on
  `integration.netdata_port` (default 8125 — *not* Netdata's 19999
  dashboard port). `pirewall.integration.netdata.StatsdNetdataTransport`
  sends one UDP StatsD gauge packet per metric to
  `integration.netdata_host:netdata_port`. Confirm the `pirewall.*` charts
  (see `pirewall.integration.netdata.snapshot_to_metrics` for the full
  metric list, including the ADDENDUM.md A3 adaptive-rule-rate metrics)
  appear in the dashboard. Note StatsD is UDP and therefore silent on
  failure — absence of charts is the only symptom of a wrong host/port.

  *On Arch/Omarchy*: `pacman -S netdata` packages it directly, or use
  Netdata's official kickstart script. StatsD is built in; no plugin
  install is needed, only enabling it.

- Set `integration.wazuh_enabled`/`integration.netdata_enabled = true` in
  `config/local_config.toml` once both are confirmed reachable — they
  default to `false` precisely so a misconfigured endpoint cannot cause
  errors on a first deployment.

## 8b. Raspberry Pi 4 (4 GB) sizing notes

Measured on the development machine, not on a Pi — treat as budgeting
input, and re-measure on the target with
`scripts/diagnostics/performance_smoke.py` (spec §40, §46).

**Memory — comfortable.** A full flow table at the default
`flow.max_flows = 100000` measures ~93 MiB of Python objects (~979 bytes
per tracked flow). Add the ML stack resident (numpy/scipy/scikit-learn/
lightgbm, roughly 200–250 MiB) and the interpreter, and `pirewall-core`
sits well inside the `MemoryMax=768M` its unit sets, which in turn leaves
most of a 4 GB Pi free. `pirewall-api` is capped at 256M and does no
packet-rate work. No tuning needed for 4 GB.

**Inference throughput — the real constraint.** Anomaly scoring currently
runs one flow per `IsolationForest.decision_function` call, and at
`n_estimators=100` that measures ~15.6 ms/call on x86 — almost entirely
scikit-learn's fixed per-call overhead, not tree traversal. The same
forest scoring a batch of 200 costs ~0.088 ms/flow, a ~178× difference.

That puts single-flow scoring at roughly 64 flows/sec on a fast x86
laptop, so plausibly **~10–20 flows/sec on a Pi 4's Cortex-A72**. A busy
household can complete more flows than that, in which case anomaly
scoring becomes the pipeline's bottleneck. Mitigations, cheapest first:

1. Retrain with fewer trees — `--n-estimators 25` measured ~4.3 ms/call,
   a 3.6× improvement, at some detection-quality cost.
2. Score flows in batches rather than one at a time. This is the real
   fix (two orders of magnitude) but changes the shape of the detection
   layer's inference call, so it is recorded as an open design item in
   `docs/PROGRESS.md` rather than done implicitly.

Neither is required for a **SHADOW**-mode first deployment (ADDENDUM.md
A1), where falling behind delays observations but enforces nothing —
which is another reason to run SHADOW for the recommended 1–2 weeks and
watch `pirewall.inference_latency_ms` in Netdata before enabling
enforcement.

## 9. Secure update procedure

Per spec §27 "Updates," document and follow this order — never skip
straight to restarting services with unreviewed changes:

1. **Raspberry Pi OS**: `sudo apt update && sudo apt upgrade`, review
   what changed for anything network-stack-related before rebooting.
2. **Python dependencies**: update `uv.lock` on a development machine
   (`uv lock --upgrade`), run the full test suite + `ruff check .` +
   `pyright --strict` there first, then `uv sync --no-dev` on the Pi from
   the updated lockfile — never `pip install --upgrade` ad hoc on the Pi
   itself.
3. **pirewall itself**: `git pull` (or deploy a new reviewed release) on
   a development machine first, run the full Definition of Done checks
   (`CLAUDE.md`), then deploy to the Pi and `sudo systemctl restart
   pirewall-core pirewall-api`. Because of ADDENDUM.md A4, restarting one
   doesn't require restarting the other.
4. **ML artifacts**: retrain following `docs/ML_PIPELINE.md` (Phase 9), then
   copy the new `pirewall/ml/artifacts/*.{txt,joblib}` + metadata to the
   Pi and restart `pirewall-core`. `pirewall.ml.inference.loader` refuses
   to load a model whose feature schema doesn't match at load time (Phase
   5, tested) — a bad artifact fails loudly at restart, not silently at
   inference time.

## 10. What's still Environment-dependent after all of the above

See `docs/SECURITY.md` §3 and `docs/PROGRESS.md` Phase 8 for the complete,
itemized list. In short: every step in this document that involves a real
`nft`/`sysctl`/`systemctl`/real network hardware has not been executed by
this repository's automated tests — they can't be, without a real Pi. What
*is* tested is the payload/template/config-shaping logic that feeds into
each step (see `docs/SECURITY.md` §3's Tested list).
