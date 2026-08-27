# pirewall — Deployment Guide (spec §27, §35, ADDENDUM.md)

Step-by-step for a human deploying pirewall to a real Raspberry Pi 4.
Nothing in this repository runs any of these steps automatically — spec
§21/`CLAUDE.md`: never auto-modify network configuration, systemd state, or
the nftables ruleset during a Claude Code session. Read `docs/SECURITY.md`
alongside this file.

**Before you start:** `pirewall/main.py` (the running main loop for
`pirewall-core`) and `pirewall/api/__main__.py` (the entry point for
`pirewall-api`) do not exist in this repository yet — see
`docs/PROGRESS.md` Phase 8/9. Steps 6-9 below describe the target-state
deployment those entry points are built for; you cannot actually start
either systemd unit until they land. Everything through step 5 (OS setup,
network templates, base firewall ruleset, users/groups) can be done ahead
of that.

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

```sh
sudo apt install nftables python3.12 python3.12-venv
```

`nftables` (not `iptables`) is required — `pirewall.firewall.backend.nftables.NftablesBackend`
talks to the `nft` binary directly via its JSON interface (spec §20).
Install `uv` (https://docs.astral.sh/uv/) for dependency management, or use
`pip`/`venv` directly against the pinned versions in `pyproject.toml`/`uv.lock`.

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
2. Edit `deploy/rendered/dhcpcd-lan.conf` to set the Pi's *own* address
   within the protected network (the renderer fills in the network CIDR
   as a reminder, not a specific host address — see the file's own
   comment), then append it to `/etc/dhcpcd.conf` and restart networking
   (or reboot).
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

```sh
sudo mkdir -p /opt/pirewall/deploy/certificates
sudo chown pirewall-api:pirewall-api /opt/pirewall/deploy/certificates
sudo chmod 700 /opt/pirewall/deploy/certificates
# place cert.pem / key.pem here, mode 600, owned by pirewall-api
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

- **Wazuh**: install the Wazuh agent (or a syslog-compatible collector) on
  the Admin PC, listening on `integration.wazuh_port` (default 1514).
  `pirewall.integration.wazuh.SyslogWazuhTransport` sends one JSON line per
  `SecurityEvent` over a TCP connection to `integration.wazuh_host:wazuh_port`.
  Confirm events appear in Wazuh's event viewer after triggering a test
  detection.
- **Netdata**: install Netdata on the Admin PC with its StatsD collector
  enabled, listening on `integration.netdata_port` (default 8125 — *not*
  Netdata's 19999 dashboard port). `pirewall.integration.netdata.StatsdNetdataTransport`
  sends one UDP StatsD gauge packet per metric to
  `integration.netdata_host:netdata_port`. Confirm the `pirewall.*` charts
  (see `pirewall.integration.netdata.snapshot_to_metrics` for the full
  metric list, including the ADDENDUM.md A3 adaptive-rule-rate metrics)
  appear in Netdata's dashboard.
- Set `integration.wazuh_enabled`/`integration.netdata_enabled = true` in
  `config/local_config.toml` once both are confirmed reachable.

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
