# pirewall — Setup

The ordered, copy-paste path from a blank Raspberry Pi to a running
firewall. Every command here is meant to be run **on the Pi**, from
`/opt/pirewall`, unless it says otherwise.

**How this differs from the other deployment docs**, so you know which one
to open:

| Doc | Use it when |
|---|---|
| **`SETUP.md`** (this file) | You are setting the thing up. Ordered steps, minimal prose. |
| `DEPLOYMENT.md` | You want the *why*: OS choices, hardening rationale, network templates, Wazuh/Netdata specifics, update procedure. |
| `DEPLOYMENT_COMPLETE.md` | You want to know what has actually been verified vs. what only real hardware can confirm. |

Nothing in this repository changes your network configuration, systemd
state, or nftables ruleset on its own (spec §21). Every step below is one
you run deliberately.

---

## 0. Before you start

* **64-bit Raspberry Pi OS Lite** (arm64). Not optional: `numpy`, `scipy`,
  `scikit-learn` and `lightgbm` publish prebuilt wheels for `aarch64` but
  not for 32-bit `armv7l`, and compiling them on the Pi takes hours and
  usually fails for lack of RAM.
* **Two network interfaces**: an uplink (WAN) and the interface facing the
  network you want protected (LAN). **Each side can independently be wired
  or wireless** — see the next section.
* **The LAN side must already be up and addressed** before step 3 — that is
  what setup reads the layout from.

See `DEPLOYMENT.md` §1–§4 for OS setup, packages, installing Python 3.12
via `uv`, and applying the network/NAT templates.

### Bring the two interfaces up — pick one path per side

Independent choices: wired WAN + wireless LAN, wireless WAN + wired LAN, or
either matching pair. pirewall's own code never distinguishes them
(`DEPLOYMENT.md` §4.6), so nothing later in this file changes with your
choice. Bookworm and later: this is `nmcli`, not `/etc/dhcpcd.conf`.

**First, know which interface is which.** With two `wlan`-named interfaces
the name alone does not tell you — `wlan0` is not guaranteed to be the
onboard radio across reboots, since USB probe order decides it:

```sh
ip link show
ethtool -i wlan0        # driver brcmfmac = onboard Pi radio
ethtool -i wlan1        # driver rtl8xxxu (or 8188eu) = RTL8188EUS USB dongle
```

`DEPLOYMENT.md` §4.1 has a `systemd.link` snippet to pin stable names.

**WAN — pick one:**

```sh
# A. Wired: plug into the upstream router, take DHCP. Nothing to configure.
ip addr show "$WAN_IF" && ip route      # confirm an address and a default route

# B. Wireless: associate as a client to the existing Wi-Fi network.
sudo nmcli device wifi connect "<SSID>" password "<PSK>" ifname "$WAN_IF"
ip addr show "$WAN_IF" && ip route      # confirm an address and a default route
```

The Wi-Fi passphrase lives in NetworkManager's own store, not in
`config/local_config.toml` — host configuration, like an SSH host key, not
a pirewall secret.

**LAN — pick one:**

```sh
# A. Wired: static address, no DHCP server (configure clients statically
#    or run your own dnsmasq).
sudo nmcli con add type ethernet ifname "$LAN_IF" con-name pirewall-lan \
    ipv4.method manual ipv4.addresses "$PIREWALL_LAN_IP/$PREFIX" \
    ipv4.never-default yes
sudo nmcli con up pirewall-lan

# B. Wireless AP on a USB dongle. CHECK AP SUPPORT FIRST — "AP" must appear:
iw list | grep -A 12 "Supported interface modes"

sudo nmcli device wifi hotspot ifname "$LAN_IF" con-name pirewall-lan-ap \
    ssid "<your SSID>" password "<WPA2 passphrase, 8+ chars>"
# Required: the hotspot defaults to 10.42.0.1/24 and MUST be moved onto the
# subnet in your config, or pirewall protects an address the Pi lacks.
sudo nmcli connection modify pirewall-lan-ap \
    ipv4.method shared ipv4.addresses "$PIREWALL_LAN_IP/$PREFIX" \
    ipv4.never-default yes 802-11-wireless.band bg \
    wifi-sec.key-mgmt wpa-psk wifi-sec.proto rsn \
    wifi-sec.pairwise ccmp wifi-sec.group ccmp
sudo nmcli connection down pirewall-lan-ap && sudo nmcli connection up pirewall-lan-ap

nmcli device status && ip addr show "$LAN_IF" && iw dev "$LAN_IF" info
# Then connect a real client and confirm it gets a lease in YOUR subnet,
# not 10.42.0.x.
```

If `iw list` does not show `AP` for an RTL8188EUS dongle (USB `0bda:8179`),
or the hotspot starts but drops clients, the in-kernel `rtl8xxxu` driver is
the problem — `DEPLOYMENT.md` §4.4.1 documents replacing it with
<https://github.com/aircrack-ng/rtl8188eus>. That dongle is also 2.4 GHz
802.11b/g/n only (~150 Mbps PHY ceiling).

**Switching later** is a NetworkManager operation only — no pirewall config
or code change:

```sh
sudo nmcli con down <name> && sudo nmcli con delete <name>
# ...then the other path's commands above
uv run python -m scripts.deployment.configure --detect   # confirm the new layout
```

Update `network.*_interface` / `capture.interface` and re-render the
templates only if the interface *name* changed. `DEPLOYMENT.md` §4.6.

## 1. Install pirewall

```sh
sudo mkdir -p /opt/pirewall
sudo chown "$USER" /opt/pirewall
git clone <your-repo-url> /opt/pirewall
cd /opt/pirewall
uv sync --no-dev   # production install, skips pytest/ruff/pyright
```

## 2. Create the service users and log directories

Two separate unprivileged users, per ADDENDUM.md A4 — `pirewall-core` holds
the capture and firewall capabilities, `pirewall-api` holds none at all:

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

`deploy/systemd/README.md` explains why `pirewall-core`'s *primary* group
is the shared `pirewall-ipc` group while `pirewall-api` only holds it as a
supplementary group.

## 3. Generate the configuration

```sh
uv run python -m scripts.deployment.configure
```

This reads your live network layout with `ip` and asks only for what it
cannot observe. Look at the detected values before continuing:

```text
Detected network layout:
  WAN interface      eth0
  Upstream gateway   192.168.1.1
  LAN interface      wlan0   (capture happens here)
  Protected network  192.168.100.0/24
  This Pi's LAN IP   192.168.100.1
  Hosts seen on LAN  192.168.100.10, 192.168.100.23   (candidates only — you choose)
```

**Detected, not asked** — interfaces, the LAN's CIDR, the Pi's own LAN
address, the upstream gateway. Two of these matter more than the rest:
`pirewall_lan_ip` and `upstream_gateway` are the addresses safety
validation refuses to ever block (spec §24), so a typo in either silently
removes the protection that stops pirewall cutting off your own management
access or your whole internet connection. Detecting them removes that
whole class of mistake.

**Asked, never guessed** — the Admin PC and the admin password. "Which
machine may administer this firewall" is a policy decision, not something
the network can answer: the neighbour table only knows which hosts have
recently talked to the Pi. So detected hosts are offered as a numbered
list, and you choose — or type any address, including a machine that is
switched off right now.

To preview without writing anything:

```sh
uv run python -m scripts.deployment.configure --detect
```

The result is `config/local_config.toml`, which is **gitignored** — it
holds your real layout and a password hash, and never leaves the Pi. It is
written only after validating as a real `PirewallConfig`, so setup cannot
leave you with a config the services will refuse.

Editing it by hand afterwards is fine. `--check-config` (step 6) is the
safety net either way.

## 4. Generate the TLS certificate

```sh
scripts/deployment/make_certs.sh 192.168.100.1     # your "This Pi's LAN IP" from step 3
```

Self-signed is appropriate here: the control panel is reachable only from
one Admin PC on a LAN the Pi itself hosts, and there is no public name for
a CA to attest to. The script puts that IP in the certificate's
`subjectAltName`, which is what clients actually verify — a certificate
with only a Common Name fails verification even after you click through the
warning.

Then hand the key to the API user:

```sh
sudo chown pirewall-api:pirewall-api deploy/certificates/pirewall.{crt,key}
sudo chmod 600 deploy/certificates/pirewall.key
```

## 5. Render and apply the network/firewall templates

```sh
uv run python -m scripts.deployment.render_templates --config config/local_config.toml
ls deploy/rendered/
```

**Read every rendered file before applying it.** These are the ones that
change your host's networking; `DEPLOYMENT.md` §4 walks through applying
them.

## 6. Check the configuration before starting anything

```sh
uv run python -m pirewall.main --check-config    # config shape and values
uv run python -m pirewall.api  --check-config    # the above, plus credentials and TLS material
```

Both validate and exit without binding a socket or opening a capture
handle. Run these after every config change — far faster than diagnosing a
failed unit.

## 7. Install and start the services

```sh
sudo cp deploy/systemd/pirewall-core.service deploy/systemd/pirewall-api.service \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pirewall-core.service
systemctl status pirewall-core.service
ls -l /run/pirewall/core.sock          # expect: srw-rw---- pirewall-core pirewall-ipc
```

Only once `pirewall-core` is healthy:

```sh
sudo systemctl enable --now pirewall-api.service
systemctl status pirewall-api.service
```

## 8. Confirm it works, from the Admin PC

```sh
curl --insecure https://192.168.100.1:8443/api/v1/health

TOKEN=$(curl --insecure -s -X POST https://192.168.100.1:8443/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<your password>"}' | jq -r .token)

curl --insecure https://192.168.100.1:8443/api/v1/status        -H "Authorization: Bearer $TOKEN"
curl --insecure https://192.168.100.1:8443/api/v1/capture-stats -H "Authorization: Bearer $TOKEN"
```

Then open `https://192.168.100.1:8443/control-panel` in a browser and
accept the self-signed certificate once.

Two things to confirm explicitly:

* **`capture-stats` is counting packets.** If `packets_seen` stays at zero,
  or `journalctl -u pirewall-core` shows a `capture_error` at startup,
  pirewall is running but not seeing traffic — check `capture.interface`
  and that `pirewall-core` has `CAP_NET_RAW`.
* **The restriction actually restricts.** From any *other* host on the LAN,
  the same `curl` must be refused with 403.

## 9. Go live gradually

`firewall.enforcement_mode` starts at `shadow` (ADDENDUM.md A1) — pirewall
watches, scores, and records what it *would* do, and enforces nothing.
Leave it there until the control panel's decisions look right to you.

```text
shadow  ->  assisted  ->  active
```

* `assisted` — high-confidence BLOCKs wait in an approval queue for you
  (A7); everything else deploys.
* `active` — deploys without asking.

Edit `firewall.enforcement_mode` in `config/local_config.toml`, then
`sudo systemctl restart pirewall-core`.

If something goes wrong, the kill-switch (A8) reverts every adaptive rule:

```sh
curl --insecure -X POST https://192.168.100.1:8443/api/v1/firewall/kill-switch \
  -H "Authorization: Bearer $TOKEN"
```

---

## Changing the Admin PC

This is the command you want if your admin machine moves, gets a new
address, or you want to hand administration to a different host:

```sh
uv run python -m scripts.deployment.configure --set-admin-pc
```

It re-scans the LAN, shows you the candidates, and lets you pick one or
type an address. To do it without prompts (a script, or when the new
machine is not on the network yet):

```sh
uv run python -m scripts.deployment.configure --set-admin-pc --admin-pc-ip 192.168.100.50
```

Then:

```sh
sudo systemctl restart pirewall-api
```

It is a **targeted edit** — every comment and any threshold you have tuned
by hand survives. Three things change together, because leaving any of them
behind would be a bug:

| Value | Why it follows |
|---|---|
| `admin.admin_pc_ip` | The access restriction itself (spec §29). |
| The Admin PC allowlist entry | ADDENDUM.md A2 — otherwise it keeps exempting a machine that is no longer your Admin PC. |
| `integration.wazuh_host` / `netdata_host` | Only if they still point at the *old* Admin PC. If you aimed them at a dedicated box, they are left alone. |

**Read this before you run it:** the moment `pirewall-api` restarts, the old
address can no longer reach the control panel or the API. If you get the new
address wrong you will have locked yourself out of the web interface — the
fix is SSH to the Pi and run the command again with the right address.
Nothing is lost, but you need SSH access to recover.

## Changing the admin password

```sh
uv run python -m scripts.deployment.configure --set-password
sudo systemctl restart pirewall-api
```

The plaintext is never written anywhere; only the scrypt hash goes into the
config. Existing sessions stay valid until they expire — log out to
invalidate yours immediately.

## Everything else

Any other setting is edited directly in `config/local_config.toml`, then:

```sh
uv run python -m pirewall.main --check-config
sudo systemctl restart pirewall-core     # and pirewall-api if you changed [api] or [authentication]
```

There is deliberately **no way to change configuration through the control
panel**. `GET /api/v1/config` shows the running configuration (with the
password hash and TLS paths redacted) and has no write counterpart: a
control panel that could rewrite `enforcement_mode` or `admin_pc_ip` over
HTTP would make one stolen session equivalent to owning the firewall
(spec §45).

## Troubleshooting

| Symptom | Where to look |
|---|---|
| `pirewall-core` won't start | `journalctl -u pirewall-core -n 50`, then `--check-config`. |
| `pirewall-api` won't start | Almost always TLS material or a `CHANGE_ME` credential — `--check-config` names the exact problem. |
| Control panel says "core unreachable" | `pirewall-core` is down or the socket is missing. That page is expected behaviour, not a crash (ADDENDUM.md A6) — `systemctl status pirewall-core`. |
| 403 from the Admin PC | `admin.admin_pc_ip` doesn't match the address you're connecting from. Check with `ip -j neigh show` on the Pi, then `--set-admin-pc`. |
| `capture_error` at startup | `capture.interface` is wrong or `CAP_NET_RAW` is missing. Compare against `--detect`. |
| No threats ever detected | Expected without trained models — pirewall runs behaviour-only detection and says so at startup. See `docs/ML_PIPELINE.md`. |
