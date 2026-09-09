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

> **Setting up on a new network for the first time?** `setup-new-network.md`
> in the repository root is the same path as a pure command runbook — every
> command in order, plus the Admin PC side (Wazuh and Netdata, with and
> without Docker) and how to move an existing Pi to a different network.
> This file is that path with the reasoning attached; read it when something
> here fails or you want to know why a step exists.

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

## 5–10 in one command: `pirewall-start`

Once steps 0–4 are done (config generated, TLS certificate created), the
remaining bring-up is scripted. It is idempotent — safe to re-run any time,
including after a failed attempt:

```sh
sudo scripts/deployment/pirewall-start --check    # preflight only, changes nothing
scripts/deployment/pirewall-start --dry-run       # print every command, run none
sudo scripts/deployment/pirewall-start            # do it
```

It snapshots the current ruleset to `deploy/rollback/` before touching
anything, creates the service accounts and directories, renders and
syntax-checks every ruleset before loading it, installs and starts the three
units in dependency order, and verifies the result. It prints the rollback
commands when it finishes.

It deliberately never generates configuration or TLS material: both need
answers it cannot invent, and `configure.py` refuses to guess the Admin PC
address or the admin password on purpose.

Two ordering constraints it enforces, both of which cost real debugging to
find: `pirewall-core` starts before `pirewall-portal` because core creates
the portal's RPC socket, and the captive-portal nft table loads only after
the sign-in page is confirmed serving — loading it earlier gates the whole
protected network with nowhere to sign in.

`--no-portal` brings up core and api only. `--skip-nft` leaves the ruleset
alone.

The rest of this section documents what the script does, for when you want
to run a step by hand or understand a failure.

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

## 10. Turn on the LAN captive portal (optional)

Makes every device that joins the AP sign in before its traffic is
forwarded, and gives a device the adaptive pipeline blocks a page explaining
why (`docs/ADDENDUM_3.md`).

**Nothing is gated until all three pieces are in place.** Enabling
`portal.enabled` without loading the ruleset and starting the service means
LAN clients are gated with no page to sign in on. Do these in order.

### 10.1 Service account, groups, directories

The portal runs as its own user, in its **own** IPC group. It must never be
in `pirewall-ipc`: that group reaches the privileged socket carrying the
kill switch and every rule mutation.

```sh
sudo groupadd --system pirewall-portal-ipc
sudo groupadd --system pirewall-portal
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
     -g pirewall-portal -G pirewall-portal-ipc pirewall-portal

# pirewall-core serves both sockets, so it needs to be in the portal group too
sudo usermod -a -G pirewall-portal-ipc pirewall-core

# Directories, modes, and the setgid bit that gives the portal socket its group
sudo cp deploy/systemd/pirewall-tmpfiles.conf /etc/tmpfiles.d/pirewall.conf
sudo systemd-tmpfiles --create
```

Confirm the groups came out right — this is the privilege boundary:

```sh
id pirewall-portal   # must NOT list pirewall-ipc
id pirewall-api      # must NOT list pirewall-portal-ipc
ls -ld /run/pirewall-portal   # must be drwxr-s--- ... pirewall-portal-ipc
```

### 10.2 Configure

In `config/local_config.toml`:

```toml
[portal]
enabled = true
network_name = "pirewall-lan"        # your SSID; cosmetic
listen_host = "192.168.100.1"        # must equal network.pirewall_lan_ip
listen_port = 8080                   # unprivileged; port 80 is redirected here
session_timeout_seconds = 1800
```

```sh
uv run python -m pirewall.portal --check-config
```

### 10.3 Create LAN accounts

```sh
sudo -u pirewall-core uv run python -m scripts.deployment.portal_users add alice
sudo -u pirewall-core uv run python -m scripts.deployment.portal_users list
```

`add` and `passwd` prompt twice and never echo; only the scrypt hash is
stored. Accounts can also be created from the control panel, including
alongside an allowlist entry.

See **[The five demo accounts](#the-five-demo-accounts)** below before going
anywhere near production.

### 10.4 Portal discovery for clients

```sh
uv run python -m scripts.deployment.render_templates --config config/local_config.toml
sudo cp deploy/rendered/dnsmasq-portal.conf \
        /etc/NetworkManager/dnsmasq-shared.d/pirewall-portal.conf
sudo nmcli connection down pirewall-lan-ap && sudo nmcli connection up pirewall-lan-ap
```

This hands clients the portal URL in their DHCP lease (RFC 8910 option 114),
so modern iOS/Android/Windows open the sign-in page by themselves. Older
clients are caught by the port-80 redirect in the next step. It works only
if NetworkManager's `shared` mode is providing DHCP — confirm with
`pgrep -a dnsmasq | grep conf-dir`.

DNS is deliberately **not** hijacked; see ADDENDUM_3.md C2 for why.

### 10.5 Start the service, then load the gate

Order matters: bring the portal up *before* gating forwarding, or clients
lose the network with nowhere to sign in.

```sh
sudo cp deploy/systemd/pirewall-portal.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart pirewall-core          # opens the second RPC socket
sudo systemctl enable --now pirewall-portal
systemctl is-active pirewall-core pirewall-portal

# only now: the gate
sudo nft -c -f deploy/rendered/portal.nft && sudo nft -f deploy/rendered/portal.nft
```

### 10.6 Verify

```sh
curl -s http://192.168.100.1:8080/portal | grep 'Sign in'
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://192.168.100.1:8080/generate_204
sudo nft list set inet pirewall_portal authed        # empty until someone signs in
```

Then from a phone: join the SSID, confirm the sign-in page appears by
itself, confirm the internet is refused before signing in, sign in, confirm
it works, and watch the countdown on the keepalive page.

### Rolling the portal back

```sh
sudo nft delete table inet pirewall_portal      # ungates forwarding immediately
sudo systemctl disable --now pirewall-portal
sudo rm /etc/NetworkManager/dnsmasq-shared.d/pirewall-portal.conf
sudo nmcli connection down pirewall-lan-ap && sudo nmcli connection up pirewall-lan-ap
```

Then set `portal.enabled = false` and restart `pirewall-core`. Deleting the
table alone is enough to restore forwarding in an emergency.

## The five demo accounts

`seed-demo` creates five accounts so you can prove the portal works before
provisioning anyone real:

```sh
sudo -u pirewall-core uv run python -m scripts.deployment.portal_users \
     seed-demo --i-understand-these-are-insecure
```

| Username | Password |
|---|---|
| `demo-alice` | `pirewall-demo-1` |
| `demo-bob` | `pirewall-demo-2` |
| `demo-carol` | `pirewall-demo-3` |
| `demo-dave` | `pirewall-demo-4` |
| `demo-erin` | `pirewall-demo-5` |

> ### ⚠ Delete these before production
>
> **These passwords are published — they are printed in this file, in the
> repository, and in the script's source.** They are fixed and non-secret on
> purpose: a *generated* password written into a git-tracked document would
> be a committed credential. Anyone who can read this repository, or who has
> simply seen it, can join your protected network while they exist.
>
> ```sh
> for u in demo-alice demo-bob demo-carol demo-dave demo-erin; do
>   sudo -u pirewall-core uv run python -m scripts.deployment.portal_users remove "$u"
> done
> ```
>
> While any of them exists, pirewall tells you so in three places: a
> `SYSTEM_WARNING` event at every `pirewall-core` startup, a banner on the
> sign-in page, and a red notice on the control panel's portal panel. If you
> see those, this step has not been done.

**Portal credentials cross the LAN in the clear.** The sign-in page is plain
HTTP, because a self-signed certificate breaks captive-portal detection and
trains users to click through certificate warnings (ADDENDUM_3.md C5). Treat
these as network-access credentials, keep them distinct from the admin
password, and do not reuse a password from anywhere else. The control panel,
which does carry privilege, stays HTTPS-only and Admin-PC-restricted.

## Opening the control panel from the Pi's own desktop

`security.restrict_to_admin_pc` means `https://127.0.0.1:8443` returns 403
on the Pi itself. To allow the local console as well:

```toml
[admin]
allow_local_console = true
```

```sh
sudo systemctl restart pirewall-api
chromium https://127.0.0.1:8443/control-panel/login
```

This permits **loopback only** — never a routable address. Loopback cannot
be reached from any network, so it grants nothing to the LAN or the WAN,
whereas permitting the Pi's LAN address would expose the panel to anything
that can occupy that segment. The certificate is self-signed, so the browser
will warn once.

## Wazuh and Netdata

pirewall does **not** run a Wazuh agent on the enforcement box (spec §45 —
fewer privileged daemons on the machine holding `CAP_NET_ADMIN`). It
forwards its own JSON security events to the Wazuh **manager** over TCP
syslog, and its own metrics to Netdata over StatsD:

```toml
[integration]
wazuh_enabled = true
wazuh_host = "192.168.101.2"   # the Admin PC
wazuh_port = 514               # remote syslog collector, NOT 1514 (agent enrollment)
netdata_enabled = true
netdata_host = "192.168.101.2"
netdata_port = 8125            # StatsD, NOT 19999 (the dashboard)
```

Both run **on the Admin PC**, not on the Pi. Netdata on a Pi costs
100–250 MB resident plus continuous SD-card writes; the Pi only emits UDP
datagrams, which costs essentially nothing.

> **Kali users: you need Docker.** Wazuh publishes no Kali packages, and its
> Debian repository targets Debian/Ubuntu releases Kali does not track. Use
> the container path below. Netdata has a Kali package but the container
> path works there too.

### Wazuh manager — with Docker

The single-node stack (manager + indexer + dashboard). Budget **at least
6 GB RAM and 4 CPU cores** — this does not belong on the Pi.

```sh
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.0
cd wazuh-docker/single-node

# Required: the indexer will not start without it
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf

docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d

docker compose ps
```

Dashboard: `https://<admin-pc>:443` — default `admin` / `SecretPassword`,
**change it immediately** in `docker-compose.yml` and `config/wazuh_indexer/`.

### Wazuh manager — without Docker

Debian/Ubuntu, from the official repository:

```sh
curl -sO https://packages.wazuh.com/key/GPG-KEY-WAZUH
sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg \
     --import GPG-KEY-WAZUH
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update && sudo apt install -y wazuh-manager
sudo systemctl enable --now wazuh-manager
```

Arch/Omarchy has no official package and no maintained AUR one — use Docker.

### Enable the syslog collector (required either way)

pirewall sends plain JSON lines, so the manager must accept **remote
syslog**. Without this block the Pi's events are silently discarded, and a
refused connection is indistinguishable from "no events yet" from the Pi's
side. In `/var/ossec/etc/ossec.conf` (or the container's mounted copy):

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>192.168.101.0/24</allowed-ips>
</remote>
```

Restart the manager, then confirm from the Pi:

```sh
nc -zv 192.168.101.2 514
journalctl -u pirewall-core | grep -i wazuh    # no "Connection refused"
```

### Netdata — with Docker

```sh
docker run -d --name=netdata --restart=unless-stopped \
  -p 19999:19999 -p 8125:8125/udp \
  -v netdataconfig:/etc/netdata \
  -v netdatalib:/var/lib/netdata \
  -v netdatacache:/var/cache/netdata \
  -v /etc/passwd:/host/etc/passwd:ro -v /etc/group:/host/etc/group:ro \
  -v /proc:/host/proc:ro -v /sys:/host/sys:ro -v /etc/os-release:/host/etc/os-release:ro \
  --cap-add SYS_PTRACE --security-opt apparmor=unconfined \
  netdata/netdata
```

Note `-p 8125:8125/udp` — without it the Pi's metrics never arrive.

### Netdata — without Docker

```sh
# Arch / Omarchy
sudo pacman -S netdata && sudo systemctl enable --now netdata

# Debian / Ubuntu / Kali
sudo apt install -y netdata && sudo systemctl enable --now netdata

# Or the upstream installer, for a newer build than your distro ships
wget -O /tmp/kickstart.sh https://get.netdata.cloud/kickstart.sh && sh /tmp/kickstart.sh
```

Then make the StatsD listener reachable from the Pi. In
`/etc/netdata/netdata.conf`:

```ini
[statsd]
    enabled = yes
    bind to = udp:0.0.0.0:8125
```

```sh
sudo systemctl restart netdata
ss -lunp | grep 8125            # on the Admin PC
```

Dashboard: `http://<admin-pc>:19999`. pirewall's metrics appear under the
`pirewall_*` StatsD charts once `pirewall-core` has run for a minute.

### If you want them on the Pi anyway

Supported, but measure first. Netdata's defaults are expensive on an SD
card; at minimum set `[db] mode = ram` and disable collectors you do not
need. A Wazuh agent on the enforcement box contradicts spec §45 and its
`syscheck` FIM scans are the heaviest recurring disk I/O the Pi will see —
if you install one anyway, widen `<frequency>` and narrow `<directories>`.

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
| LAN clients get no DHCP lease | The base ruleset must accept DHCP by *interface* (`iifname "<lan>" udp dport 67`), not by source address — a DISCOVER comes from `0.0.0.0`. Re-render the template if yours predates that fix. |
| Pi loses its WAN address after a while | The base ruleset needs `iifname "<wan>" udp dport 68 accept`, or the reply to its own lease renewal is dropped. |
| Portal shows "Could not grant network access" | `table inet pirewall_portal` is not loaded, so there is no set to authorize into. That message is the honest failure — the login is refused rather than reported as successful onto a dead network. |
| `pirewall-core` won't start: "socket is in group ..." | `/etc/tmpfiles.d/pirewall.conf` is missing or unapplied. Run `sudo systemd-tmpfiles --create`; the portal socket's directory must be setgid `pirewall-portal-ipc`. |
| LAN clients gated with no sign-in page | The nft table was loaded before `pirewall-portal` was running. `sudo nft delete table inet pirewall_portal` restores forwarding immediately. |
| Portal logs nothing to file | `portal.log_dir` must be its own directory — `pirewall-portal` is not in `pirewall-ipc` and cannot write `/var/log/pirewall`. |
| Log files stop updating after a day | A `logrotate` drop-in recreating them under the wrong owner. pirewall rotates its own logs; delete `/etc/logrotate.d/pirewall`. |
| No threats ever detected | Expected without trained models — pirewall runs behaviour-only detection and says so at startup. See `docs/ML_PIPELINE.md`. |
