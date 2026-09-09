# Setting up pirewall on a new network

An ordered runbook: every command, in the order you run it, from bare
hardware to a firewall that is actually enforcing — plus the Admin PC side,
which is where Wazuh and Netdata actually live.

**This file is the "what do I type" path.** `docs/SETUP.md` is the same
ground with the reasoning attached, and `docs/DEPLOYMENT.md` explains why
each choice was made. When something here fails, those two are where the
answer is. `setup-commands.txt` is a scratch runbook for one specific
already-deployed Pi — not this.

Budget about an hour for a first run, most of it waiting on downloads.

---

## Contents

1. [Plan the addressing](#1-plan-the-addressing)
2. [Prepare the Pi](#2-prepare-the-pi)
3. [Bring up the interfaces](#3-bring-up-the-interfaces)
4. [Install pirewall](#4-install-pirewall)
5. [Generate config and TLS](#5-generate-config-and-tls)
6. [Bring the stack up](#6-bring-the-stack-up)
7. [Create LAN accounts](#7-create-lan-accounts)
8. [Set up the Admin PC](#8-set-up-the-admin-pc)
9. [Verify end to end](#9-verify-end-to-end)
10. [Go live gradually](#10-go-live-gradually)
11. [Moving an existing Pi to a different network](#11-moving-an-existing-pi-to-a-different-network)
12. [Teardown and rollback](#12-teardown-and-rollback)
13. [Quick reference](#quick-reference)

---

## 1. Plan the addressing

Decide this before typing anything — steps 3 and 5 both depend on it, and
changing your mind later means redoing the TLS certificate.

pirewall needs an **uplink (WAN)** and a **protected side (LAN)**. Each can
independently be wired or wireless; the code never distinguishes them.

**Two layouts work. Pick one.**

### Layout A — two interfaces, Admin PC on the protected LAN

Simplest. The Admin PC is just another host on the LAN, singled out by
`admin.admin_pc_ip`.

```
internet ── [WAN] Pi [LAN] ── switch/AP ── Admin PC + protected clients
                                              192.168.100.x
```

### Layout B — three interfaces, dedicated admin segment (recommended)

The Admin PC sits on a separate wire that protected clients cannot reach at
all, so a compromised LAN client cannot even send packets at the control
panel. This is what the reference deployment uses.

```
internet ── [wlan1 WAN] Pi [wlan0 LAN] ── Wi-Fi ── protected clients
                            [eth0 admin] ── cable ── Admin PC
```

Fill in your own values and keep them handy — later steps reuse them:

| Thing | Example | Yours |
|---|---|---|
| WAN interface | `wlan1` | |
| LAN interface (capture happens here) | `wlan0` | |
| Protected network | `192.168.100.0/24` | |
| Pi's LAN address | `192.168.100.1` | |
| Admin interface (Layout B only) | `eth0` | |
| Pi's admin address (Layout B) | `192.168.101.1` | |
| Admin PC address | `192.168.101.2` (B) / `192.168.100.10` (A) | |
| AP SSID | `pirewall-lan` | |

> **Do not reuse your upstream router's subnet.** If the WAN side is
> `192.168.1.0/24`, the protected side must not be. Overlapping subnets
> produce routing that looks fine and silently drops traffic.

---

## 2. Prepare the Pi

**64-bit Raspberry Pi OS is a hard requirement.** `numpy`, `scipy`,
`scikit-learn` and `lightgbm` publish `aarch64` wheels but not 32-bit
`armv7l`; on 32-bit they compile from source for hours and usually die for
lack of RAM.

```sh
uname -m          # must print aarch64
free -h           # 4 GB is comfortable; 2 GB works with a smaller flow table
```

```sh
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y nftables git curl ethtool iw

# Python 3.12 through uv, NOT apt. Debian 12 ships 3.11 and has no
# python3.12 package; Debian 13 ships 3.13. uv pins the same interpreter
# everywhere, so the Pi runs what development ran.
curl -LsSf https://astral.sh/uv/install.sh | sh
exec "$SHELL" -l
uv python install 3.12
```

If the LAN side will be a **wireless AP**, confirm the radio supports it —
`AP` must appear in the output:

```sh
iw list | grep -A 12 "Supported interface modes"
```

If it does not (common on RTL8188EUS dongles, USB `0bda:8179`), see
`docs/DEPLOYMENT.md` §4.4.1 for replacing the in-kernel driver.

---

## 3. Bring up the interfaces

Bookworm and later use NetworkManager — `nmcli`, not `/etc/dhcpcd.conf`.

**Know which interface is which first.** With two `wlan` devices the name
tells you nothing; USB probe order decides it, and it can change on reboot:

```sh
ip link show
ethtool -i wlan0     # brcmfmac = onboard Pi radio
ethtool -i wlan1     # rtl8xxxu / 8188eu = USB dongle
```

Set your values once, then paste the rest:

```sh
export WAN_IF=wlan1
export LAN_IF=wlan0
export ADMIN_IF=eth0                 # Layout B only
export PI_LAN_IP=192.168.100.1
export PI_ADMIN_IP=192.168.101.1     # Layout B only
export PREFIX=24
export AP_SSID=pirewall-lan
```

### WAN — pick one

```sh
# A. Wired: plug into the upstream router and take DHCP. Nothing to do.
ip addr show "$WAN_IF" && ip route

# B. Wireless client
sudo nmcli device wifi connect "<upstream SSID>" password "<PSK>" ifname "$WAN_IF"
ip addr show "$WAN_IF" && ip route
```

Confirm you have an address **and a default route** before continuing.
The Wi-Fi passphrase lives in NetworkManager's store, not in pirewall's
config — host configuration, like an SSH host key.

### LAN — pick one

```sh
# A. Wired LAN: static, no DHCP server (clients static, or run your own dnsmasq)
sudo nmcli con add type ethernet ifname "$LAN_IF" con-name pirewall-lan \
    ipv4.method manual ipv4.addresses "$PI_LAN_IP/$PREFIX" ipv4.never-default yes
sudo nmcli con up pirewall-lan
```

```sh
# B. Wireless AP — NetworkManager also runs DHCP and DNS for it
sudo nmcli device wifi hotspot ifname "$LAN_IF" con-name pirewall-lan-ap \
    ssid "$AP_SSID" password "<WPA2 passphrase, 8+ chars>"

# REQUIRED. The hotspot defaults to 10.42.0.1/24 and must be moved onto your
# subnet, or pirewall protects an address the Pi does not have.
sudo nmcli connection modify pirewall-lan-ap \
    ipv4.method shared ipv4.addresses "$PI_LAN_IP/$PREFIX" \
    ipv4.never-default yes 802-11-wireless.band bg \
    wifi-sec.key-mgmt wpa-psk wifi-sec.proto rsn \
    wifi-sec.pairwise ccmp wifi-sec.group ccmp
sudo nmcli connection down pirewall-lan-ap && sudo nmcli connection up pirewall-lan-ap
```

`ipv4.never-default yes` matters on both: without it the LAN side can steal
the default route and the Pi loses its own uplink.

### Admin segment — Layout B only

```sh
sudo nmcli con add type ethernet ifname "$ADMIN_IF" con-name pirewall-admin-wired \
    ipv4.method manual ipv4.addresses "$PI_ADMIN_IP/$PREFIX" ipv4.never-default yes
sudo nmcli con up pirewall-admin-wired
```

### Confirm before moving on

```sh
nmcli device status
ip -br addr
ip route                              # exactly one default route, via the WAN
```

For a wireless AP, connect a real phone now and confirm it gets a lease **in
your subnet, not 10.42.0.x**. Nothing downstream works if this does not.

---

## 4. Install pirewall

```sh
sudo mkdir -p /opt/pirewall
sudo chown "$USER" /opt/pirewall
git clone https://github.com/ashmit27j/pirewall.git /opt/pirewall
cd /opt/pirewall

uv sync --no-dev            # production install; omit --no-dev to run the tests
```

Optional but worth it once, to prove the checkout is sound:

```sh
uv sync && uv run pytest -q
```

---

## 5. Generate config and TLS

### 5.1 Configuration

```sh
cd /opt/pirewall
uv run python -m scripts.deployment.configure --detect     # preview, writes nothing
uv run python -m scripts.deployment.configure              # for real
```

It reads the live layout with `ip` and asks only for what it cannot observe:
**the Admin PC address and the admin password**. It deliberately refuses to
guess either — "which machine may administer this firewall" is a policy
decision, and the neighbour table only knows who has recently talked to the
Pi.

Check the detected values before accepting them. `pirewall_lan_ip` and
`upstream_gateway` are the two addresses safety validation refuses to ever
block, so a wrong value there silently removes the protection that stops
pirewall cutting off your own management access.

Result: `config/local_config.toml`. It is gitignored, holds a password hash,
and never leaves the Pi.

### 5.2 TLS certificate

The address in the certificate must be **the address your Admin PC types in
the browser**:

```sh
# Layout A (Admin PC on the protected LAN)
scripts/deployment/make_certs.sh "$PI_LAN_IP"

# Layout B (dedicated admin segment) — use the ADMIN-side address
scripts/deployment/make_certs.sh "$PI_ADMIN_IP"

sudo chown pirewall-api:pirewall-api deploy/certificates/pirewall.{crt,key}
sudo chmod 600 deploy/certificates/pirewall.key
```

> **`make_certs.sh` writes exactly one IP into the SAN.** If you want to
> reach the panel on both the LAN and admin addresses, generate it by hand
> with both — a certificate carrying only a Common Name and no SAN is
> rejected by every modern client, warning-click or not:
>
> ```sh
> openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
>   -keyout deploy/certificates/pirewall.key \
>   -out deploy/certificates/pirewall.crt \
>   -subj "/CN=pirewall" \
>   -addext "subjectAltName=IP:${PI_ADMIN_IP},IP:${PI_LAN_IP},IP:127.0.0.1"
> ```
>
> Verify what you produced: `openssl x509 -in deploy/certificates/pirewall.crt -noout -ext subjectAltName`

### 5.3 Optional: enable the captive portal

Skip if you do not want LAN clients to sign in. In
`config/local_config.toml`:

```toml
[portal]
enabled = true
network_name = "pirewall-lan"     # your SSID; cosmetic
listen_host = "192.168.100.1"     # must equal network.pirewall_lan_ip
listen_port = 8080

[admin]
allow_local_console = true        # lets you open the panel on the Pi's own desktop
```

---

## 6. Bring the stack up

One idempotent script does the rest — accounts, directories, rulesets,
services, in dependency order:

```sh
sudo scripts/deployment/pirewall-start --check     # preflight, changes nothing
scripts/deployment/pirewall-start --dry-run        # print every command, run none
sudo scripts/deployment/pirewall-start             # do it
```

It snapshots the current ruleset to `deploy/rollback/` before touching
anything, syntax-checks every ruleset with `nft -c -f` before loading it,
waits for each service to be genuinely ready rather than merely "active",
and prints the rollback commands when it finishes.

Safe to re-run at any point, including after a failed attempt.

```sh
sudo scripts/deployment/pirewall-start --no-portal   # core + api only
sudo scripts/deployment/pirewall-start --skip-nft    # leave the ruleset alone
```

After it succeeds, make the services survive a reboot:

```sh
sudo systemctl enable pirewall-core pirewall-api
sudo systemctl enable pirewall-portal      # only if the portal is enabled
```

> **The captive-portal ruleset is loaded last, on purpose.** It rejects
> forwarding for unauthenticated LAN clients, so loading it while the
> sign-in page is down gates the whole protected network with nowhere to
> sign in. The script enforces the ordering; if you ever load rules by
> hand, keep it.

---

## 7. Create LAN accounts

Only if the portal is enabled. Nobody can sign in until an account exists.

```sh
sudo -u pirewall-core uv run python -m scripts.deployment.portal_users add alice
sudo -u pirewall-core uv run python -m scripts.deployment.portal_users list
```

`add` and `passwd` prompt twice and never echo; only a scrypt hash is
stored. You can also create accounts from the control panel, including
alongside an allowlist entry.

To try it before provisioning real people:

```sh
sudo -u pirewall-core uv run python -m scripts.deployment.portal_users \
     seed-demo --i-understand-these-are-insecure
```

That creates `demo-alice` … `demo-erin` with passwords `pirewall-demo-1` …
`pirewall-demo-5`. **Those passwords are published in this repository.**
Delete them before the network carries real traffic:

```sh
for u in demo-alice demo-bob demo-carol demo-dave demo-erin; do
  sudo -u pirewall-core uv run python -m scripts.deployment.portal_users remove "$u"
done
```

While any survives, pirewall says so at every core startup, on the sign-in
page, and on the control panel.

Portal credentials cross the LAN in the clear — the sign-in page is plain
HTTP, because a self-signed certificate breaks captive-portal detection.
Treat them as network-access credentials, keep them distinct from the admin
password, and never reuse a password from elsewhere.

---

## 8. Set up the Admin PC

The Admin PC is the only machine allowed to reach the control panel, and it
is where Wazuh and Netdata run. **Neither belongs on the Pi**: Netdata costs
100–250 MB resident plus continuous SD-card writes, and the Wazuh stack
wants 6 GB RAM. The Pi only emits UDP datagrams and syslog lines, which
costs essentially nothing.

### 8.1 Addressing

Give it the address you told `configure` about.

```sh
# Layout B — static on the admin segment. NetworkManager:
sudo nmcli con add type ethernet ifname eth0 con-name pirewall-admin \
    ipv4.method manual ipv4.addresses 192.168.101.2/24 ipv4.never-default yes
sudo nmcli con up pirewall-admin

# Layout A — a DHCP reservation on the Pi's LAN, or a static address
# outside the DHCP pool (default pool is .50–.200).
```

`ipv4.never-default yes` keeps the admin link from stealing the Admin PC's
own default route.

```sh
ping -c2 192.168.101.1                       # the Pi's admin address
nc -zvn -w5 192.168.101.1 8443               # control panel reachable
```

If `nc` fails, check in this order: the cable has carrier
(`cat /sys/class/net/eth0/carrier` on the Pi — `0` means unplugged),
`admin.admin_pc_ip` matches this machine, and the Pi's base ruleset allows
you (it restricts port 22 and 8443 to that one address).

### 8.2 Reach the control panel

```
https://192.168.101.1:8443/control-panel        # Layout B
https://192.168.100.1:8443/control-panel        # Layout A
```

The certificate is self-signed, so the browser warns once. Accept and pin
it. If the browser refuses outright rather than warning, the certificate has
no matching SAN — regenerate it per §5.2.

Log in with the username and password you set during `configure`.

Firefox: *Advanced → Accept the Risk and Continue*.
Chromium: *Advanced → Proceed*, or import the cert into the OS trust store:

```sh
sudo cp pirewall.crt /usr/local/share/ca-certificates/pirewall.crt
sudo update-ca-certificates
```

### 8.3 Wazuh manager

pirewall does **not** run a Wazuh agent on the enforcement box (spec §45 —
fewer privileged daemons on the machine holding `CAP_NET_ADMIN`). It
forwards JSON security events to the manager over **TCP syslog on port
514**, not the agent-enrollment port 1514.

> **Kali users need Docker.** Wazuh publishes no Kali packages and its
> Debian repository targets releases Kali does not track. Use the container
> path.

#### With Docker

Budget **6 GB RAM and 4 CPU cores** for manager + indexer + dashboard.

```sh
# Docker itself, if not present
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER" && newgrp docker

git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.0
cd wazuh-docker/single-node

# Required — the indexer will not start without it
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf

docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
docker compose ps
```

Dashboard at `https://localhost` — default `admin` / `SecretPassword`.
**Change it immediately** in `docker-compose.yml` and
`config/wazuh_indexer/internal_users.yml`.

Expose the syslog port to the Pi by adding to the manager service in
`docker-compose.yml`:

```yaml
    ports:
      - "514:514/tcp"
```

#### Without Docker (Debian/Ubuntu)

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

Arch/Omarchy has no official or maintained package — use Docker.

#### Enable the syslog collector — required either way

Without this the Pi's events are silently discarded, and a refused
connection is indistinguishable from "no events yet" from the Pi's side. In
`/var/ossec/etc/ossec.conf` (or the container's mounted copy), inside
`<ossec_config>`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>192.168.101.0/24</allowed-ips>
</remote>
```

Restart the manager, then confirm **from the Pi**:

```sh
nc -zv 192.168.101.2 514
sudo grep -i wazuh /var/log/pirewall/core.log | tail -5    # no "Connection refused"
```

### 8.4 Netdata

pirewall pushes metrics as **UDP StatsD on port 8125** — not 19999, which is
only the dashboard.

#### With Docker

```sh
docker run -d --name=netdata --restart=unless-stopped \
  -p 19999:19999 -p 8125:8125/udp \
  -v netdataconfig:/etc/netdata \
  -v netdatalib:/var/lib/netdata \
  -v netdatacache:/var/cache/netdata \
  -v /etc/passwd:/host/etc/passwd:ro -v /etc/group:/host/etc/group:ro \
  -v /proc:/host/proc:ro -v /sys:/host/sys:ro \
  -v /etc/os-release:/host/etc/os-release:ro \
  --cap-add SYS_PTRACE --security-opt apparmor=unconfined \
  netdata/netdata
```

`-p 8125:8125/udp` is the line people forget; without it the Pi's metrics
never arrive.

#### Without Docker

```sh
sudo pacman -S netdata                        # Arch / Omarchy
sudo apt install -y netdata                   # Debian / Ubuntu / Kali
# or, for a newer build than the distro ships:
wget -O /tmp/kickstart.sh https://get.netdata.cloud/kickstart.sh && sh /tmp/kickstart.sh

sudo systemctl enable --now netdata
```

Make the StatsD listener reachable from the Pi — by default it binds
localhost only. In `/etc/netdata/netdata.conf`:

```ini
[statsd]
    enabled = yes
    bind to = udp:0.0.0.0:8125
```

```sh
sudo systemctl restart netdata
ss -lunp | grep 8125          # must show a listener
```

Dashboard at `http://localhost:19999`. pirewall's charts appear under
`pirewall_*` about a minute after `pirewall-core` starts.

### 8.5 Point the Pi at the Admin PC

Back on the Pi, in `config/local_config.toml`:

```toml
[integration]
wazuh_enabled = true
wazuh_host = "192.168.101.2"
wazuh_port = 514
netdata_enabled = true
netdata_host = "192.168.101.2"
netdata_port = 8125
```

```sh
uv run python -m pirewall.main --check-config
sudo systemctl restart pirewall-core
```

---

## 9. Verify end to end

**On the Pi:**

```sh
systemctl is-active pirewall-core pirewall-api pirewall-portal
sudo nft list tables                       # pirewall_base, pirewall_portal, nm-shared-*
sudo tail -20 /var/log/pirewall/core.log
ping -c2 1.1.1.1                           # the Pi still has its own uplink
```

**From the Admin PC:**

```sh
nc -zvn -w5 192.168.101.1 8443
```

Open the control panel and confirm: System shows `capture=up` and models
loaded, Network shows packets climbing, Events is populating.

**From a phone or laptop on the protected Wi-Fi:**

1. Join the SSID → it gets a lease in your subnet.
2. If the portal is on, the sign-in page appears by itself. Confirm the
   internet is refused *before* signing in.
3. Sign in with an account from §7. Confirm the internet works.
4. Watch the countdown on the keepalive page.

**Confirm the kernel agrees**, on the Pi:

```sh
sudo nft list set inet pirewall_portal authed
```

A signed-in client is one element with a `timeout` counting down. Signing
out empties it. If an element is present with nobody signed in, core
revokes it within one sweep and logs why.

---

## 10. Go live gradually

`firewall.enforcement_mode` starts at `shadow`: pirewall watches, scores and
records what it *would* do, and enforces nothing. Leave it there — a week or
two is the recommendation — until the control panel's decisions look right.

```
shadow  ->  assisted  ->  active
```

* **`assisted`** — high-confidence BLOCKs wait in an approval queue for you;
  everything else deploys.
* **`active`** — deploys without asking.

Edit `firewall.enforcement_mode` in `config/local_config.toml`, then:

```sh
uv run python -m pirewall.main --check-config
sudo systemctl restart pirewall-core
```

If something goes wrong, the kill-switch reverts every adaptive rule and
drops back to `shadow`. From the control panel, or:

```sh
TOKEN=$(curl -sk -X POST https://192.168.101.1:8443/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<yours>"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')

curl -sk -X POST https://192.168.101.1:8443/api/v1/firewall/kill-switch \
  -H "Authorization: Bearer $TOKEN"
```

---

## 11. Moving an existing Pi to a different network

You do **not** repeat the whole runbook. Most of it is unchanged.

```sh
cd /opt/pirewall

# 1. Repoint the WAN at the new upstream
sudo nmcli device wifi connect "<new SSID>" password "<PSK>" ifname "$WAN_IF"
ip route                                   # new default route present?

# 2. See what changed. The upstream gateway almost always did.
uv run python -m scripts.deployment.configure --detect
```

**The upstream gateway matters more than it looks.** It is one of the
addresses safety validation refuses to ever block, so a stale value silently
removes the protection that keeps pirewall from cutting off your own
internet. `pirewall-start --check` warns when the configured value and the
live default route disagree.

```sh
# 3. Apply the changes you need
uv run python -m scripts.deployment.configure               # full re-run, or:
uv run python -m scripts.deployment.configure --set-admin-pc  # just the Admin PC

# 4. If the Admin PC's address changed, the certificate no longer matches
scripts/deployment/make_certs.sh "$PI_ADMIN_IP"
sudo chown pirewall-api:pirewall-api deploy/certificates/pirewall.{crt,key}
sudo chmod 600 deploy/certificates/pirewall.key

# 5. Re-render and restart — pirewall-start does both, idempotently
sudo scripts/deployment/pirewall-start
```

**What does not change:** the protected subnet, the AP's SSID and
passphrase, LAN user accounts, and the admin password. Clients on the
protected side never notice the uplink moved.

**If the LAN interface *name* changed** (USB probe order can do this across
reboots), update `network.lan_interface` and `capture.interface` together —
they must agree, or pirewall captures on one interface and writes rules
about another.

---

## 12. Teardown and rollback

```sh
# Ungate the LAN immediately — clients get their network back at once
sudo nft delete table inet pirewall_portal

# Stop everything
sudo systemctl stop pirewall-portal pirewall-api pirewall-core

# Restore the ruleset as it was before the last pirewall-start
sudo nft flush ruleset
sudo nft -f deploy/rollback/ruleset-<timestamp>.nft
sudo systemctl restart NetworkManager

# Full uninstall
sudo systemctl disable --now pirewall-portal pirewall-api pirewall-core
sudo rm /etc/systemd/system/pirewall-{core,api,portal}.service
sudo rm -f /etc/tmpfiles.d/pirewall.conf
sudo rm -f /etc/NetworkManager/dnsmasq-shared.d/pirewall-portal.conf
sudo systemctl daemon-reload
sudo nft delete table inet pirewall_base 2>/dev/null
sudo nft delete table inet pirewall 2>/dev/null
sudo nmcli connection down pirewall-lan-ap && sudo nmcli connection up pirewall-lan-ap
```

`deploy/rollback/` is gitignored and exists **only on this Pi** — a fresh
clone will not have your snapshots.

---

## Quick reference

**The whole thing, once the network is up:**

```sh
cd /opt/pirewall
uv sync --no-dev
uv run python -m scripts.deployment.configure
scripts/deployment/make_certs.sh <admin-facing-ip>
sudo chown pirewall-api:pirewall-api deploy/certificates/pirewall.{crt,key}
sudo chmod 600 deploy/certificates/pirewall.key
sudo scripts/deployment/pirewall-start
sudo -u pirewall-core uv run python -m scripts.deployment.portal_users add <name>
sudo systemctl enable pirewall-core pirewall-api pirewall-portal
```

**Ports**

| Port | Where | What |
|---|---|---|
| 8443/tcp | Pi | Control panel + API (HTTPS, Admin PC only) |
| 8080/tcp | Pi, LAN side | Captive portal (HTTP; port 80 redirects here) |
| 22/tcp | Pi | SSH — restricted to the Admin PC by the base ruleset |
| 53, 67/udp | Pi, LAN side | DNS and DHCP for protected clients |
| 514/tcp | Admin PC | Wazuh syslog collector (**not** 1514) |
| 8125/udp | Admin PC | Netdata StatsD (**not** 19999) |
| 19999/tcp | Admin PC | Netdata dashboard |

**Health checks**

```sh
systemctl is-active pirewall-core pirewall-api pirewall-portal
sudo nft list tables
sudo nft list set inet pirewall_portal authed
sudo tail -f /var/log/pirewall/core.log
journalctl -u pirewall-core -n 50
uv run python -m pirewall.main --check-config
sudo scripts/deployment/pirewall-start --check
```

**When a service will not start twice in a row**, the crash-loop limiter has
tripped — that is it working, not a bug:

```sh
sudo systemctl reset-failed pirewall-core.service
sudo systemctl start pirewall-core.service
```

`pirewall-start` does this for you, which is what makes it re-runnable.

**More depth:** `docs/SETUP.md` (the same path with reasoning),
`docs/DEPLOYMENT.md` (why each choice), `docs/ADDENDUM_3.md` (how the portal
works), `docs/SECURITY.md` (threat model), `docs/PROGRESS.md` (what is
verified versus what still needs real hardware).
