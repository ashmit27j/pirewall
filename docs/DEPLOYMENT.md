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
4. Confirm you have two usable interfaces and note their real names:
   `ip link show`. pirewall needs an uplink (WAN) and an interface facing
   the network you want protected (LAN); **each side may independently be
   wired or wireless** — two NICs, one NIC + a USB Ethernet adapter, the
   onboard Wi-Fi radio as a client uplink, a USB Wi-Fi dongle running an
   access point, or any mix. §4 documents both paths for both sides.
   Whatever you end up with, the names are what
   `network.wan_interface`/`network.lan_interface` must match exactly — do
   not guess or reuse the placeholder `eth0`/`eth1` from
   `config/default_config.toml`. If both interfaces are `wlan`-named, see
   §4.1 for how to tell the onboard radio from the dongle.

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
before applying it by hand. The order is: identify the interfaces (§4.1),
enable forwarding (§4.2), bring up the WAN (§4.3), bring up the LAN (§4.4),
then load the nftables rulesets (§4.5).

**Raspberry Pi OS Bookworm and later use NetworkManager**, so every
interface command below is `nmcli`, not `/etc/dhcpcd.conf`. Only on
Bullseye or older (which predate the NetworkManager switch) use
`deploy/rendered/dhcpcd-lan.conf`, appended to `/etc/dhcpcd.conf`.

### 4.1 Identify your interfaces

Do this first, and write the names down — everything after it refers to
`$WAN_IF` and `$LAN_IF`. `ethtool` and `iw` are used throughout this
section and are not on a Lite image by default:

```sh
sudo apt install ethtool iw
ip link show
```

If one side is Ethernet and the other Wi-Fi (`eth0` + `wlan0`) the names
speak for themselves. **If both are `wlan`-named, the name alone does not
tell you which radio is which** — ask the driver:

```sh
ethtool -i wlan0
ethtool -i wlan1
```

| `driver:` field | What it is |
|---|---|
| `brcmfmac` | the Pi's **onboard** Wi-Fi radio |
| `rtl8xxxu` | an **RTL8188EUS-class USB dongle** (in-kernel driver) |
| `8188eu` / `rtl8188eus` | the same dongle, running the out-of-tree DKMS driver (§4.4.1) |
| `smsc95xx`, `lan78xx`, `r8152`, … | onboard or USB **Ethernet** |

Do this rather than assuming `wlan0` is onboard: USB devices are enumerated
in probe order, so a dongle can come up as `wlan0` on one boot and `wlan1`
on the next. Two guards are worth setting up once you know which is which:

* Pin the names. Match on the USB device rather than the driver, so the
  rule survives a driver swap:

  ```ini
  # /etc/systemd/network/10-pirewall-lan.link
  [Match]
  Property=ID_VENDOR_ID=0bda ID_MODEL_ID=8179

  [Link]
  Name=pirewall-lan
  ```

  Then use `pirewall-lan` as `network.lan_interface` and
  `capture.interface`. pirewall does not care what an interface is called
  (§4.6), so a descriptive name is free.
* Re-run detection after any reboot that could have reordered them:

  ```sh
  uv run python -m scripts.deployment.configure --detect
  ```

  This prints the layout it observes and writes nothing. Note that when
  more than one non-WAN interface is addressed, `--detect` breaks the tie
  **alphabetically** and says so in a warning — it does not know which
  radio you meant. Read the warning rather than skipping past it.

### 4.2 Enable forwarding

```sh
sudo cp deploy/rendered/60-pirewall-forwarding.conf /etc/sysctl.d/60-pirewall-forwarding.conf
sudo sysctl --system
```

### 4.3 WAN interface — pick one

The WAN side needs an address and the Pi's default route. Either path
produces exactly that; nothing later in this document depends on which one
you took.

#### Option A — wired uplink (Ethernet into the upstream router)

Nothing to configure. Plug it in and let the upstream router's DHCP address
it, which is the Raspberry Pi OS default. Confirm:

```sh
ip addr show "$WAN_IF"     # expect an address in the upstream router's subnet
ip route                   # expect: default via <router> dev $WAN_IF
```

The gateway shown there is `network.upstream_gateway`.

#### Option B — wireless uplink (associate as a client to an existing Wi-Fi network)

Use the onboard radio (`brcmfmac`) as a normal Wi-Fi client:

```sh
sudo nmcli device wifi list ifname "$WAN_IF"          # confirm the SSID is visible
sudo nmcli device wifi connect "<SSID>" password "<PSK>" ifname "$WAN_IF"
```

Confirm it associated *and* got a route — association alone is not enough:

```sh
nmcli device status                # $WAN_IF should read "connected"
ip addr show "$WAN_IF"             # expect an address from the upstream network
ip route                           # expect: default via <router> dev $WAN_IF
```

Two notes on this path:

* **The Wi-Fi passphrase is not a pirewall secret.** It lives in
  NetworkManager's own connection store
  (`/etc/NetworkManager/system-connections/`, mode `600`, root-owned), the
  same place the rest of the host's network credentials live. It never
  enters `config/local_config.toml`, is never read by pirewall, and is not
  covered by `CLAUDE.md`'s "never commit secrets" rule any more than the
  host's SSH host key is — treat it as host configuration, not application
  configuration.
* **A wireless uplink is a shared, variable-latency medium.** If the
  upstream link drops, the Pi loses its default route and LAN clients lose
  internet. That is an availability property of the deployment, not a
  pirewall failure mode, and ADDENDUM.md A6's `fail_open` default means
  pirewall does not compound it.

### 4.4 LAN interface — pick one

The LAN side needs the Pi's own address on the protected network — the
value you set as `network.pirewall_lan_ip`, in the CIDR you set as
`network.protected_network`. Safety validation refuses to ever block that
address (spec §24), so what the interface actually ends up holding must
match the config exactly.

#### Option A — wired LAN (static address on an Ethernet interface)

```sh
sudo nmcli con add type ethernet ifname "$LAN_IF" con-name pirewall-lan \
    ipv4.method manual \
    ipv4.addresses "$PIREWALL_LAN_IP/$PREFIX" \
    ipv4.never-default yes          # the LAN side is not our default route
sudo nmcli con up pirewall-lan
```

`ipv4.never-default yes` matters: the Pi's own default route must stay on
the WAN side (toward `network.upstream_gateway`). Verify with
`ip addr show "$LAN_IF"` and `ip route`.

This path gives clients **no DHCP** — `ipv4.method manual` addresses the Pi
and nothing else. Either configure LAN clients statically, or run a DHCP
server yourself (`dnsmasq` bound to `$LAN_IF`). Option B below includes one.

#### Option B — wireless LAN (a USB dongle running as an access point)

This is the path for a Pi whose only wired port is doing something else, or
none at all. `nmcli device wifi hotspot` creates the AP, and NetworkManager
runs a `dnsmasq` instance behind it for DHCP and DNS.

**Check AP support before anything else.** Not every Wi-Fi chipset can act
as an access point, and the failure mode if it can't is confusing rather
than explicit:

```sh
iw list | grep -A 12 "Supported interface modes"
```

`AP` must appear in that list for the radio you intend to use. If it does
not, stop here and read §4.4.1 — no amount of `nmcli` will work around a
driver that does not implement AP mode.

Then create the hotspot and immediately pin its addressing:

```sh
sudo nmcli device wifi hotspot ifname "$LAN_IF" con-name pirewall-lan-ap \
    ssid "<your SSID>" password "<your WPA2 passphrase, 8+ chars>"

# `nmcli device wifi hotspot` picks its own subnet (10.42.0.1/24) and brings
# the connection straight up. Override it to match your config, then bounce
# the connection so the new address and its DHCP pool take effect.
sudo nmcli connection modify pirewall-lan-ap \
    ipv4.method shared \
    ipv4.addresses "$PIREWALL_LAN_IP/$PREFIX" \
    ipv4.never-default yes \
    802-11-wireless.band bg \
    wifi-sec.key-mgmt wpa-psk \
    wifi-sec.proto rsn \
    wifi-sec.pairwise ccmp \
    wifi-sec.group ccmp
sudo nmcli connection down pirewall-lan-ap
sudo nmcli connection up pirewall-lan-ap
```

**Why the second command is not optional.** `nmcli device wifi hotspot`
defaults to `10.42.0.1/24`, which will not match the
`network.pirewall_lan_ip` / `network.protected_network` in
`config/local_config.toml`. If you leave the mismatch in place, safety
validation is protecting an address the Pi does not have and rule
generation is scoping rules to a network no client is on — pirewall will
start and look healthy while enforcing against the wrong subnet. Keeping
`ipv4.method shared` is what preserves the DHCP/DNS service; overriding
`ipv4.addresses` is what moves it onto your subnet. `wifi-sec.*` pins
WPA2-CCMP explicitly rather than relying on the default, and
`802-11-wireless.band bg` pins 2.4 GHz (see §4.4.2).

The other order that works, if you would rather never have the wrong subnet
live at all, is `nmcli connection add type wifi ... ipv4.method shared` with
every property set up front. The two-step form above is documented because
it is harder to get wrong.

Verify — all four, not just the first:

```sh
nmcli device status                          # $LAN_IF: "connected", pirewall-lan-ap
nmcli connection show pirewall-lan-ap | grep -E 'ipv4.method|ipv4.addresses|802-11-wireless'
ip addr show "$LAN_IF"                       # must show $PIREWALL_LAN_IP
iw dev "$LAN_IF" info                        # expect: type AP
```

Then **connect a real client device** and confirm it gets a lease in your
subnet before moving on:

```sh
sudo journalctl -u NetworkManager | grep -i dhcp   # dnsmasq lease messages
ip neigh show dev "$LAN_IF"                        # the client's address should appear
```

A client that associates but gets no address, or an address in
`10.42.0.0/24`, means the `ipv4.addresses` override did not take — go back
and re-check `nmcli connection show`.

**One interaction to check, not assume:** `ipv4.method shared` makes
NetworkManager install its *own* masquerade rules for the shared subnet, in
addition to whatever you load from `deploy/rendered/nat-masquerade.nft`.
After §4.5, run `sudo nft list ruleset` and look at what masquerade rules
actually exist. If NetworkManager has already covered
`network.protected_network`, loading the template's rule as well is
redundant. Decide deliberately which one owns NAT rather than ending up
with both by accident.

##### 4.4.1 RTL8188EUS (USB ID `0bda:8179`) — AP-mode caveat

This dongle is the one this deployment was specified around, and it has a
known wrinkle worth stating plainly. The in-kernel driver it binds to is
`rtl8xxxu`, whose AP-mode support for this chipset is incomplete: depending
on your kernel version, `iw list` may not list `AP` under "Supported
interface modes" at all, or may list it while the hotspot fails to start,
starts and accepts no clients, or drops clients shortly after association.

Confirm with the `iw list` check in §4.4 **before** troubleshooting `nmcli`
— if `AP` is absent, the problem is the driver and nothing at the
NetworkManager layer will fix it.

The documented fallback is to replace `rtl8xxxu` with the out-of-tree
Realtek `rtl8188eus` driver, which does implement AP mode for this chipset,
built as a DKMS module so it survives kernel upgrades:

> <https://github.com/aircrack-ng/rtl8188eus>

Follow that repository's own instructions. They are **not reproduced here**
on purpose: the build depends on your exact kernel headers and blacklisting
`rtl8xxxu`, it has not been run against this deployment, and inlining steps
nobody here has executed would be the kind of unverified claim `CLAUDE.md`'s
labeling rules exist to prevent. This is the same category as every other
host-specific step in this document — **documented, not automated**.

After swapping drivers, re-check `ethtool -i "$LAN_IF"` (the `driver:` field
becomes `8188eu`), re-run the `iw list` check, and note that the interface
may come back with a different name — re-run `--detect` (§4.1).

##### 4.4.2 What this dongle can and cannot do

The RTL8188EUS is **2.4 GHz only, 802.11b/g/n, single-stream** — a ~150
Mbps PHY rate, so realistically ~40–70 Mbps of usable throughput shared
across every client, less on a congested 2.4 GHz band. There is no 5 GHz
and no 802.11ac/ax.

This is irrelevant to pirewall's own function: capture, flow tracking,
detection, and enforcement are unaffected by link rate, and a Pi 4 is not
throughput-limited by pirewall at these speeds. It matters only for
expectations — if the protected LAN carries anything bandwidth-heavy, the
dongle is the ceiling, not the firewall.

### 4.5 Load the nftables rulesets

```sh
sudo nft -c -f deploy/rendered/base.nft         # syntax check first
sudo nft -f deploy/rendered/base.nft
sudo nft -f deploy/rendered/nat-masquerade.nft  # see the NAT note in §4.4 Option B
```

Load `base.nft` **before** `nat-masquerade.nft`: the base ruleset's
deny-by-default forwarding posture should exist before NAT starts
forwarding traffic. Both templates reference `${WAN_INTERFACE}` /
`${LAN_INTERFACE}` by name, so if you renamed an interface in §4.1 or
switched a side between wired and wireless, re-render before loading.

Then confirm forwarding actually works from a test LAN client (e.g. `ping`
and a real outbound connection through the Pi) before proceeding.

See `deploy/network/README.md` and `deploy/firewall/README.md` for the full
rationale behind each template and the load order.

### 4.6 Why pirewall itself does not care which paths you picked

Worth stating explicitly, because a Wi-Fi-only deployment otherwise leaves
it as an unstated assumption:

* **pirewall's runtime code never distinguishes wired from wireless.**
  `network.wan_interface`, `network.lan_interface`, and
  `capture.interface` are plain strings (`pirewall/config/models.py`); no
  code anywhere branches on an interface's name or type. The nftables
  templates substitute whatever names you configured, and adaptive rules
  generated at runtime match on addresses and ports, never on an interface.
* **`AF_PACKET` capture is identical on a client-mode and an AP-mode
  interface.** `pirewall.capture.af_packet.AFPacketCapture` binds a
  `SOCK_RAW` socket to the interface by name and reads
  Ethernet-framed packets. The kernel's mac80211 layer presents a wireless
  interface in either mode as a normal Ethernet device to `AF_PACKET` —
  802.11 headers are stripped and 802.3 headers synthesized before the
  packet reaches the socket. `pirewall/capture/parser.py` therefore sees
  exactly the same frames it would on `eth0`, and needs no wireless-specific
  handling. (This holds for `managed` and `AP` mode; it would *not* hold for
  `monitor` mode, which delivers raw 802.11 frames — pirewall does not use
  monitor mode.)

#### Switching between wired and wireless later

Because of the two points above, moving either side between modes is purely
a NetworkManager operation. There is **no pirewall config change and no code
change** involved:

```sh
sudo nmcli con down pirewall-lan-ap        # or pirewall-lan / the wifi connection
sudo nmcli con delete pirewall-lan-ap
# ...then run the other option's commands from §4.3 or §4.4
```

Afterwards, do these three things — they are the only pirewall-side work:

1. Re-run detection to confirm the new layout is what you think it is:

   ```sh
   uv run python -m scripts.deployment.configure --detect
   ```

2. If the interface **name** changed (it will, switching between an
   Ethernet port and a Wi-Fi radio), update `network.wan_interface` /
   `network.lan_interface` / `capture.interface` in
   `config/local_config.toml`, re-render the templates (§4), reload
   `base.nft` and `nat-masquerade.nft`, and
   `sudo systemctl restart pirewall-core`.
3. If the interface name is the same and the addressing is unchanged,
   nothing needs to change at all — `uv run python -m pirewall.main
   --check-config` and a restart are enough to confirm it.

Keeping `network.pirewall_lan_ip` and `network.protected_network` the same
across a LAN-side switch means step 2 is the only edit, and the allowlist,
the Admin PC restriction, and every safety-validation invariant carry over
untouched.

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
