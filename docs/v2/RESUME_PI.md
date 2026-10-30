# RESUME_PI — power on the Pi and get back to work

Written 2026-10-31. `docs/v2/RUNBOOK_PI.md` is the *campaign* runbook (H0–H42,
walked once). **This file is the everyday one**: what to run after a reboot,
where the dashboard is, and what to check when something looks wrong.

Everything here was run against the real Pi on 2026-10-31 and is `pi-live`
unless it says otherwise.

---

## 0. The one thing that bites after every reboot

**Nothing loads the kernel tables at boot.** `pirewall-core`, `-api` and
`-portal` are `enabled`, so systemd starts all three — but `pirewall-start`
is what loads `pirewall_base`, `pirewall_static`, `pirewall_static_arp`,
`pirewall_adaptive` and `pirewall_portal`, and no unit runs it.

So after a power-on the panel serves, the services report healthy, and
`sudo nft list tables` shows only NetworkManager's `nm-shared-wlan0`:
**core is running against an empty ruleset — no guards, no adaptive sets.**
It looks fine and enforces nothing.

Until a boot unit exists, step 1 is not optional.

## 1. Device map

| Device | Address | Role |
|---|---|---|
| Pi | `raspberrypi@192.168.101.1` (eth0), repo `/opt/pirewall` | the firewall |
| Admin PC (Kali) | `192.168.101.2` on eth0 | dashboard, SSH, lab attacker |
| LAN clients | DHCP `192.168.100.50–200` | join Wi-Fi `pirewall-lan-ap` |

Interfaces on the Pi: `wlan0` = LAN/AP (`192.168.100.1`), `wlan1` = WAN
(uplink), `eth0` = out-of-band management. `wlan1` must be the uplink and
`wlan0` the AP: the `rtl8xxxu` dongle advertises only `managed`/`monitor` and
**cannot** be an access point; the onboard `brcmfmac` can.

## 2. After every reboot, on the Pi

```sh
cd /opt/pirewall
nmcli -t -f NAME,TYPE,DEVICE connection show --active   # pirewall-lan-ap/wlan0, pirewall-wan/wlan1, pirewall-admin-wired/eth0
ip route | grep default                                 # must exist, via wlan1
sudo scripts/deployment/pirewall-start --check --data-mode live
sudo scripts/deployment/pirewall-start --data-mode live --manifest ~/manifest-v2.0.json
```

`pirewall-start` restarts the three services itself and clears the crash-loop
counter, so there is no separate `systemctl restart`. Exit 2 is a refusal and
prints its own fix. It ends by printing the panel URL and the rollback lines.

Then verify:

```sh
sudo nft list tables     # pirewall_base, pirewall_static, arp pirewall_static_arp, pirewall_adaptive, pirewall_portal
sudo nft list chain inet pirewall_static guard_verdict_input   # contains `drop` => input guard enforcing
sudo nft list set inet pirewall_adaptive block_mac             # empty while in SHADOW
systemctl is-active pirewall-core pirewall-api pirewall-portal
```

## 3. The dashboard, from the Admin PC

**<https://192.168.101.1:8443/control-panel>** — sign-in page at
`/control-panel/login`. Self-signed certificate, so accept the warning once.

Access is pinned to the Admin PC (`192.168.101.2`, MAC
`c8:5b:76:9a:94:d3`); it will not open from anywhere else. On the Pi itself,
`https://127.0.0.1:8443/control-panel` works because
`admin.allow_local_console = true`.

Quick health check without a browser:

```sh
curl -sk https://192.168.101.1:8443/api/v1/health      # {"message":"ok"}
```

## 4. The captive portal, from a LAN client

`http://192.168.100.1:8080/portal` (plaintext HTTP by design — ADDENDUM_3 C5).

Five demo accounts exist (`demo-alice` … `demo-erin`, passwords in
`scripts/deployment/portal_users.py`). **They are public, and
`pirewall-core` refuses ASSISTED/ACTIVE enforcement while any of them
exists** — remove them before leaving SHADOW:

```sh
sudo -u pirewall-core .venv/bin/python -m scripts.deployment.portal_users remove-demo
sudo -u pirewall-core .venv/bin/python -m scripts.deployment.portal_users list
```

Portal *gating* (no internet until sign-in) is deliberately not in force
during the benign soak: gating changes the traffic profile being measured,
and sessions expiring mid-capture look like anomalies. Turn it on after the
soak, not before.

## 5. The benign capture does not survive a reboot

It runs as a transient unit, so a power cycle ends it. Re-arm it each boot:

```sh
sudo systemd-run --unit=pirewall-benign-capture \
  bash "$PWD/lab/capture/benign_capture.sh" start --foreground --i-have-consent
sudo bash lab/capture/benign_capture.sh status
```

Stop and seal with `sudo bash lab/capture/benign_capture.sh stop`. A session
left unsealed by a reboot is sealed afterwards with
`seal <session dir>`.

## 6. When the uplink is down

Symptom: no default route, `apt` cannot reach the archive, the GitHub push
fails (`gh` is authenticated **on the Pi**, so pushes go from there).

```sh
ip -br a show wlan1
sudo nmcli connection up pirewall-wan
```

* *"The Wi-Fi network could not be found"* — the uplink AP is not
  broadcasting. Nothing to fix on the Pi; `pirewall-wan` is already
  `autoconnect=yes` with `autoconnect-retries=-1`, so it rejoins by itself
  the moment the SSID reappears.
* **Do not unbind the `rtl8xxxu` driver to "reset" the radio.** The dongle
  drops off the USB bus and does not re-enumerate; neither a hub reset nor
  toggling `authorized` brings it back. It needs a physical replug or a
  reboot. (Learned the hard way, 2026-10-31.)
* A phone hotspot hands out a **different subnet each session**. See §7.

## 7. After the uplink's address changes

`network.upstream_gateway` is one of the addresses safety validation refuses
to let an adaptive rule block. A stale value means the protection is guarding
an address that is no longer the uplink while the real gateway is
unprotected. `pirewall-start` warns about the drift; it does not refuse.

Re-pin it with a targeted edit (never a full `configure.py` run — that
re-prompts for the Admin PC and password):

```sh
uv run python -m scripts.deployment.configure --set-gateway     # from the live default route
uv run python -m scripts.deployment.configure --set-gateway --gateway 10.36.207.147
sudo scripts/deployment/pirewall-start --data-mode live         # re-render with the new address
```

It is deliberately not automatic: a safety-critical address that silently
followed the kernel's default route would move whenever the route did.

The durable fix is a **stable uplink** — a second NetworkManager profile for
a fixed home network, which NetworkManager prefers by
`autoconnect-priority`, leaving the phone hotspot as a fallback.

## 8. Current state and the known gaps

| | |
|---|---|
| Enforcement | `shadow` (ADDENDUM A1 default; keep for the soak) |
| Failure mode | `fail_open` (A6) |
| Engine | `pipeline.engine = "v1"` — the evaluation baseline |
| Guards | input `drop`, raw `drop`, forward observe (D2 defaults) |
| Capture | **Python path** — `pirewall_native` is not built on the Pi, and it drops packets under load |
| nft transport | `nft -j -f -` subprocess — `python3-nftables` is not linked into the venv |
| Time sync | **chrony absent** — manifest and event timestamps may be wrong |

The last three are all `apt`-installable and were blocked only by the uplink
being down. Fix them before any measurement run:

```sh
sudo apt install -y python3-nftables chrony
sudo scripts/deployment/install_nftables_pth.sh
command -v cargo || { curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal; . "$HOME/.cargo/env"; }
uv sync --no-dev --extra native
```

Still unproven because no LAN client has ever stayed joined: `ether saddr` on
`brcmfmac` (KNOWN_ISSUES V2 — the whole MAC identity layer rests on it), the
panic/restore drill, crash-safety G6, the lab victim, and both campaigns.

## 9. Undo

| Situation | Command |
|---|---|
| Anything looks wrong | `sudo scripts/deployment/pirewall-start --panic` |
| Back to v1 on the v2 data plane | `sudo scripts/deployment/pirewall-start --engine v1 --data-mode live` |
| Ungate the LAN immediately | `sudo nft delete table inet pirewall_portal` |
| Stop everything | `sudo systemctl stop pirewall-portal pirewall-api pirewall-core` |

More in `docs/SETUP.md` → Troubleshooting, and `docs/v2/RUNBOOK_PI.md` → Undo.
