# `deploy/network/` — gateway network configuration templates

Spec §21 (Gateway Configuration): "Do not automatically modify network
configuration without explicit configuration." `CLAUDE.md`: "Never
auto-modify network configuration." Nothing in this repository runs these
files. They are **templates a human reviews, fills in, and applies by hand**
(or via `scripts/deployment/render_templates.py`, which only *renders*
substituted files to `deploy/rendered/` — it never applies anything).

## Files

| File | Purpose | Applied via |
|------|---------|--------------|
| `60-pirewall-forwarding.conf.template` | Enables IPv4 forwarding (ADDENDUM.md A5 — IPv4-only for v1; IPv6 forwarding is deliberately left disabled) | `/etc/sysctl.d/60-pirewall-forwarding.conf` + `sysctl --system` |
| `dhcpcd-lan.conf.template` | Static IP for the LAN interface, **Bullseye and older only** | appended to `/etc/dhcpcd.conf`. Raspberry Pi OS Bookworm+ uses NetworkManager — use `nmcli` instead, see `docs/DEPLOYMENT.md` §4 step 2 |
| `nat-masquerade.nft.template` | NAT/masquerading so protected-LAN clients can reach the WAN | loaded via `nft -f` into its own table, separate from `deploy/firewall/base.nft.template` and the `pirewall`/`adaptive` table `pirewall.firewall.backend.nftables.NftablesBackend` manages at runtime |

## Placeholders

Every template uses `${TOKEN}` placeholders that map directly to
`pirewall.config.models.NetworkConfig`/`AdminConfig`/`APIConfig` fields:

```text
${WAN_INTERFACE}       network.wan_interface
${LAN_INTERFACE}       network.lan_interface
${PROTECTED_NETWORK}   network.protected_network   (CIDR, e.g. 192.168.1.0/24)
${UPSTREAM_GATEWAY}    network.upstream_gateway
${ADMIN_PC_IP}         admin.admin_pc_ip
${API_PORT}            api.port
```

Render them from your real (not the placeholder) `config/local_config.toml`
with:

```sh
uv run python -m scripts.deployment.render_templates --config config/local_config.toml
```

This writes substituted copies under `deploy/rendered/` — it does not touch
`/etc`, `nft`, or any live interface. Review every rendered file before
applying it by hand on the Pi.

## Order of operations on the real Pi

1. Confirm `network.wan_interface`/`network.lan_interface` in your config
   actually match `ip link show` on the target hardware — do not guess. If
   both are `wlan`-named, use `ethtool -i <iface>` to tell the onboard Pi
   radio (`brcmfmac`) from a USB dongle (`rtl8xxxu`/`8188eu`); USB probe
   order makes `wlan0`/`wlan1` unstable across reboots
   (`docs/DEPLOYMENT.md` §4.1).
2. Apply `60-pirewall-forwarding.conf` (sysctl), then bring up both sides.
   **Each side may independently be wired or wireless** — a wired or
   Wi-Fi-client WAN, and a static-Ethernet or Wi-Fi-AP LAN;
   `docs/DEPLOYMENT.md` §4.3/§4.4 documents all four combinations. Either
   way this is `nmcli` on Bookworm and later, and `dhcpcd-lan.conf` only on
   Bullseye and older with a wired LAN (see the table above). Then confirm
   the LAN interface came up with the expected address — for a Wi-Fi AP,
   that means overriding `nmcli device wifi hotspot`'s default
   `10.42.0.1/24` onto `network.protected_network` — and that the default
   route still points at `upstream_gateway` on the WAN side.

   These templates substitute interface *names* only; nothing in them or in
   `pirewall/` distinguishes wired from wireless (`docs/DEPLOYMENT.md`
   §4.6). Switching a side between the two later means re-rendering these
   templates if the name changed, and nothing else.
3. Load `deploy/firewall/base.nft.template` (see that directory's README)
   **before** `nat-masquerade.nft.template` — the base ruleset's
   deny-by-default forwarding posture should exist before NAT starts
   forwarding traffic.
4. Only then start `pirewall-core.service`, which bootstraps its own
   `pirewall`/`adaptive` nftables table on top of the base ruleset (see
   `deploy/systemd/README.md`).

None of this is exercised by this repository's test suite beyond static
template-rendering tests — applying it on real hardware and confirming
routing/forwarding/NAT actually work end-to-end is **Environment-dependent**
(see `docs/PROGRESS.md`).
