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
| `dhcpcd-lan.conf.template` | Static IP configuration for the LAN-facing interface | appended to `/etc/dhcpcd.conf` (or the equivalent for your network manager — see below) |
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
   actually match `ip link show` on the target hardware — do not guess.
2. Apply `60-pirewall-forwarding.conf` (sysctl), then `dhcpcd-lan.conf` (or
   your network manager's equivalent static-IP config), then reboot or
   restart networking to confirm the LAN interface comes up with the
   expected static address.
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
