# `deploy/firewall/` — base nftables ruleset template

Spec §24/§27, ADDENDUM.md. **Not applied automatically** — a human reviews,
renders, and loads this by hand. See `../network/README.md` for the
`scripts/deployment/render_templates.py` rendering command; it writes a
substituted copy to `deploy/rendered/base.nft` and touches nothing else.

## What this is (and isn't)

`base.nft.template` establishes the *default posture*:

- deny-by-default forwarding (`policy drop` on the `forward` chain) —
  nothing crosses WAN <-> LAN unless explicitly allowed or already
  established/related,
- deny-by-default input (`policy drop` on the `input` chain) — management
  access (SSH, the control panel/API) is restricted to
  `admin.admin_pc_ip` only.

It is **not** where pirewall's adaptive, threat-driven rules live.
`pirewall.firewall.backend.nftables.NftablesBackend` bootstraps and manages
its own separate `inet pirewall` table (chain `adaptive`, hook `forward`,
priority 0) at runtime, through the fully validated
Threat Assessment -> CandidateRule -> Validation -> FirewallBackend pipeline
(spec §22) — this file must never be hand-edited to add rules that pipeline
should be producing, and nothing in `pirewall/` writes to this file or this
table.

## Why the adaptive chain runs *before* this one

`base.nft.template`'s `forward` chain uses `priority 10`; the adaptive
chain uses `priority 0`. Lower priority numbers are evaluated first in
nftables, so a narrow adaptive `BLOCK`/`RATE_LIMIT` rule for one specific
flagged flow gets first say — including overriding traffic this base
ruleset would otherwise allow (e.g. a LAN device's outbound connection to a
now-flagged destination). Only traffic the adaptive chain doesn't
terminally accept/drop falls through to this file's broader policy.

## Load order on the real Pi

1. `../network/60-pirewall-forwarding.conf.template` (sysctl — IP
   forwarding must be on before any of this does anything)
2. `base.nft.template` (this file)
3. `../network/nat-masquerade.nft.template`
4. start `pirewall-core.service` (see `../systemd/README.md`), which
   bootstraps the `inet pirewall` adaptive table on first rule deployment

## Verification

- **Tested** (this repository): `tests/security/test_firewall_base_template.py`
  statically parses this file and asserts the `forward` and `input` chains
  default to `policy drop`, and that management access is scoped to the
  `${ADMIN_PC_IP}` placeholder rather than left open.
- **Environment-dependent**: actually loading this on a real Pi with a real
  `nft` binary, confirming syntax is accepted (`nft -c -f`), and confirming
  real traffic is filtered as intended — a human must do this on the target
  hardware. See `docs/DEPLOYMENT.md`.
