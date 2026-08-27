# pirewall

An AI-assisted adaptive network firewall for a Raspberry Pi 4. It captures
traffic on the protected LAN, extracts flow-level features, scores threats
with LightGBM (known-attack classification) and Isolation Forest (anomaly
detection) plus deterministic behavioral analysis, and turns high-confidence
assessments into validated, auditable nftables rules — with a shadow/dry-run
mode, a static allowlist, and a kill-switch so the adaptive system can never
be the only thing standing between you and your own network.

## Architecture, in one line

```text
Packet -> Flow -> Features -> [LightGBM + Isolation Forest + Behavior]
       -> Threat Assessment -> Decision -> Candidate Rule -> Validation
       -> nftables
```

Detection, decision, and enforcement are kept as separate layers throughout
— the ML layer only ever produces evidence, never a firewall rule or a
shell command. See `docs/ARCHITECTURE.md` for the full pipeline diagram and
module boundaries.

Two separate OS processes: `pirewall-core` (packet capture, detection,
firewall enforcement — runs with exactly the Linux capabilities it needs)
and `pirewall-api` (the FastAPI control panel — runs with *no* raw-socket
or firewall capabilities at all), talking over a narrow local RPC protocol.
See `docs/SECURITY.md`.

## Safety posture

- **Shadow mode by default** — the full pipeline runs, but nothing deploys
  to nftables until you've reviewed the shadow log and moved to assisted
  or active enforcement.
- **Static allowlist** outranks every adaptive rule, unconditionally.
- **Rate-capped rule creation** — detection keeps running at full fidelity
  even under a flood; only rule *creation* is bounded.
- **Fail-open by default** — a `pirewall-core` crash never silently cuts
  household internet access.
- **Kill-switch** — one authenticated action reverts to the static base
  ruleset and every adaptive rule.

Full detail in `docs/ADDENDUM.md`.

## Documentation map

| Doc | Covers |
|---|---|
| `docs/MASTER_SPEC.md` | The original, frozen specification. |
| `docs/ADDENDUM.md` | Safety-oriented additions on top of the spec (wins on conflict). |
| `docs/PROGRESS.md` | Phase-by-phase implementation status, with honest Implemented/Tested/Mocked/Environment-dependent/Not-yet-validated labels. |
| `docs/ARCHITECTURE.md` | Pipeline diagram, module boundaries, dependency decisions. |
| `docs/FEATURE_SCHEMA.md` | The canonical 29-feature schema, feature by feature. |
| `docs/ML_PIPELINE.md` | Dataset adapters, training, model artifacts, runtime inference. |
| `docs/FIREWALL.md` | Decision engine, candidate generation, the 10-stage validation chain, rule lifecycle. |
| `docs/API.md` | Every API endpoint, the auth model, the control panel. |
| `docs/TESTING.md` | How to run each test tier, the Protocol+Fake pattern, what's Fake vs. real-hardware-verified. |
| `docs/SECURITY.md` | Hardening, the two-process privilege split, threat model, resource-exhaustion protections. |
| `docs/DEPLOYMENT.md` | Step-by-step real Raspberry Pi deployment. |
| `docs/DEVELOPMENT_WORKFLOW.md` | The per-subsystem development loop this project follows. |

## Platform support

Three machines are involved, with different requirements:

| Role | Platform | Notes |
|---|---|---|
| **Enforcement box** | Raspberry Pi 4, **64-bit** Raspberry Pi OS | 4 GB is comfortable — a full flow table measures ~93 MiB against a 768 MiB unit cap. arm64 is required: `numpy`/`scipy`/`scikit-learn`/`lightgbm` ship `aarch64` wheels but not 32-bit `armv7l`. |
| **Admin PC** | Any Linux (Arch/Omarchy, Debian, Fedora…) | Runs Wazuh and Netdata and views the control panel. Both integrations are plain network protocols (TCP syslog, UDP StatsD), so nothing is distro-specific — see `docs/DEPLOYMENT.md` §8, which includes Arch notes since Wazuh has no official Arch package. |
| **Development** | Linux or macOS | The full suite runs on both. The Linux-only modules (`AFPacketCapture`, `NftablesBackend`) import cleanly everywhere and are exercised through their `Fake` counterparts; the `AF_UNIX` RPC transport is genuinely tested on any POSIX host. Windows can run most of the suite but skips the socket tests. |

**Python 3.12+ is required**, and on the Pi it must come from `uv`, not
`apt`: Raspberry Pi OS Bookworm is Debian 12 and ships Python 3.11, with no
`python3.12` package. `uv python install 3.12` fetches a standalone
`aarch64` build. See `docs/DEPLOYMENT.md` §2.

## Getting started (development)

```sh
uv sync                                     # install dependencies
uv run pytest                               # run the full test suite
uv run ruff check .                         # lint
uv run pyright                              # strict type check
uv run python -m scripts.diagnostics.performance_smoke   # performance smoke pass
```

None of the above touches real network configuration, systemd state, or a
real nftables ruleset — every hardware-dependent component (packet
capture, the nftables backend, the inter-process RPC socket) is a
`Protocol` with a real implementation and a `Fake` used throughout testing
(spec §39, `docs/TESTING.md`).

## Deploying to a real Raspberry Pi

See `docs/DEPLOYMENT.md` for the full step-by-step guide (OS setup,
network/firewall templates, systemd units, certificates, Admin PC-side
Wazuh/Netdata configuration, secure update procedure) and
`docs/SECURITY.md` for the hardening rationale behind it. Nothing in this
repository applies any of that automatically — every template under
`deploy/` is reviewed and applied by a human.

## Project status

See `docs/PROGRESS.md` for the authoritative, phase-by-phase status with
honest labels on what's tested, what's mocked, and what's genuinely
Environment-dependent pending real Raspberry Pi hardware.
