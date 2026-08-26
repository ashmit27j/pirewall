# pirewall

An AI-assisted adaptive network firewall for a Raspberry Pi 4. It captures
traffic on the protected LAN, extracts flow-level features, scores threats
with LightGBM (known-attack classification) and Isolation Forest (anomaly
detection), and turns high-confidence assessments into validated, auditable
nftables rules — with a shadow/dry-run mode, a static allowlist, and a
kill-switch so the adaptive system can never be the only thing standing
between you and your own network.

See `docs/MASTER_SPEC.md` for the full specification and `docs/ADDENDUM.md`
for the safety-oriented additions on top of it. `docs/PROGRESS.md` tracks
current implementation status phase by phase.
