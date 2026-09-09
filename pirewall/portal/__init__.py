"""pirewall-portal: the LAN-facing captive portal (ADDENDUM_3.md C1).

Nothing in this package may import `pirewall.capture`,
`pirewall.firewall.backend`, or `pirewall.firewall.manager` — the same
import-graph rule ADDENDUM.md A4 places on `pirewall/api/` and
`pirewall/web/`, for the stronger reason that this process is the one
untrusted LAN clients actually talk to. Enforced by
`tests/security/test_api_process_isolation.py`.
"""
