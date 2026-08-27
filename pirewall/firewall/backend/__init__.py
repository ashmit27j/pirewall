"""Firewall backend implementations (nftables, fake).

CLAUDE.md: "Exactly one authorized code path may deploy to the firewall
backend. Nothing else calls into firewall/backend/." Only
`pirewall.firewall.manager` (and tests) may import from this package —
enforced by `tests/security/test_backend_isolation.py`.
"""

from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.nftables import NftablesBackend

__all__ = ["FakeFirewallBackend", "NftablesBackend"]
