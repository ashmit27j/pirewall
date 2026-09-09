"""The `FirewallBackend` contract (spec §20).

Contract only — no shell-command construction here. Exactly one caller may
use an implementation of this Protocol: `pirewall.firewall.manager`
(CLAUDE.md "Exactly one authorized code path may deploy to the firewall
backend").
"""

from ipaddress import IPv4Address
from typing import Protocol, runtime_checkable

from pirewall.core.models.rule import FirewallRule


@runtime_checkable
class FirewallBackend(Protocol):
    """Contract for applying/removing/inspecting firewall rules.

    `list_active_rule_ids` returns IDs, not full `FirewallRule` objects —
    the backend enforces rules, it is not the source of truth for rule
    metadata (status, reason, threat score, ...); that's
    `pirewall.firewall.manager`'s `RuleStore`. Real backends generally
    can't reconstruct that metadata from the underlying ruleset anyway.
    """

    def apply_rule(self, rule: FirewallRule) -> None:
        """Deploy `rule`. Raises `pirewall.core.exceptions.FirewallError` on failure."""
        ...

    def remove_rule(self, rule_id: str) -> None:
        """Remove a previously applied rule by id. Idempotent: removing an unknown id is a no-op."""
        ...

    def list_active_rule_ids(self) -> frozenset[str]:
        """IDs of rules currently deployed in the backend."""
        ...

    def health_check(self) -> bool:
        """True if the backend is reachable and operating normally."""
        ...

    def authorize_portal_client(self, client_ip: IPv4Address, timeout_seconds: int) -> None:
        """Add `client_ip` to the captive portal's authorized set (ADDENDUM_3.md C2).

        `timeout_seconds` is handed to the kernel as the set element's own
        timeout, so the session expires without pirewall running a timer,
        polling, or spawning anything to clean it up. That is the whole
        reason this is a set element rather than a `FirewallRule`: a rule
        would need the full validated lifecycle and an expiry sweep, for
        state that nftables already expires for free.

        Portal set elements are **not** adaptive rules. They never enter the
        `RuleStatus` lifecycle, never consume the ADDENDUM.md A3 rate cap,
        and are never derived from ML output — they encode "this address
        logged in", nothing more.

        Raises `pirewall.core.exceptions.FirewallError` on failure.
        """
        ...

    def deauthorize_portal_client(self, client_ip: IPv4Address) -> None:
        """Remove `client_ip` from the portal's authorized set. Idempotent."""
        ...

    def list_portal_clients(self) -> frozenset[IPv4Address]:
        """Addresses currently in the portal's authorized set.

        The kernel is the source of truth here, not pirewall's in-memory
        session table: elements expire without telling us, so anything that
        needs to know who is actually authorized must ask the backend.
        """
        ...
