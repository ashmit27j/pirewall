"""The `FirewallBackend` contract (spec §20).

Contract only — no shell-command construction here. Exactly one caller may
use an implementation of this Protocol: `pirewall.firewall.manager`
(CLAUDE.md "Exactly one authorized code path may deploy to the firewall
backend").
"""

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
