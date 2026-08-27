"""`FakeFirewallBackend`: an in-memory `FirewallBackend` for tests (spec §39).

Lets the full CANDIDATE -> ... -> ACTIVE lifecycle be tested without root
or a real nftables ruleset. Also exposes `deployed_rules` (beyond the
`FirewallBackend` Protocol) so tests can assert on exactly what was
deployed, not just which IDs are present.
"""

from pirewall.core.exceptions import FirewallError
from pirewall.core.models.rule import FirewallRule


class FakeFirewallBackend:
    """In-memory `FirewallBackend`. `fail_on_apply`/`fail_on_remove` simulate backend failure."""

    def __init__(self, *, fail_on_apply: bool = False, fail_on_remove: bool = False) -> None:
        self.deployed_rules: dict[str, FirewallRule] = {}
        self.fail_on_apply = fail_on_apply
        self.fail_on_remove = fail_on_remove
        self.apply_calls = 0
        self.remove_calls = 0

    def apply_rule(self, rule: FirewallRule) -> None:
        self.apply_calls += 1
        if self.fail_on_apply:
            raise FirewallError(f"simulated apply failure for rule {rule.id}")
        self.deployed_rules[rule.id] = rule

    def remove_rule(self, rule_id: str) -> None:
        self.remove_calls += 1
        if self.fail_on_remove:
            raise FirewallError(f"simulated remove failure for rule {rule_id}")
        self.deployed_rules.pop(rule_id, None)

    def list_active_rule_ids(self) -> frozenset[str]:
        return frozenset(self.deployed_rules.keys())

    def health_check(self) -> bool:
        return True
