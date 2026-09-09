"""`FakeFirewallBackend`: an in-memory `FirewallBackend` for tests (spec §39).

Lets the full CANDIDATE -> ... -> ACTIVE lifecycle be tested without root
or a real nftables ruleset. Also exposes `deployed_rules` (beyond the
`FirewallBackend` Protocol) so tests can assert on exactly what was
deployed, not just which IDs are present.
"""

from datetime import datetime, timedelta
from ipaddress import IPv4Address

from pirewall.core.exceptions import FirewallError
from pirewall.core.models.rule import FirewallRule


class FakeFirewallBackend:
    """In-memory `FirewallBackend`. `fail_on_apply`/`fail_on_remove` simulate backend failure."""

    def __init__(
        self,
        *,
        fail_on_apply: bool = False,
        fail_on_remove: bool = False,
        fail_on_portal: bool = False,
    ) -> None:
        self.deployed_rules: dict[str, FirewallRule] = {}
        self.fail_on_apply = fail_on_apply
        self.fail_on_remove = fail_on_remove
        self.fail_on_portal = fail_on_portal
        self.apply_calls = 0
        self.remove_calls = 0
        # Portal set elements carry an expiry so the fake can model the one
        # behaviour that matters most about the real set: the kernel drops
        # elements on its own, without pirewall being told (ADDENDUM_3.md C2).
        self.portal_clients: dict[IPv4Address, datetime | None] = {}
        self.portal_authorize_calls = 0
        self.portal_deauthorize_calls = 0
        self._now: datetime | None = None

    def set_clock(self, now: datetime) -> None:
        """Drive element expiry in tests. Without this the fake never expires anything."""
        self._now = now

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

    def authorize_portal_client(self, client_ip: IPv4Address, timeout_seconds: int) -> None:
        self.portal_authorize_calls += 1
        if self.fail_on_portal:
            raise FirewallError(f"simulated portal authorize failure for {client_ip}")
        expires_at = self._now + timedelta(seconds=timeout_seconds) if self._now is not None else None
        self.portal_clients[client_ip] = expires_at

    def deauthorize_portal_client(self, client_ip: IPv4Address) -> None:
        self.portal_deauthorize_calls += 1
        if self.fail_on_portal:
            raise FirewallError(f"simulated portal deauthorize failure for {client_ip}")
        self.portal_clients.pop(client_ip, None)

    def list_portal_clients(self) -> frozenset[IPv4Address]:
        if self._now is None:
            return frozenset(self.portal_clients)
        live = {
            ip
            for ip, expires_at in self.portal_clients.items()
            if expires_at is None or expires_at > self._now
        }
        # Model the kernel actually removing them, not just hiding them.
        self.portal_clients = {ip: self.portal_clients[ip] for ip in live}
        return frozenset(live)
