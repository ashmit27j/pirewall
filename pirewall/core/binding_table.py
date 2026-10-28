"""The `BindingTable` interface: IP<->MAC resolution for v2 (ADDENDUM_4.md D3).

A Protocol frozen by phase 11 (docs/V2_CONTRACTS.md); phase 14 provides the
implementation and the lease-sync thread that feeds it. It lives in
`pirewall.core` because three layers consult it and none may import another
backwards: the firewall generator and validator (target MAC), the portal
service (client MAC from the peer IP), and the phase-17 D1 detectors
(new-MAC/new-lease rate).

Implementations hold no nft handle. Turning a `BindingChange` into kernel
elements is `FirewallManager.sync_bindings`, the only writer of the binding
sets (D1).
"""

from collections.abc import Sequence
from datetime import datetime
from ipaddress import IPv4Address
from typing import Protocol

from pirewall.core.models.common import MacAddress
from pirewall.core.models.identity import Binding, BindingChange


class BindingTable(Protocol):
    """Current IP<->MAC bindings: lease file entries merged with `[[antispoof.static]]`.

    Merge rule: a static binding always wins. A lease for an IP or a MAC that
    a static entry already names is ignored, never applied, so the
    administrator's declaration cannot be overridden by whatever the DHCP
    server handed out.

    Thread-safety: lease sync writes, many readers read. `snapshot` must
    return an immutable copy so RPC handlers can serve it without holding
    core's RPC lock (V2_CONTRACTS.md "RPC").
    """

    def resolve_mac(self, ip: IPv4Address) -> MacAddress | None:
        """The MAC currently bound to `ip`, or None if nothing binds it."""
        ...

    def resolve_ip(self, mac: MacAddress) -> IPv4Address | None:
        """The IPv4 address currently bound to `mac`, or None if nothing binds it."""
        ...

    def snapshot(self) -> tuple[Binding, ...]:
        """Every live binding, static and lease, as an immutable copy."""
        ...

    def apply_leases(self, leases: Sequence[Binding], now: datetime) -> BindingChange:
        """Replace the lease-sourced bindings with `leases` and return what changed.

        `leases` is the full current lease set (already parsed; only MAC, IP
        and expiry, never hostname or client-id). Entries whose `expires_at`
        is not after `now` are treated as absent. Static bindings are
        untouched. The returned `BindingChange` lists removals before
        additions, and a changed pair appears as a removal of the old pair
        plus an addition of the new one.
        """
        ...
