"""Device identity for v2: rule targets and IP<->MAC bindings (ADDENDUM_4.md D3).

Contract stubs frozen by phase 11 (docs/V2_CONTRACTS.md). Phase 14 wires
them into the rule models, the generator, the portal and lease sync; nothing
reads them yet.

IPv4-only, like every adaptive-pipeline model (ADDENDUM.md A5).
"""

from ipaddress import IPv4Address

from pydantic import AwareDatetime, Field, model_validator

from pirewall.core.enums import BindingSource
from pirewall.core.models.common import PirewallModel, UnicastMacAddress


class RuleTarget(PirewallModel):
    """The device an adaptive action is about: always an IPv4 address, plus its MAC when known.

    `mac` is None when no binding resolves the IP; enforcement then falls
    back to the IP-keyed sets (`block4`). When it is set, enforcement prefers
    the MAC-keyed sets (`block_mac`, `ratelimit_mac`), because a MAC survives
    the device changing address and cannot be framed by a spoofed source IP
    once anti-spoof is enforcing (D3).
    """

    ip: IPv4Address
    mac: UnicastMacAddress | None = None


class Binding(PirewallModel):
    """One IP<->MAC pair the anti-spoof guard treats as legitimate (D3).

    `expires_at` is the lease expiry for `LEASE` bindings, and becomes the nft
    element timeout. `STATIC` bindings (from `[[antispoof.static]]`) never
    expire, so they carry None.
    """

    ip: IPv4Address
    mac: UnicastMacAddress
    source: BindingSource
    expires_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _check_expiry_matches_source(self) -> "Binding":
        if self.source is BindingSource.LEASE and self.expires_at is None:
            raise ValueError("a lease binding needs expires_at (its element timeout)")
        if self.source is BindingSource.STATIC and self.expires_at is not None:
            raise ValueError("a static binding never expires; expires_at must be None")
        return self


class BindingChange(PirewallModel):
    """What one `BindingTable.apply_leases` call changed, in the order it must reach the kernel.

    `removed` is applied before `added` in the same nft batch. A lease that
    moved to a new MAC therefore stops being honoured for the old device
    before the new device is bound (critique_safety_eval.md A6).
    """

    removed: tuple[Binding, ...] = Field(default_factory=tuple)
    added: tuple[Binding, ...] = Field(default_factory=tuple)
