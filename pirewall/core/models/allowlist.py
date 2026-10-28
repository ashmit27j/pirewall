"""The `AllowlistEntry` domain model (ADDENDUM.md A2).

Distinct from safety validation (spec §24): safety validation catches
*accidental* self/Admin-PC/LAN/internet lockout, while the allowlist is
*deliberate* admin-declared exceptions that outrank every adaptive rule
unconditionally, regardless of threat score or enforcement mode.
"""

from ipaddress import IPv4Network
from uuid import uuid4

from pydantic import AwareDatetime, Field, model_validator

from pirewall.core.enums import Protocol
from pirewall.core.models.common import PirewallModel, UnicastMacAddress


class AllowlistEntry(PirewallModel):
    """A static, admin-defined target that adaptive BLOCK/RATE_LIMIT rules may never touch.

    IPv4-only per ADDENDUM.md A5, like every other adaptive-pipeline model.

    `mac` (ADDENDUM_4.md D3) pins the entry to one device. It protects that
    MAC wherever it is, as well as `target`: the validator refuses a target
    whose IP *or* MAC is allowlisted. An entry with both a `/32` and a MAC
    is also written to the kernel's `allow_bound` sets, which exempt that
    exact pair from the flood meters, after anti-spoof (so the IP cannot be
    borrowed). A MAC only makes sense for one address, so it needs a `/32`.
    """

    id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    target: IPv4Network
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Protocol | None = None
    reason: str = Field(min_length=1)
    created_at: AwareDatetime
    created_by: str = Field(min_length=1)
    mac: UnicastMacAddress | None = None

    @model_validator(mode="after")
    def _check_mac_names_one_device(self) -> "AllowlistEntry":
        if self.mac is not None and self.target.prefixlen != 32:
            raise ValueError("a MAC-pinned allowlist entry must target a single /32 address")
        return self
