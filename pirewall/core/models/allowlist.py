"""The `AllowlistEntry` domain model (ADDENDUM.md A2).

Distinct from safety validation (spec §24): safety validation catches
*accidental* self/Admin-PC/LAN/internet lockout, while the allowlist is
*deliberate* admin-declared exceptions that outrank every adaptive rule
unconditionally, regardless of threat score or enforcement mode.
"""

from ipaddress import IPv4Network
from uuid import uuid4

from pydantic import AwareDatetime, Field

from pirewall.core.enums import Protocol
from pirewall.core.models.common import PirewallModel


class AllowlistEntry(PirewallModel):
    """A static, admin-defined target that adaptive BLOCK/RATE_LIMIT rules may never touch.

    IPv4-only per ADDENDUM.md A5, like every other adaptive-pipeline model.
    """

    id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    target: IPv4Network
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Protocol | None = None
    reason: str = Field(min_length=1)
    created_at: AwareDatetime
    created_by: str = Field(min_length=1)
