"""The `SecurityEvent` domain model (spec §31)."""

from ipaddress import IPv4Address
from uuid import uuid4

from pydantic import AwareDatetime, Field

from pirewall.core.enums import EventSeverity, FirewallAction, Protocol, SecurityEventType
from pirewall.core.models.common import PirewallModel


class SecurityEvent(PirewallModel):
    """A single auditable event, forming the system's security/audit trail.

    Deliberately excludes anything not needed to explain "what happened and
    why" (spec §31 "do not include unnecessary sensitive information") —
    e.g. no raw packet payloads.
    """

    id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    timestamp: AwareDatetime
    severity: EventSeverity
    event_type: SecurityEventType
    subsystem: str = Field(min_length=1)

    source: IPv4Address | None = None
    destination: IPv4Address | None = None
    protocol: Protocol | None = None
    flow_id: str | None = None

    threat_score: float | None = Field(default=None, ge=0.0, le=100.0)
    decision: FirewallAction | None = None
    rule_id: str | None = None

    reason: str | None = None
    model_version: str | None = None
