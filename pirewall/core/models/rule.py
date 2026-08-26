"""`CandidateRule` and `FirewallRule` domain models (spec §23, §24, §25).

IPv4-only for v1 (ADDENDUM.md A5): `source`/`destination` are typed
`IPv4Network`, so a rule targeting an IPv6 address/CIDR cannot be
constructed at all — this is a belt-and-suspenders check enforced at the
type level, on top of the explicit validator-stage rejection Phase 6 adds.
"""

from ipaddress import IPv4Network
from uuid import uuid4

from pydantic import AwareDatetime, Field

from pirewall.core.enums import FirewallAction, Protocol, RuleDirection, RuleStatus
from pirewall.core.models.common import PirewallModel


class _RuleFields(PirewallModel):
    """Fields shared by `CandidateRule` and `FirewallRule` (spec §23)."""

    action: FirewallAction
    direction: RuleDirection
    source: IPv4Network
    destination: IPv4Network
    protocol: Protocol
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    reason: str = Field(min_length=1)
    threat_score: float | None = Field(default=None, ge=0.0, le=100.0)
    evidence: tuple[str, ...] = Field(default_factory=tuple)
    metadata: dict[str, str] = Field(default_factory=dict)


class CandidateRule(_RuleFields):
    """A not-yet-validated rule proposed by the candidate rule generator (spec §22).

    Produced directly from a `FirewallDecision`; must pass the full
    validation chain (spec §24, ADDENDUM.md A2/A3) before it can become an
    approved `FirewallRule`.
    """

    id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    decision_id: str = Field(min_length=1)
    created_at: AwareDatetime
    expires_at: AwareDatetime | None = None
    status: RuleStatus = RuleStatus.CANDIDATE


class FirewallRule(_RuleFields):
    """A validated, prioritized rule that has (or will) pass through the firewall backend.

    `priority` and `status` only make sense once validation has run — a
    `CandidateRule` does not have a `priority` because precedence isn't
    determined until the conflict/priority validation stages (spec §24) run.
    """

    id: str = Field(min_length=1)
    priority: int
    status: RuleStatus
    created_at: AwareDatetime
    expires_at: AwareDatetime | None = None
    deployed_at: AwareDatetime | None = None
