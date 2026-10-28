"""`PolicyDecision`: what the v2 policy table decided for one device (ADDENDUM_4.md D4).

Contract stub frozen by phase 11 (docs/V2_CONTRACTS.md); the policy engine
that produces it is phase 17. It replaces score-driven action selection
under `pipeline.engine = "v2"`: the action comes from the policy table, and
`threat_level` is *derived from the action* for the dashboard and API, the
reverse of v1's level -> action ladder (`pirewall.engine.decision`).

A `PolicyDecision` is still only a decision. It reaches the kernel only
through the validator chain and `FirewallManager`, the single deploy path.
"""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final
from uuid import uuid4

from pydantic import AwareDatetime, Field, model_validator

from pirewall.core.enums import FirewallAction, ThreatLevel
from pirewall.core.models.common import PirewallModel
from pirewall.core.models.identity import RuleTarget

MAX_ELEMENT_TTL_SECONDS: Final = 3600
"""Hard ceiling on any adaptive element's timeout (template invariant); `policy.max_ttl_seconds` <= this."""

ML_ONLY_ACTION_CEILING: Final = FirewallAction.MONITOR
"""The strongest action D2/D3 evidence can cause without D1 or enforce-mode K evidence (D4)."""

THREAT_LEVEL_BY_ACTION: Final[Mapping[FirewallAction, ThreatLevel]] = MappingProxyType(
    {
        FirewallAction.ALLOW: ThreatLevel.LOW,
        FirewallAction.MONITOR: ThreatLevel.MEDIUM,
        FirewallAction.RATE_LIMIT: ThreatLevel.HIGH,
        FirewallAction.BLOCK: ThreatLevel.CRITICAL,
    }
)
"""UI compatibility: the exact inverse of v1's `_ACTION_BY_LEVEL`, so v1 and v2 rows read alike."""

_ENFORCING_ACTIONS: Final = frozenset({FirewallAction.RATE_LIMIT, FirewallAction.BLOCK})


class PolicyDecision(PirewallModel):
    """One policy-table outcome for one device.

    * `ttl_seconds` is the element timeout the action would carry; required
      for RATE_LIMIT/BLOCK (every adaptive element expires), None otherwise.
    * `reasons` are human-readable lines for the audit log and the C4 notice.
    * `evidence_ids` name the evidence that justified the action
      (`pirewall.core.models.evidence_v2.evidence_id`); escalation needs at
      least one id not used by an earlier decision for the same target.
    * `requires_approval` routes a BLOCK to the A7 approval queue.
    """

    id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    target: RuleTarget
    action: FirewallAction
    ttl_seconds: int | None = Field(default=None, gt=0, le=MAX_ELEMENT_TTL_SECONDS)
    reasons: tuple[str, ...] = Field(min_length=1)
    evidence_ids: tuple[str, ...] = Field(default_factory=tuple)
    requires_approval: bool = False
    decided_at: AwareDatetime
    # Derived from `action`, never from a score. Stored rather than computed
    # so a serialized decision round-trips under `extra="forbid"`; filled in
    # when omitted, and refused when it disagrees with `action`.
    threat_level: ThreatLevel | None = None

    @model_validator(mode="after")
    def _check_consistency(self) -> "PolicyDecision":
        expected_level = THREAT_LEVEL_BY_ACTION[self.action]
        if self.threat_level is None:
            self.threat_level = expected_level
        elif self.threat_level is not expected_level:
            raise ValueError(f"threat_level for {self.action.value} is {expected_level.value}")
        if self.action in _ENFORCING_ACTIONS:
            if self.ttl_seconds is None:
                raise ValueError("RATE_LIMIT and BLOCK need ttl_seconds: every adaptive element expires")
            if not self.evidence_ids:
                raise ValueError("an enforcing decision must name the evidence behind it")
        elif self.ttl_seconds is not None:
            raise ValueError("only RATE_LIMIT and BLOCK carry a ttl_seconds")
        if self.requires_approval and self.action is not FirewallAction.BLOCK:
            raise ValueError("only BLOCK goes to the approval queue (ADDENDUM.md A7)")
        return self
