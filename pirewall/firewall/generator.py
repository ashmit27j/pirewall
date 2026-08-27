"""`FirewallDecision -> CandidateRule` (spec §22, §23).

Generated rules are as narrow as v1's evidence can support: v1 only ever
has single-flow evidence, so every candidate targets the exact
source/destination `/32` pair the flow used — never a wider network. The
full validation chain (`pirewall.firewall.validator`) independently
enforces this as a hard ceiling too (never trust the generator alone,
CLAUDE.md "no shortcuts, no trusted callers").

`ALLOW` decisions never produce a candidate rule at all — there is nothing
to enforce for traffic pirewall isn't acting on.
"""

from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network

from pirewall.core.enums import FirewallAction, RuleDirection
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.flow import Flow
from pirewall.core.models.rule import CandidateRule


def generate_candidate_rule(
    decision: FirewallDecision, flow: Flow, created_at: datetime, default_ttl_seconds: int
) -> CandidateRule | None:
    """Generate the narrowest possible `CandidateRule` for `decision`, or `None` for `ALLOW`.

    `source_port` is deliberately left unset (matches any): an attacker's
    source port is normally ephemeral and unique per connection, so
    matching on it would make the rule useless against the very next
    connection from the same source. `destination_port` is narrowed to the
    flow's actual port, since that's what the evidence is actually about.
    """
    if decision.action is FirewallAction.ALLOW:
        return None

    assert isinstance(flow.source_ip, IPv4Address)  # Flow is structurally IPv4-only (ADDENDUM.md A5)
    assert isinstance(flow.destination_ip, IPv4Address)

    return CandidateRule(
        decision_id=decision.id,
        action=decision.action,
        direction=RuleDirection.INBOUND,
        source=IPv4Network(f"{flow.source_ip}/32"),
        destination=IPv4Network(f"{flow.destination_ip}/32"),
        protocol=flow.protocol,
        source_port=None,
        destination_port=flow.destination_port,
        reason=decision.reason,
        threat_score=decision.threat_score,
        evidence=decision.evidence,
        created_at=created_at,
        expires_at=created_at + timedelta(seconds=default_ttl_seconds),
        metadata={},
    )
