"""`FirewallDecision -> CandidateRule` (spec §22, §23).

Generated rules are as narrow as v1's evidence can support: v1 only ever
has single-flow evidence, so every candidate targets the exact
source/destination `/32` pair the flow used — never a wider network. The
full validation chain (`pirewall.firewall.validator`) independently
enforces this as a hard ceiling too (never trust the generator alone,
CLAUDE.md "no shortcuts, no trusted callers").

`ALLOW` decisions never produce a candidate rule at all — there is nothing
to enforce for traffic pirewall isn't acting on.

**Device identity (ADDENDUM_4.md D3).** Every candidate also names its
device, `target = RuleTarget(ip=<source>, mac=...)`. The MAC is the one the
binding table holds for the source address, with one exception: when the
flow's opening frame came from a *different* unicast MAC, the source IP was
spoofed, and the target names the frame's sender instead. Keying on the
binding would hand the address's owner a block for traffic someone else
sent (audit item 16). The flow's own MAC is never used without a binding to
compare it against: for a source with no binding (a WAN host, an unbound
device) the frame MAC may be a router's, so the target stays IP-only.
"""

from collections.abc import Callable
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
from typing import Final

from pydantic import TypeAdapter, ValidationError

from pirewall.core.enums import FirewallAction, RuleDirection
from pirewall.core.models.common import UnicastMacAddress
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.flow import Flow
from pirewall.core.models.identity import RuleTarget
from pirewall.core.models.rule import CandidateRule

MacResolver = Callable[[IPv4Address], str | None]
"""IP -> bound MAC, or None (`pirewall.core.bindings.LeaseBindingTable.resolve_mac`)."""

_UNICAST_MAC: Final[TypeAdapter[str]] = TypeAdapter(UnicastMacAddress)


def generate_candidate_rule(
    decision: FirewallDecision,
    flow: Flow,
    created_at: datetime,
    default_ttl_seconds: int,
    resolve_mac: MacResolver | None = None,
) -> CandidateRule | None:
    """Generate the narrowest possible `CandidateRule` for `decision`, or `None` for `ALLOW`.

    `source_port` is deliberately left unset (matches any): an attacker's
    source port is normally ephemeral and unique per connection, so
    matching on it would make the rule useless against the very next
    connection from the same source. `destination_port` is narrowed to the
    flow's actual port, since that's what the evidence is actually about.

    `resolve_mac` fills `target.mac` (module docstring). Without it the
    target is IP-only, which is exactly the v1 behaviour.
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
        target=RuleTarget(ip=flow.source_ip, mac=_target_mac(flow, resolve_mac)),
    )


def _target_mac(flow: Flow, resolve_mac: MacResolver | None) -> str | None:
    bound = resolve_mac(flow.source_ip) if resolve_mac is not None else None
    if bound is None:
        return None
    observed = _unicast_or_none(flow.source_mac)
    if observed is not None and observed != bound:
        return observed  # a spoofed source: the frame's sender, never the address's owner
    return bound


def _unicast_or_none(mac: str | None) -> str | None:
    if mac is None:
        return None
    try:
        return _UNICAST_MAC.validate_python(mac)
    except ValidationError:
        return None
