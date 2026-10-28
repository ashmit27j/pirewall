"""The full candidate-rule validation chain, in order (spec §24, ADDENDUM.md).

Order (ADDENDUM.md, updated from spec §24's base order): schema -> network
-> allowlist -> safety -> conflict -> duplicate -> rate-cap -> priority ->
expiration -> authorization. Every stage is a separate function so each is
independently testable; `validate_candidate_rule` is the only thing that
chains them, short-circuiting on the first rejection. A rejected candidate
is never silently dropped — the caller (`pirewall.firewall.manager`)
records exactly which stage rejected it and why.

The safety stage protects four distinct addresses/ranges, each with its own
independent check (spec §24): the Admin PC (`admin.admin_pc_ip`), pirewall
itself and therefore management access (`network.pirewall_lan_ip`), the
upstream gateway and therefore all internet reachability
(`network.upstream_gateway`), and the protected LAN as a whole
(`network.protected_network`), plus a minimum-prefix floor so no rule is
broader than the single-flow evidence that generated it.

An earlier phase folded "pirewall itself"/"management access" into the
Admin-PC-IP check on the reasoning that management access *is* "reach the
Pi from the Admin PC". A later audit found that insufficient — the Admin PC
is the *client* end of that connection, so a rule targeting the Pi's own
address (the *server* end, and every LAN client's default gateway) passed
every check. `pirewall_lan_ip` and `upstream_gateway` now get their own
checks; see docs/PROGRESS.md "Known deviations from spec".

A later field session found the same gap once more, from the other
direction: configuration names *some* of the Pi's addresses, never all of
them. A Pi routing between a LAN AP, a WAN uplink and a wired admin link
holds three, and the WAN one is a DHCP lease nobody writes down — six
`BLOCK` rules against the Pi's own WAN address reached the approval queue.
The safety stage therefore also consults
`pirewall.firewall.local_addresses`, the kernel's own view of which
addresses this host holds, and rejects any candidate naming one of them or
a local broadcast address. That source degrades to empty (leaving the
configured checks exactly as they were) rather than failing.

The same stage rejects candidates naming an address no host can own —
`0.0.0.0`, `255.255.255.255`, multicast, loopback, link-local. Such a rule
is never enforceable and never evidence-backed;
`pirewall.flow.aggregator` already keeps that traffic out of the pipeline,
but safety validation is not permitted to assume an upstream layer was
careful.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Network

from pirewall.config.models import PirewallConfig
from pirewall.core.enums import FirewallAction, RuleRejectionReason, RuleStatus
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.identity import RuleTarget
from pirewall.core.models.rule import CandidateRule, FirewallRule
from pirewall.firewall.local_addresses import LocalAddresses, cached_local_addresses
from pirewall.firewall.rate_limiter import RuleCreationRateLimiter

_WHOLE_INTERNET = IPv4Network("0.0.0.0/0")
_RESTRICTIVE_ACTIONS = (FirewallAction.BLOCK, FirewallAction.RATE_LIMIT)


@dataclass(frozen=True, slots=True)
class ValidationRejection:
    """Which stage rejected a candidate, and why."""

    stage: str
    reason: RuleRejectionReason


@dataclass(frozen=True, slots=True)
class ValidationOutcome:
    """The result of running the full chain: either approved with a priority, or rejected."""

    approved: bool
    priority: int | None = None
    rejection: ValidationRejection | None = None


def validate_candidate_rule(
    candidate: CandidateRule,
    *,
    config: PirewallConfig,
    known_decision_ids: Sequence[str],
    active_rules: Sequence[FirewallRule],
    allowlist: Sequence[AllowlistEntry],
    rate_limiter: RuleCreationRateLimiter,
    now: datetime,
    local_addresses: LocalAddresses | None = None,
) -> ValidationOutcome:
    """Run the full validation chain against `candidate`, in order.

    `local_addresses` overrides the safety stage's view of which addresses
    this host holds; when omitted it is read from the kernel (see
    `pirewall.firewall.local_addresses`). Tests pass it explicitly so their
    result does not depend on the addressing of the machine they run on.

    Each stage is only *called* once it's actually its turn — building an
    eagerly-evaluated tuple of call results here would run every stage
    regardless of an earlier rejection, defeating short-circuiting (and,
    for stages that assume an earlier stage already ruled out a bad input,
    could crash instead of cleanly rejecting).
    """
    checks: tuple[tuple[str, Callable[[], RuleRejectionReason | None]], ...] = (
        ("schema", lambda: _validate_schema(candidate)),
        ("network", lambda: _validate_network(candidate)),
        ("allowlist", lambda: _validate_allowlist(candidate, allowlist)),
        ("safety", lambda: _validate_safety(candidate, config, local_addresses)),
        ("conflict", lambda: _validate_conflict(candidate, active_rules)),
        ("duplicate", lambda: _validate_duplicate(candidate, active_rules)),
        ("rate_cap", lambda: _validate_rate_cap(rate_limiter, now)),
        ("priority", lambda: _validate_priority(candidate, active_rules)),
        ("expiration", lambda: _validate_expiration(candidate)),
        ("authorization", lambda: _validate_authorization(candidate, known_decision_ids)),
    )
    for stage_name, check in checks:
        reason = check()
        if reason is not None:
            return ValidationOutcome(approved=False, rejection=ValidationRejection(stage_name, reason))
    return ValidationOutcome(approved=True, priority=_assign_priority(candidate))


def _validate_schema(candidate: CandidateRule) -> RuleRejectionReason | None:
    # Field-level validity is already guaranteed by CandidateRule's Pydantic
    # model (Phase 1). This stage adds the one cross-field check that model
    # can't express on its own: an adaptive rule must carry the threat score
    # that justified it.
    if candidate.threat_score is None:
        return RuleRejectionReason.INVALID_SCHEMA
    return None


def _validate_network(candidate: CandidateRule) -> RuleRejectionReason | None:
    # Belt-and-suspenders (ADDENDUM.md A5): CandidateRule.source/destination
    # are typed IPv4Network, so pyright correctly considers this check
    # unreachable given the type system today — it's intentional insurance
    # against a caller bypassing Pydantic validation entirely (e.g. via
    # model_construct) or a future refactor loosening the field type.
    is_valid = isinstance(candidate.source, IPv4Network) and isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        candidate.destination, IPv4Network
    )
    if not is_valid:
        return RuleRejectionReason.INVALID_NETWORK
    return None


def _validate_allowlist(
    candidate: CandidateRule, allowlist: Sequence[AllowlistEntry]
) -> RuleRejectionReason | None:
    if candidate.action not in _RESTRICTIVE_ACTIONS:
        return None
    for entry in allowlist:
        if _matches_allowlist(candidate, entry):
            return RuleRejectionReason.ALLOWLISTED
    return None


def _matches_allowlist(candidate: CandidateRule, entry: AllowlistEntry) -> bool:
    if entry.protocol is not None and entry.protocol != candidate.protocol:
        return False
    source_match = candidate.source.overlaps(entry.target) and (
        entry.port is None or entry.port == candidate.source_port
    )
    destination_match = candidate.destination.overlaps(entry.target) and (
        entry.port is None or entry.port == candidate.destination_port
    )
    return source_match or destination_match


def _validate_safety(
    candidate: CandidateRule,
    config: PirewallConfig,
    local_addresses: LocalAddresses | None = None,
) -> RuleRejectionReason | None:
    if candidate.action not in _RESTRICTIVE_ACTIONS:
        return None

    # No rule may ever name an address that is not a routable unicast host
    # address: the unspecified address, the limited broadcast address,
    # multicast, loopback, link-local. Such a rule cannot be backed by
    # single-host evidence and cannot describe a real peer.
    for network in (candidate.source, candidate.destination):
        if not _is_targetable_network(network):
            return RuleRejectionReason.UNSAFE

    # spec §24 "blocking pirewall itself": every address this host actually
    # holds, as the kernel reports it — not just the ones configuration
    # happens to name. Empty when unavailable, which changes nothing.
    resolved_local = cached_local_addresses() if local_addresses is None else local_addresses
    for address in (*resolved_local.host, *resolved_local.broadcast):
        own = IPv4Network(f"{address}/32")
        if candidate.source.overlaps(own) or candidate.destination.overlaps(own):
            return RuleRejectionReason.UNSAFE

    admin_pc = IPv4Network(f"{config.admin.admin_pc_ip}/32")
    if candidate.source.overlaps(admin_pc) or candidate.destination.overlaps(admin_pc):
        return RuleRejectionReason.UNSAFE

    # spec §24 "blocking pirewall itself" / "blocking management access".
    # Protecting the Admin PC's address alone is NOT sufficient: that's the
    # *client* end of a management connection. A rule targeting the Pi's own
    # LAN address — the *server* end, and every LAN client's default gateway
    # — kills the control panel and all LAN routing while leaving
    # `admin_pc_ip` untouched, so it needs its own independent check.
    pirewall_self = IPv4Network(f"{config.network.pirewall_lan_ip}/32")
    if candidate.source.overlaps(pirewall_self) or candidate.destination.overlaps(pirewall_self):
        return RuleRejectionReason.UNSAFE

    # spec §24 "blocking the entire internet". The `0.0.0.0/0` check below
    # only catches the literal all-addresses rule; blocking the upstream
    # gateway achieves the same outage with a /32, since every packet
    # leaving the protected network transits it.
    upstream = IPv4Network(f"{config.network.upstream_gateway}/32")
    if candidate.source.overlaps(upstream) or candidate.destination.overlaps(upstream):
        return RuleRejectionReason.UNSAFE

    protected = config.network.protected_network
    if _covers(candidate.source, protected) or _covers(candidate.destination, protected):
        return RuleRejectionReason.UNSAFE

    if candidate.source == _WHOLE_INTERNET or candidate.destination == _WHOLE_INTERNET:
        return RuleRejectionReason.UNSAFE

    min_prefix = config.firewall.min_rule_prefix_length
    if candidate.source.prefixlen < min_prefix or candidate.destination.prefixlen < min_prefix:
        return RuleRejectionReason.UNSAFE

    return None


def _is_targetable_network(network: IPv4Network) -> bool:
    """True if every address in `network` could be a real host a rule may name.

    A `/32` is judged on its single address. A wider prefix is judged on
    both ends, which is enough to catch a candidate that reaches into
    multicast, loopback or link-local space from either side.
    """
    for address in (network.network_address, network.broadcast_address):
        if (
            address.is_unspecified
            or address.is_loopback
            or address.is_multicast
            or address.is_link_local
            or address.is_reserved
        ):
            return False
    return True


def _covers(candidate_network: IPv4Network, target: IPv4Network) -> bool:
    """True if `candidate_network` is target itself or a strict supernet of it."""
    return candidate_network == target or candidate_network.supernet_of(target)


def _target_key(rule: CandidateRule | FirewallRule) -> tuple[object, ...]:
    """The (direction, source, destination, protocol, destination_port) tuple, action excluded."""
    return (rule.direction, rule.source, rule.destination, rule.protocol, rule.destination_port)


def _full_key(rule: CandidateRule | FirewallRule) -> tuple[object, ...]:
    """`_target_key` plus action and source_port — an exact-match key including the action taken."""
    return (rule.action, *_target_key(rule), rule.source_port)


def _validate_conflict(
    candidate: CandidateRule, active_rules: Sequence[FirewallRule]
) -> RuleRejectionReason | None:
    target = _target_key(candidate)
    for rule in active_rules:
        if rule.status is not RuleStatus.ACTIVE or rule.action == candidate.action:
            continue
        if _target_key(rule) == target:
            return RuleRejectionReason.CONFLICT
    return None


def _validate_duplicate(
    candidate: CandidateRule, active_rules: Sequence[FirewallRule]
) -> RuleRejectionReason | None:
    candidate_key = _full_key(candidate)
    for rule in active_rules:
        if rule.status is RuleStatus.ACTIVE and _full_key(rule) == candidate_key:
            return RuleRejectionReason.DUPLICATE
    return None


def _validate_rate_cap(rate_limiter: RuleCreationRateLimiter, now: datetime) -> RuleRejectionReason | None:
    if not rate_limiter.would_allow(now):
        return RuleRejectionReason.RATE_LIMITED
    return None


def _validate_priority(
    candidate: CandidateRule, active_rules: Sequence[FirewallRule]
) -> RuleRejectionReason | None:
    """Reject a candidate that an existing active rule already fully covers (same action, broader scope).

    An *exact*-scope match with the same action is a duplicate, not a
    shadow — `_validate_duplicate` (earlier in the chain) already rejects
    that case, so by the time control reaches here, a covering match is
    necessarily strictly broader.
    """
    for rule in active_rules:
        if rule.status is not RuleStatus.ACTIVE or rule.action != candidate.action:
            continue
        if rule.protocol != candidate.protocol:
            continue
        if rule.destination_port is not None and rule.destination_port != candidate.destination_port:
            continue
        source_covers = rule.source == candidate.source or rule.source.supernet_of(candidate.source)
        destination_covers = rule.destination == candidate.destination or rule.destination.supernet_of(
            candidate.destination
        )
        if source_covers and destination_covers:
            return RuleRejectionReason.SHADOWED
    return None


def _validate_expiration(candidate: CandidateRule) -> RuleRejectionReason | None:
    if candidate.expires_at is None:
        return RuleRejectionReason.MISSING_EXPIRATION
    return None


def _validate_authorization(
    candidate: CandidateRule, known_decision_ids: Sequence[str]
) -> RuleRejectionReason | None:
    if candidate.decision_id not in known_decision_ids:
        return RuleRejectionReason.UNAUTHORIZED
    return None


def _assign_priority(candidate: CandidateRule) -> int:
    """Higher threat score -> lower priority number -> evaluated first."""
    score = candidate.threat_score if candidate.threat_score is not None else 0.0
    return round(100.0 - min(max(score, 0.0), 100.0))


# ================================================================ v2 set path


@dataclass(frozen=True, slots=True)
class ActiveTarget:
    """An ACTIVE rule and the device its set element enforces on (the v2 validator's view)."""

    rule: FirewallRule
    target: RuleTarget


@dataclass(frozen=True, slots=True)
class SetValidationOutcome:
    """The v2 chain's verdict. `upgrade_of` names the ACTIVE RATE_LIMIT a BLOCK replaces atomically."""

    approved: bool
    rejection: ValidationRejection | None = None
    upgrade_of: str | None = None


def validate_set_candidate(
    candidate: CandidateRule,
    *,
    target: RuleTarget | None,
    config: PirewallConfig,
    known_decision_ids: Sequence[str],
    active: Sequence[ActiveTarget],
    allowlist: Sequence[AllowlistEntry],
    rate_limiter: RuleCreationRateLimiter,
    now: datetime,
    local_addresses: LocalAddresses | None = None,
) -> SetValidationOutcome:
    """The v2 validator chain for set elements (ADDENDUM_4.md D4, PLAN_FINAL §4.6), in order.

    schema -> network -> allowlist -> safety -> conflict -> duplicate ->
    rate-cap -> escalation -> expiration -> authorization.

    What differs from the v1 chain (`validate_candidate_rule`, unchanged):

    * **network**: there must be a device to key on (`target`, from
      `pirewall.firewall.sets.device_target`). A rule with no LAN /32 source
      is UNENFORCEABLE: v2 enforces per device, at LAN ingress.
    * **allowlist**: an element acts on the whole device, so any allowlist
      entry covering the target's IP refuses it, whatever port or protocol
      the entry names. Narrower than the device would be the v1 notion.
    * **safety**: the target IP and MAC against the infrastructure set (every
      address this host holds, the configured Pi LAN address, the gateway,
      the Admin PC's IP and MAC). Non-unicast MACs cannot reach here: the
      target type refuses them.
    * **conflict / duplicate**: per target, not per port tuple (audit item
      14). BLOCK outranks RATE_LIMIT: a RATE_LIMIT on a blocked device is a
      CONFLICT, a BLOCK on a rate-limited one is an upgrade.
    * **escalation** replaces priority: an upgrade needs evidence the active
      rule did not already carry (NO_NEW_EVIDENCE otherwise). Repeating the
      same evidence never upgrades.
    * **expiration** is mandatory and capped at `policy.max_ttl_seconds`.
    """
    upgrade_of: list[str] = []
    checks: tuple[tuple[str, Callable[[], RuleRejectionReason | None]], ...] = (
        ("schema", lambda: _validate_schema(candidate)),
        ("network", lambda: None if target is not None else RuleRejectionReason.UNENFORCEABLE),
        ("allowlist", lambda: _validate_set_allowlist(candidate, _require(target), allowlist)),
        ("safety", lambda: _validate_set_safety(candidate, _require(target), config, local_addresses)),
        ("conflict", lambda: _validate_set_conflict(candidate, _require(target), active, upgrade_of)),
        ("duplicate", lambda: _validate_set_duplicate(candidate, _require(target), active)),
        ("rate_cap", lambda: _validate_rate_cap(rate_limiter, now)),
        ("escalation", lambda: _validate_escalation(candidate, active, upgrade_of)),
        ("expiration", lambda: _validate_set_expiration(candidate, config, now)),
        ("authorization", lambda: _validate_authorization(candidate, known_decision_ids)),
    )
    for stage_name, check in checks:
        reason = check()
        if reason is not None:
            return SetValidationOutcome(approved=False, rejection=ValidationRejection(stage_name, reason))
    return SetValidationOutcome(approved=True, upgrade_of=upgrade_of[0] if upgrade_of else None)


def _require(target: RuleTarget | None) -> RuleTarget:
    # Every stage after "network" only runs once it has passed.
    assert target is not None
    return target


def _same_device(left: RuleTarget, right: RuleTarget) -> bool:
    """Same IP, or the same known MAC (a MAC survives a change of address, D3)."""
    return left.ip == right.ip or (left.mac is not None and left.mac == right.mac)


def _validate_set_allowlist(
    candidate: CandidateRule, target: RuleTarget, allowlist: Sequence[AllowlistEntry]
) -> RuleRejectionReason | None:
    if candidate.action not in _RESTRICTIVE_ACTIONS:
        return None
    if any(target.ip in entry.target for entry in allowlist):
        return RuleRejectionReason.ALLOWLISTED
    return None


def _validate_set_safety(
    candidate: CandidateRule,
    target: RuleTarget,
    config: PirewallConfig,
    local_addresses: LocalAddresses | None,
) -> RuleRejectionReason | None:
    if candidate.action not in _RESTRICTIVE_ACTIONS:
        return None
    if not _is_targetable_network(IPv4Network(f"{target.ip}/32")):
        return RuleRejectionReason.UNSAFE
    resolved_local = cached_local_addresses() if local_addresses is None else local_addresses
    infrastructure = {
        *resolved_local.host,
        *resolved_local.broadcast,
        config.network.pirewall_lan_ip,
        config.network.upstream_gateway,
        config.admin.admin_pc_ip,
        config.network.protected_network.network_address,
        config.network.protected_network.broadcast_address,
    }
    if target.ip in infrastructure:
        return RuleRejectionReason.UNSAFE
    admin_mac = config.admin.admin_pc_mac
    if admin_mac is not None and target.mac == admin_mac:
        return RuleRejectionReason.UNSAFE
    return None


def _validate_set_conflict(
    candidate: CandidateRule,
    target: RuleTarget,
    active: Sequence[ActiveTarget],
    upgrade_of: list[str],
) -> RuleRejectionReason | None:
    for entry in active:
        if not _same_device(entry.target, target) or entry.rule.action == candidate.action:
            continue
        if entry.rule.action is FirewallAction.BLOCK and candidate.action is FirewallAction.RATE_LIMIT:
            return RuleRejectionReason.CONFLICT
        if entry.rule.action is FirewallAction.RATE_LIMIT and candidate.action is FirewallAction.BLOCK:
            upgrade_of.append(entry.rule.id)
    return None


def _validate_set_duplicate(
    candidate: CandidateRule, target: RuleTarget, active: Sequence[ActiveTarget]
) -> RuleRejectionReason | None:
    for entry in active:
        if _same_device(entry.target, target) and entry.rule.action == candidate.action:
            return RuleRejectionReason.DUPLICATE
    return None


def _validate_escalation(
    candidate: CandidateRule, active: Sequence[ActiveTarget], upgrade_of: list[str]
) -> RuleRejectionReason | None:
    for entry in active:
        if entry.rule.id in upgrade_of and set(candidate.evidence) <= set(entry.rule.evidence):
            return RuleRejectionReason.NO_NEW_EVIDENCE
    return None


def _validate_set_expiration(
    candidate: CandidateRule, config: PirewallConfig, now: datetime
) -> RuleRejectionReason | None:
    if candidate.expires_at is None or candidate.expires_at <= now:
        return RuleRejectionReason.MISSING_EXPIRATION
    if (candidate.expires_at - now).total_seconds() > config.policy.max_ttl_seconds:
        return RuleRejectionReason.EXPIRATION_TOO_LONG
    return None
