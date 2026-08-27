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
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Network

from pirewall.config.models import PirewallConfig
from pirewall.core.enums import FirewallAction, RuleRejectionReason, RuleStatus
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.rule import CandidateRule, FirewallRule
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
) -> ValidationOutcome:
    """Run the full validation chain against `candidate`, in order.

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
        ("safety", lambda: _validate_safety(candidate, config)),
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


def _validate_safety(candidate: CandidateRule, config: PirewallConfig) -> RuleRejectionReason | None:
    if candidate.action not in _RESTRICTIVE_ACTIONS:
        return None

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
