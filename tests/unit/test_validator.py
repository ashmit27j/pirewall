"""The full candidate-rule validation chain, stage by stage (spec §24, ADDENDUM.md)."""

from collections.abc import Sequence
from datetime import UTC, datetime
from ipaddress import IPv4Network

from pirewall.config.models import PirewallConfig
from pirewall.core.enums import FirewallAction, Protocol, RuleRejectionReason
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.rule import CandidateRule, FirewallRule
from pirewall.firewall.rate_limiter import RuleCreationRateLimiter
from pirewall.firewall.validator import ValidationOutcome, validate_candidate_rule
from tests.helpers.config import make_config
from tests.helpers.rules import make_candidate, make_firewall_rule

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _validate(
    candidate: CandidateRule,
    *,
    config: PirewallConfig | None = None,
    known_decision_ids: Sequence[str] = ("decision-1",),
    active_rules: Sequence[FirewallRule] = (),
    allowlist: Sequence[AllowlistEntry] = (),
    rate_limiter: RuleCreationRateLimiter | None = None,
) -> ValidationOutcome:
    return validate_candidate_rule(
        candidate,
        config=config if config is not None else make_config(),
        known_decision_ids=known_decision_ids,
        active_rules=active_rules,
        allowlist=allowlist,
        rate_limiter=rate_limiter or RuleCreationRateLimiter(max_per_window=100, window_seconds=60),
        now=NOW,
    )


def _assert_rejected(outcome: ValidationOutcome, stage: str, reason: RuleRejectionReason) -> None:
    assert outcome.approved is False
    assert outcome.rejection is not None
    assert outcome.rejection.stage == stage
    assert outcome.rejection.reason is reason


def test_valid_candidate_is_approved_with_a_priority() -> None:
    outcome = _validate(make_candidate())
    assert outcome.approved is True
    assert outcome.priority is not None


def test_schema_stage_rejects_missing_threat_score() -> None:
    outcome = _validate(make_candidate(threat_score=None))
    _assert_rejected(outcome, "schema", RuleRejectionReason.INVALID_SCHEMA)


def test_network_stage_rejects_bypassed_ipv6_construction() -> None:
    candidate = make_candidate()
    # model_copy(update=...) skips validation on the updated fields,
    # simulating a caller that bypassed Pydantic (ADDENDUM.md A5
    # belt-and-suspenders scenario) without fighting pyright over
    # model_construct's precisely-typed **values splat.
    broken = candidate.model_copy(update={"source": "2001:db8::/64"})
    outcome = _validate(broken)
    _assert_rejected(outcome, "network", RuleRejectionReason.INVALID_NETWORK)
    assert isinstance(candidate.source, IPv4Network)  # the *real* constructor still can't do this


def test_allowlist_stage_rejects_block_targeting_allowlisted_destination() -> None:
    entry = AllowlistEntry.model_validate(
        {"target": "192.168.1.10/32", "reason": "never block this", "created_at": NOW, "created_by": "admin"}
    )
    candidate = make_candidate(action=FirewallAction.BLOCK, destination="192.168.1.10/32", threat_score=99.0)
    outcome = _validate(candidate, allowlist=(entry,))
    _assert_rejected(outcome, "allowlist", RuleRejectionReason.ALLOWLISTED)


def test_allowlist_does_not_block_monitor_action() -> None:
    entry = AllowlistEntry.model_validate(
        {"target": "192.168.1.10/32", "reason": "never block this", "created_at": NOW, "created_by": "admin"}
    )
    candidate = make_candidate(action=FirewallAction.MONITOR, destination="192.168.1.10/32")
    outcome = _validate(candidate, allowlist=(entry,))
    assert outcome.approved is True


def test_safety_stage_rejects_admin_pc_target() -> None:
    candidate = make_candidate(destination="192.168.1.50/32")  # matches make_config()'s admin_pc_ip
    outcome = _validate(candidate)
    _assert_rejected(outcome, "safety", RuleRejectionReason.UNSAFE)


def test_safety_stage_rejects_admin_pc_as_source() -> None:
    candidate = make_candidate(source="192.168.1.50/32", destination="10.0.0.0/24")
    outcome = _validate(candidate)
    _assert_rejected(outcome, "safety", RuleRejectionReason.UNSAFE)


def test_safety_stage_rejects_pirewall_own_lan_ip_as_destination() -> None:
    """spec §24 "blocking pirewall itself"/"management access" — the *server* end of management.

    Regression test for an audit finding: the Admin-PC-IP check alone let
    this through, because the Pi's own address is a different address from
    the Admin PC's. Blocking it kills the control panel and every LAN
    client's default gateway.
    """
    outcome = _validate(make_candidate(destination="192.168.1.2/32"))
    _assert_rejected(outcome, "safety", RuleRejectionReason.UNSAFE)


def test_safety_stage_rejects_pirewall_own_lan_ip_as_source() -> None:
    outcome = _validate(make_candidate(source="192.168.1.2/32"))
    _assert_rejected(outcome, "safety", RuleRejectionReason.UNSAFE)


def test_safety_stage_rejects_upstream_gateway() -> None:
    """spec §24 "blocking the entire internet" — a /32 on the gateway achieves exactly that.

    Regression test for an audit finding: only the literal `0.0.0.0/0` rule
    was rejected, so a /32 targeting the upstream gateway — which every
    outbound packet transits — was approved.
    """
    _assert_rejected(_validate(make_candidate(source="192.168.1.1/32")), "safety", RuleRejectionReason.UNSAFE)
    _assert_rejected(
        _validate(make_candidate(destination="192.168.1.1/32")), "safety", RuleRejectionReason.UNSAFE
    )


def test_safety_stage_protects_critical_addresses_from_rate_limit_too() -> None:
    """RATE_LIMIT is restrictive too — throttling the gateway or the Pi is still an outage."""
    for target in ("192.168.1.1/32", "192.168.1.2/32"):
        outcome = _validate(make_candidate(action=FirewallAction.RATE_LIMIT, destination=target))
        _assert_rejected(outcome, "safety", RuleRejectionReason.UNSAFE)


def test_safety_stage_rejects_whole_protected_lan() -> None:
    candidate = make_candidate(destination="192.168.1.0/24")  # the whole protected_network
    outcome = _validate(candidate)
    _assert_rejected(outcome, "safety", RuleRejectionReason.UNSAFE)


def test_safety_stage_rejects_whole_internet() -> None:
    candidate = make_candidate(source="0.0.0.0/0")
    outcome = _validate(candidate)
    _assert_rejected(outcome, "safety", RuleRejectionReason.UNSAFE)


def test_safety_stage_rejects_rule_broader_than_evidence() -> None:
    candidate = make_candidate(source="10.0.0.0/8")  # /8 from single-flow evidence
    outcome = _validate(candidate)
    _assert_rejected(outcome, "safety", RuleRejectionReason.UNSAFE)


def test_safety_stage_does_not_apply_to_monitor() -> None:
    candidate = make_candidate(action=FirewallAction.MONITOR, destination="192.168.1.50/32")
    outcome = _validate(candidate)
    assert outcome.approved is True


def test_conflict_stage_rejects_same_target_different_action() -> None:
    existing = make_firewall_rule(action=FirewallAction.MONITOR)
    candidate = make_candidate(action=FirewallAction.BLOCK)
    outcome = _validate(candidate, active_rules=(existing,))
    _assert_rejected(outcome, "conflict", RuleRejectionReason.CONFLICT)


def test_duplicate_stage_rejects_identical_active_rule() -> None:
    existing = make_firewall_rule()
    candidate = make_candidate()
    outcome = _validate(candidate, active_rules=(existing,))
    _assert_rejected(outcome, "duplicate", RuleRejectionReason.DUPLICATE)


def test_rate_cap_stage_rejects_when_budget_exhausted() -> None:
    limiter = RuleCreationRateLimiter(max_per_window=1, window_seconds=60)
    limiter.record(NOW)
    outcome = _validate(make_candidate(), rate_limiter=limiter)
    _assert_rejected(outcome, "rate_cap", RuleRejectionReason.RATE_LIMITED)


def test_priority_stage_rejects_candidate_shadowed_by_broader_active_rule() -> None:
    existing = make_firewall_rule(source="203.0.113.0/24", destination_port=22)
    candidate = make_candidate(source="203.0.113.5/32", destination_port=22)
    outcome = _validate(candidate, active_rules=(existing,))
    _assert_rejected(outcome, "priority", RuleRejectionReason.SHADOWED)


def test_expiration_stage_rejects_missing_expiration() -> None:
    candidate = make_candidate(expires_at=None)
    outcome = _validate(candidate)
    _assert_rejected(outcome, "expiration", RuleRejectionReason.MISSING_EXPIRATION)


def test_authorization_stage_rejects_unknown_decision_id() -> None:
    candidate = make_candidate(decision_id="unknown-decision")
    outcome = _validate(candidate, known_decision_ids=("decision-1",))
    _assert_rejected(outcome, "authorization", RuleRejectionReason.UNAUTHORIZED)


def test_higher_threat_score_gets_lower_priority_number() -> None:
    low = _validate(make_candidate(threat_score=10.0))
    high = _validate(make_candidate(threat_score=90.0))
    assert low.priority is not None
    assert high.priority is not None
    assert high.priority < low.priority


def test_protocol_none_in_allowlist_entry_matches_any_protocol() -> None:
    entry = AllowlistEntry.model_validate(
        {"target": "192.168.1.10/32", "reason": "n/a", "created_at": NOW, "created_by": "admin"}
    )
    candidate = make_candidate(
        protocol=Protocol.UDP, destination="192.168.1.10/32", action=FirewallAction.BLOCK
    )
    outcome = _validate(candidate, allowlist=(entry,))
    _assert_rejected(outcome, "allowlist", RuleRejectionReason.ALLOWLISTED)
