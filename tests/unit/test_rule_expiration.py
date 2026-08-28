"""`FirewallManager.expire_rules` — making adaptive-rule TTLs actually mean something (spec §25).

`CandidateRule.expires_at` is mandatory (the validation chain's expiration
stage rejects a candidate without one), but until this landed nothing ever
acted on it: an ACTIVE rule stayed deployed in the backend indefinitely and
`RuleStatus.EXPIRED` was a documented state the lifecycle could never
reach. `pirewall.runtime.core` calls this on a timer.
"""

from datetime import UTC, datetime, timedelta

from pirewall.core.enums import RuleStatus, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from tests.helpers.config import make_config
from tests.helpers.rules import make_candidate

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _active_manager() -> tuple[FirewallManager, FakeFirewallBackend]:
    backend = FakeFirewallBackend()
    manager = FirewallManager(make_config(firewall={"enforcement_mode": "active"}), backend)
    return manager, backend


def _deploy(manager: FirewallManager, ttl_seconds: int) -> str:
    candidate = make_candidate(created_at=NOW, expires_at=NOW + timedelta(seconds=ttl_seconds))
    # The authorization stage only accepts a candidate whose decision the
    # real engine produced, so register it the way the pipeline does.
    manager.register_decision(
        FirewallDecision(
            id=candidate.decision_id,
            threat_assessment_id="assessment-1",
            flow_id="flow-1",
            action=candidate.action,
            threat_score=candidate.threat_score or 0.0,
            threat_level=ThreatLevel.CRITICAL,
            reason=candidate.reason,
            decided_at=NOW,
        )
    )
    result = manager.submit_candidate(candidate, NOW)
    assert result.rule is not None
    assert result.rule.status is RuleStatus.ACTIVE
    return result.rule.id


def test_an_expired_rule_is_retired_and_removed_from_the_backend() -> None:
    manager, backend = _active_manager()
    rule_id = _deploy(manager, ttl_seconds=60)

    expired = manager.expire_rules(NOW + timedelta(seconds=61))

    assert [rule.id for rule in expired] == [rule_id]
    retired = manager.get_rule(rule_id)
    assert retired is not None
    assert retired.status is RuleStatus.EXPIRED
    assert manager.active_rules() == []
    assert rule_id not in backend.list_active_rule_ids()


def test_a_rule_still_inside_its_ttl_is_left_alone() -> None:
    manager, _ = _active_manager()
    rule_id = _deploy(manager, ttl_seconds=3600)

    assert manager.expire_rules(NOW + timedelta(seconds=60)) == []

    rule = manager.get_rule(rule_id)
    assert rule is not None
    assert rule.status is RuleStatus.ACTIVE


def test_expiry_is_idempotent() -> None:
    """The sweep runs every `flow.cleanup_interval_seconds`; it must not re-expire."""
    manager, _ = _active_manager()
    _deploy(manager, ttl_seconds=60)
    later = NOW + timedelta(seconds=61)

    assert len(manager.expire_rules(later)) == 1
    assert manager.expire_rules(later) == []


def test_expiry_is_recorded_in_the_lifecycle_audit_trail() -> None:
    """Spec §25: every lifecycle change is recorded, expiry included."""
    manager, _ = _active_manager()
    rule_id = _deploy(manager, ttl_seconds=60)

    manager.expire_rules(NOW + timedelta(seconds=61))

    transitions = [
        transition
        for transition in manager.transitions
        if transition.rule_id == rule_id and transition.to_status is RuleStatus.EXPIRED
    ]
    assert len(transitions) == 1
    assert transitions[0].from_status is RuleStatus.ACTIVE
    assert transitions[0].reason == "rule TTL elapsed"
