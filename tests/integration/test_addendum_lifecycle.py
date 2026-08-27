"""Addendum-driven lifecycle behavior: SHADOW (A1), ASSISTED (A7), kill-switch (A8)."""

from datetime import UTC, datetime

from pirewall.core.enums import EnforcementMode, FirewallAction, RuleStatus, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.rule import CandidateRule
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from tests.helpers.config import make_config
from tests.helpers.rules import make_candidate

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _manager(**config_overrides: dict[str, object]) -> tuple[FirewallManager, FakeFirewallBackend]:
    config = make_config(**config_overrides)
    backend = FakeFirewallBackend()
    return FirewallManager(config, backend), backend


def _register_decision_for(manager: FirewallManager, candidate: CandidateRule) -> None:
    manager.register_decision(
        FirewallDecision.model_validate(
            {
                "id": candidate.decision_id,
                "threat_assessment_id": "assessment-1",
                "action": candidate.action,
                "threat_score": candidate.threat_score,
                "threat_level": ThreatLevel.CRITICAL,
                "reason": "test",
                "decided_at": NOW,
            }
        )
    )


def test_shadow_mode_never_reaches_backend() -> None:
    manager, backend = _manager(firewall={"enforcement_mode": "shadow"})
    candidate = make_candidate(action=FirewallAction.BLOCK, threat_score=95.0)
    _register_decision_for(manager, candidate)

    result = manager.submit_candidate(candidate, NOW)

    assert result.rule is not None
    assert result.rule.status is RuleStatus.SHADOWED
    assert backend.apply_calls == 0
    assert backend.list_active_rule_ids() == frozenset()
    assert "would have" in (result.event.reason or "")


def test_assisted_mode_high_score_block_holds_for_approval() -> None:
    manager, backend = _manager(
        firewall={"enforcement_mode": "assisted", "assisted_review_threshold": 75.0}
    )
    candidate = make_candidate(action=FirewallAction.BLOCK, threat_score=90.0)
    _register_decision_for(manager, candidate)

    result = manager.submit_candidate(candidate, NOW)

    assert result.rule is not None
    assert result.rule.status is RuleStatus.PENDING_APPROVAL
    assert backend.apply_calls == 0


def test_assisted_mode_approval_deploys_through_normal_path() -> None:
    manager, backend = _manager(
        firewall={"enforcement_mode": "assisted", "assisted_review_threshold": 75.0}
    )
    candidate = make_candidate(action=FirewallAction.BLOCK, threat_score=90.0)
    _register_decision_for(manager, candidate)
    manager.submit_candidate(candidate, NOW)

    approved = manager.approve_pending(candidate.id, NOW)

    assert approved is not None
    assert approved.rule is not None
    assert approved.rule.status is RuleStatus.ACTIVE
    assert candidate.id in backend.list_active_rule_ids()


def test_assisted_mode_rejection_never_deploys() -> None:
    manager, backend = _manager(
        firewall={"enforcement_mode": "assisted", "assisted_review_threshold": 75.0}
    )
    candidate = make_candidate(action=FirewallAction.BLOCK, threat_score=90.0)
    _register_decision_for(manager, candidate)
    manager.submit_candidate(candidate, NOW)

    rejected = manager.reject_pending(candidate.id, NOW)

    assert rejected is not None
    assert rejected.status is RuleStatus.REJECTED
    assert backend.apply_calls == 0


def test_assisted_mode_low_score_block_auto_deploys() -> None:
    manager, backend = _manager(
        firewall={"enforcement_mode": "assisted", "assisted_review_threshold": 75.0}
    )
    candidate = make_candidate(action=FirewallAction.BLOCK, threat_score=50.0)
    _register_decision_for(manager, candidate)

    result = manager.submit_candidate(candidate, NOW)

    assert result.rule is not None
    assert result.rule.status is RuleStatus.ACTIVE
    assert backend.apply_calls == 1


def test_assisted_mode_monitor_always_auto_deploys() -> None:
    manager, _backend = _manager(
        firewall={"enforcement_mode": "assisted", "assisted_review_threshold": 10.0}
    )
    candidate = make_candidate(action=FirewallAction.MONITOR, threat_score=99.0)
    _register_decision_for(manager, candidate)

    result = manager.submit_candidate(candidate, NOW)

    assert result.rule is not None
    assert result.rule.status is RuleStatus.ACTIVE


def test_kill_switch_removes_active_rules_and_sets_shadow_mode() -> None:
    manager, backend = _manager(firewall={"enforcement_mode": "active"})
    candidates = [
        make_candidate(decision_id=f"decision-{i}", destination=f"192.168.1.{20 + i}/32")
        for i in range(3)
    ]
    for candidate in candidates:
        _register_decision_for(manager, candidate)
        result = manager.submit_candidate(candidate, NOW)
        assert result.rule is not None
        assert result.rule.status is RuleStatus.ACTIVE

    assert len(manager.active_rules()) == 3
    assert manager.enforcement_mode is EnforcementMode.ACTIVE

    event = manager.revert_to_base(NOW)

    assert manager.enforcement_mode is EnforcementMode.SHADOW
    assert manager.active_rules() == []
    assert backend.list_active_rule_ids() == frozenset()
    for candidate in candidates:
        rule = manager.get_rule(candidate.id)
        assert rule is not None
        assert rule.status is RuleStatus.REMOVED
    assert "kill-switch" in (event.reason or "").lower()


def test_kill_switch_leaves_allowlist_untouched() -> None:
    manager, _backend = _manager(
        firewall={
            "enforcement_mode": "active",
            "allowlist": [
                {
                    "target": "192.168.1.99/32",
                    "reason": "protected device",
                    "created_by": "admin",
                    "created_at": NOW.isoformat(),
                }
            ],
        }
    )
    before = manager.allowlist
    manager.revert_to_base(NOW)
    assert manager.allowlist == before
    assert len(manager.allowlist) == 1
