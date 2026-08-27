"""Full CANDIDATE -> ... -> ACTIVE/REJECTED lifecycle via `FakeFirewallBackend` (spec §22, §25)."""

from datetime import UTC, datetime

from pirewall.core.enums import FirewallAction, RuleStatus, ThreatLevel
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


def test_end_to_end_active_rule() -> None:
    manager, backend = _manager(firewall={"enforcement_mode": "active"})
    candidate = make_candidate()
    _register_decision_for(manager, candidate)

    result = manager.submit_candidate(candidate, NOW)

    assert result.rule is not None
    assert result.rule.status is RuleStatus.ACTIVE
    assert candidate.id in backend.list_active_rule_ids()
    assert manager.active_rules() == [result.rule]

    statuses = [transition.to_status for transition in manager.transitions]
    assert RuleStatus.VALIDATING in statuses
    assert RuleStatus.DEPLOYED in statuses
    assert RuleStatus.ACTIVE in statuses


def test_end_to_end_rejected_rule_has_recorded_reason() -> None:
    manager, backend = _manager(firewall={"enforcement_mode": "active"})
    # No decision registered -> fails the authorization stage.
    candidate = make_candidate(decision_id="never-registered")

    result = manager.submit_candidate(candidate, NOW)

    assert result.rule is None
    assert result.event.reason is not None
    assert "authorization" in result.event.reason
    assert backend.apply_calls == 0


def test_deploy_failure_is_handled_and_recorded() -> None:
    config = make_config(firewall={"enforcement_mode": "active"})
    backend = FakeFirewallBackend(fail_on_apply=True)
    manager = FirewallManager(config, backend)
    candidate = make_candidate()
    _register_decision_for(manager, candidate)

    result = manager.submit_candidate(candidate, NOW)

    assert result.rule is not None
    assert result.rule.status is RuleStatus.REJECTED
    assert candidate.id not in backend.list_active_rule_ids()


def test_monitor_action_deploys_without_touching_safety_checks() -> None:
    manager, backend = _manager(firewall={"enforcement_mode": "active"})
    candidate = make_candidate(action=FirewallAction.MONITOR, destination="192.168.1.50/32")
    _register_decision_for(manager, candidate)

    result = manager.submit_candidate(candidate, NOW)

    assert result.rule is not None
    assert result.rule.status is RuleStatus.ACTIVE
    assert backend.apply_calls == 1


def test_duplicate_candidate_rejected_against_populated_backend() -> None:
    manager, backend = _manager(firewall={"enforcement_mode": "active"})
    first = make_candidate(decision_id="decision-1")
    _register_decision_for(manager, first)
    first_result = manager.submit_candidate(first, NOW)
    assert first_result.rule is not None and first_result.rule.status is RuleStatus.ACTIVE
    assert first.id in backend.list_active_rule_ids()

    duplicate = make_candidate(decision_id="decision-2")
    _register_decision_for(manager, duplicate)
    duplicate_result = manager.submit_candidate(duplicate, NOW)

    assert duplicate_result.rule is None
    assert "duplicate" in (duplicate_result.event.reason or "")
    assert backend.apply_calls == 1  # the duplicate never reached the backend


def test_conflicting_candidate_rejected_against_populated_backend() -> None:
    manager, backend = _manager(firewall={"enforcement_mode": "active"})
    monitor = make_candidate(decision_id="decision-1", action=FirewallAction.MONITOR)
    _register_decision_for(manager, monitor)
    monitor_result = manager.submit_candidate(monitor, NOW)
    assert monitor_result.rule is not None and monitor_result.rule.status is RuleStatus.ACTIVE

    conflicting_block = make_candidate(decision_id="decision-2", action=FirewallAction.BLOCK)
    _register_decision_for(manager, conflicting_block)
    block_result = manager.submit_candidate(conflicting_block, NOW)

    assert block_result.rule is None
    assert "conflict" in (block_result.event.reason or "")
    assert backend.apply_calls == 1  # only the original MONITOR rule ever reached the backend
