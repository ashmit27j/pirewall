"""Firewall backend failure handling degrades safely (spec §26, ADDENDUM.md A6).

`tests/integration/test_firewall_lifecycle.py::test_deploy_failure_is_handled_and_recorded`
already covers an `apply_rule` failure. This file covers the other half:
`remove_rule` failing (via `disable_rule`/`remove_rule`/the kill-switch) must
never crash `FirewallManager`, and — per ADDENDUM.md A6's fail-open default —
`pirewall`'s own authoritative rule state must still transition correctly
even when the backend itself couldn't be reached, so a flaky/unreachable
`nft` never leaves the control panel showing a stale "still active" rule.
"""

from datetime import UTC, datetime

from pirewall.core.enums import RuleStatus, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.rule import CandidateRule
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from tests.helpers.config import make_config
from tests.helpers.rules import make_candidate

NOW = datetime(2026, 1, 1, tzinfo=UTC)


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


def _active_manager_with_one_rule(backend: FakeFirewallBackend) -> tuple[FirewallManager, str]:
    """Deploy one rule (apply succeeds — only `fail_on_remove` is set) against `backend`."""
    config = make_config(firewall={"enforcement_mode": "active"})
    manager = FirewallManager(config, backend)
    candidate = make_candidate(destination="192.168.1.60/32")
    _register_decision_for(manager, candidate)
    result = manager.submit_candidate(candidate, NOW)
    assert result.rule is not None and result.rule.status is RuleStatus.ACTIVE
    return manager, result.rule.id


def test_disable_rule_still_transitions_state_when_backend_remove_fails() -> None:
    backend = FakeFirewallBackend(fail_on_remove=True)
    manager, rule_id = _active_manager_with_one_rule(backend)

    disabled = manager.disable_rule(rule_id, NOW)

    assert disabled is not None
    assert disabled.status is RuleStatus.DISABLED
    stored = manager.get_rule(rule_id)
    assert stored is not None
    assert stored.status is RuleStatus.DISABLED


def test_remove_rule_still_transitions_state_when_backend_remove_fails() -> None:
    backend = FakeFirewallBackend(fail_on_remove=True)
    manager, rule_id = _active_manager_with_one_rule(backend)

    removed = manager.remove_rule(rule_id, NOW)

    assert removed is not None
    assert removed.status is RuleStatus.REMOVED


def test_kill_switch_reverts_all_rules_even_when_every_backend_removal_fails() -> None:
    """ADDENDUM.md A8/A6: the kill-switch must not itself become the thing that fails unsafely."""
    config = make_config(firewall={"enforcement_mode": "active"})
    backend = FakeFirewallBackend(fail_on_remove=True)  # apply succeeds, every remove fails
    manager = FirewallManager(config, backend)

    rule_ids: list[str] = []
    for index in range(3):
        candidate = make_candidate(
            decision_id=f"decision-{index}", destination=f"192.168.1.{70 + index}/32"
        )
        _register_decision_for(manager, candidate)
        result = manager.submit_candidate(candidate, NOW)
        assert result.rule is not None and result.rule.status is RuleStatus.ACTIVE
        rule_ids.append(result.rule.id)

    event = manager.revert_to_base(NOW)  # must not raise

    assert manager.enforcement_mode.value == "shadow"
    for rule_id in rule_ids:
        rule = manager.get_rule(rule_id)
        assert rule is not None
        assert rule.status is RuleStatus.REMOVED
    assert "kill-switch" in (event.reason or "")
    assert backend.remove_calls == 3  # it did try, and failed, every time
