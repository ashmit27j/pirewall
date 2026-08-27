"""End-to-end proof that dangerous candidates can never reach ACTIVE (spec §24).

Unlike `tests/unit/test_validator.py` (which calls the validator stage
directly), these go through the real `FirewallManager.submit_candidate`
pipeline with a `FakeFirewallBackend` — proving the *whole system*, not
just one function, can't be made to lock pirewall's operator out, no
matter the enforcement mode.
"""

from datetime import UTC, datetime

import pytest

from pirewall.core.enums import EnforcementMode, FirewallAction, RuleStatus, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.rule import CandidateRule
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from tests.helpers.config import make_config
from tests.helpers.rules import make_candidate

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _manager_in_active_mode() -> FirewallManager:
    config = make_config(firewall={"enforcement_mode": "active"})
    return FirewallManager(config, FakeFirewallBackend())


def _submit(manager: FirewallManager, candidate: CandidateRule) -> RuleStatus | None:
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
    result = manager.submit_candidate(candidate, NOW)
    return result.rule.status if result.rule is not None else None


@pytest.mark.parametrize("enforcement_mode", [EnforcementMode.ACTIVE, EnforcementMode.ASSISTED])
def test_admin_pc_can_never_be_locked_out(enforcement_mode: EnforcementMode) -> None:
    config = make_config(
        firewall={"enforcement_mode": enforcement_mode.value, "assisted_review_threshold": 0.0}
    )
    manager = FirewallManager(config, FakeFirewallBackend())
    candidate = make_candidate(action=FirewallAction.BLOCK, destination="192.168.1.50/32", threat_score=100.0)

    status = _submit(manager, candidate)

    assert status != RuleStatus.ACTIVE
    assert manager.active_rules() == []


def test_management_interface_direction_is_also_protected_as_source() -> None:
    manager = _manager_in_active_mode()
    candidate = make_candidate(action=FirewallAction.BLOCK, source="192.168.1.50/32", threat_score=100.0)
    status = _submit(manager, candidate)
    assert status != RuleStatus.ACTIVE


def test_entire_protected_lan_can_never_be_blocked() -> None:
    manager = _manager_in_active_mode()
    candidate = make_candidate(action=FirewallAction.BLOCK, destination="192.168.1.0/24", threat_score=100.0)
    status = _submit(manager, candidate)
    assert status != RuleStatus.ACTIVE


def test_entire_internet_can_never_be_blocked() -> None:
    manager = _manager_in_active_mode()
    candidate = make_candidate(action=FirewallAction.BLOCK, source="0.0.0.0/0", threat_score=100.0)
    status = _submit(manager, candidate)
    assert status != RuleStatus.ACTIVE


def test_rule_broader_than_single_flow_evidence_is_rejected() -> None:
    manager = _manager_in_active_mode()
    candidate = make_candidate(action=FirewallAction.BLOCK, source="10.0.0.0/8", threat_score=100.0)
    status = _submit(manager, candidate)
    assert status != RuleStatus.ACTIVE


def test_allowlisted_target_survives_critical_threat_score() -> None:
    config = make_config(
        firewall={
            "enforcement_mode": "active",
            "allowlist": [
                {
                    "target": "192.168.1.77/32",
                    "reason": "protected device",
                    "created_by": "admin",
                    "created_at": NOW.isoformat(),
                }
            ],
        }
    )
    manager = FirewallManager(config, FakeFirewallBackend())
    candidate = make_candidate(action=FirewallAction.BLOCK, destination="192.168.1.77/32", threat_score=100.0)
    status = _submit(manager, candidate)
    assert status != RuleStatus.ACTIVE
