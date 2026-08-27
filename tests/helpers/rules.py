"""Factories for `CandidateRule`/`FirewallRule` test fixtures."""

from datetime import UTC, datetime, timedelta
from typing import Any

from pirewall.core.enums import FirewallAction, Protocol, RuleDirection, RuleStatus
from pirewall.core.models.rule import CandidateRule, FirewallRule

DEFAULT_TIME = datetime(2026, 1, 1, tzinfo=UTC)


def make_candidate(**overrides: Any) -> CandidateRule:
    defaults: dict[str, object] = {
        "decision_id": "decision-1",
        "action": FirewallAction.BLOCK,
        "direction": RuleDirection.INBOUND,
        "source": "203.0.113.5/32",
        "destination": "192.168.1.10/32",
        "protocol": Protocol.TCP,
        "destination_port": 22,
        "reason": "test candidate",
        "threat_score": 90.0,
        "created_at": DEFAULT_TIME,
        "expires_at": DEFAULT_TIME + timedelta(hours=1),
    }
    defaults.update(overrides)
    return CandidateRule.model_validate(defaults)


def make_firewall_rule(**overrides: Any) -> FirewallRule:
    defaults: dict[str, object] = {
        "id": "rule-1",
        "action": FirewallAction.BLOCK,
        "direction": RuleDirection.INBOUND,
        "source": "203.0.113.5/32",
        "destination": "192.168.1.10/32",
        "protocol": Protocol.TCP,
        "destination_port": 22,
        "reason": "test rule",
        "threat_score": 90.0,
        "priority": 10,
        "status": RuleStatus.ACTIVE,
        "created_at": DEFAULT_TIME,
        "expires_at": DEFAULT_TIME + timedelta(hours=1),
    }
    defaults.update(overrides)
    return FirewallRule.model_validate(defaults)
