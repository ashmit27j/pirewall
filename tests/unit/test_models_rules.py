"""`CandidateRule` and `FirewallRule` domain models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from pirewall.core.enums import FirewallAction, Protocol, RuleDirection, RuleStatus
from pirewall.core.models.rule import CandidateRule, FirewallRule

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _make_candidate(**overrides: object) -> CandidateRule:
    defaults: dict[str, object] = {
        "decision_id": "decision-1",
        "action": FirewallAction.BLOCK,
        "direction": RuleDirection.INBOUND,
        "source": "203.0.113.5/32",
        "destination": "10.0.0.0/24",
        "protocol": Protocol.TCP,
        "destination_port": 22,
        "reason": "repeated failed SSH auth",
        "threat_score": 88.0,
        "created_at": NOW,
    }
    defaults.update(overrides)
    return CandidateRule.model_validate(defaults)


def test_valid_candidate_rule_constructs() -> None:
    rule = _make_candidate()
    assert rule.status is RuleStatus.CANDIDATE
    assert rule.id  # generated automatically


def test_candidate_rule_ipv6_source_rejected() -> None:
    """IPv4-only for v1 (ADDENDUM.md A5) — no CandidateRule may target an IPv6 CIDR."""
    with pytest.raises(ValidationError):
        _make_candidate(source="2001:db8::/32")


def test_candidate_rule_bad_cidr_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_candidate(destination="10.0.0.0/99")


def test_candidate_rule_out_of_range_port_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_candidate(destination_port=99999)


def test_candidate_rule_bad_threat_score_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_candidate(threat_score=-5.0)


def test_valid_firewall_rule_constructs() -> None:
    rule = FirewallRule.model_validate(
        {
            "id": "rule-1",
            "action": FirewallAction.BLOCK,
            "direction": RuleDirection.INBOUND,
            "source": "203.0.113.5/32",
            "destination": "10.0.0.0/24",
            "protocol": Protocol.TCP,
            "destination_port": 22,
            "reason": "repeated failed SSH auth",
            "threat_score": 88.0,
            "priority": 100,
            "status": RuleStatus.ACTIVE,
            "created_at": NOW,
        }
    )
    assert rule.status is RuleStatus.ACTIVE


def test_firewall_rule_ipv6_destination_rejected() -> None:
    with pytest.raises(ValidationError):
        FirewallRule.model_validate(
            {
                "id": "rule-1",
                "action": FirewallAction.BLOCK,
                "direction": RuleDirection.OUTBOUND,
                "source": "10.0.0.0/24",
                "destination": "2001:db8::/32",
                "protocol": Protocol.TCP,
                "reason": "n/a",
                "priority": 100,
                "status": RuleStatus.ACTIVE,
                "created_at": NOW,
            }
        )
