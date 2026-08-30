"""Enum values match the spec/addendum vocabulary."""

from pirewall.core.enums import (
    AddressFamily,
    BehaviorPatternType,
    EnforcementMode,
    EventSeverity,
    FailureMode,
    FirewallAction,
    ModelType,
    Protocol,
    RuleDirection,
    RuleStatus,
    SecurityEventType,
    ThreatLevel,
)


def test_threat_level_values() -> None:
    assert {m.value for m in ThreatLevel} == {"low", "medium", "high", "critical"}


def test_firewall_action_values() -> None:
    assert {m.value for m in FirewallAction} == {"allow", "monitor", "rate_limit", "block"}


def test_rule_status_values_match_addendum_lifecycle() -> None:
    assert {m.value for m in RuleStatus} == {
        "candidate",
        "validating",
        "rejected",
        "shadowed",
        "pending_approval",
        "approved",
        "deployed",
        "active",
        "expired",
        "disabled",
        "removed",
    }


def test_rule_direction_values() -> None:
    assert {m.value for m in RuleDirection} == {"inbound", "outbound"}


def test_protocol_values() -> None:
    assert {m.value for m in Protocol} == {"tcp", "udp", "icmp", "icmpv6", "other", "any"}


def test_security_event_type_values() -> None:
    assert {m.value for m in SecurityEventType} == {
        "threat_detected",
        "firewall_block",
        "firewall_allow",
        "rule_created",
        "rule_deployed",
        "rule_rejected",
        "rule_expired",
        "model_error",
        "capture_error",
        "flow_error",
        "firewall_error",
        "authentication_failure",
        "system_warning",
    }


def test_event_severity_values() -> None:
    assert {m.value for m in EventSeverity} == {"info", "warning", "error", "critical"}


def test_enforcement_mode_values() -> None:
    assert {m.value for m in EnforcementMode} == {"shadow", "assisted", "active"}


def test_failure_mode_values() -> None:
    assert {m.value for m in FailureMode} == {"fail_open", "fail_closed"}


def test_behavior_pattern_type_values() -> None:
    assert {m.value for m in BehaviorPatternType} == {
        "repeated_connections",
        "high_frequency",
        "burst",
        "persistence",
        "destination_diversity",
        "repeated_failures",
        "temporal_pattern",
        "scanning",
        "slow_rate_dos",
    }


def test_model_type_values() -> None:
    assert {m.value for m in ModelType} == {"lightgbm", "isolation_forest"}


def test_address_family_values() -> None:
    assert {m.value for m in AddressFamily} == {"ipv4", "ipv6"}
