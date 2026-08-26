"""Finite-value vocabulary shared across every subsystem.

Every field in the domain models (`pirewall.core.models`) that has a closed
set of legal values uses one of these enums rather than a raw string, per
`CLAUDE.md`'s type-safety rules.
"""

from enum import StrEnum


class ThreatLevel(StrEnum):
    """Coarse severity bucket a `ThreatAssessment` is classified into (spec §18)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FirewallAction(StrEnum):
    """Actions the decision engine may choose; only ones the backend supports (spec §19)."""

    ALLOW = "allow"
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit"
    BLOCK = "block"


class RuleStatus(StrEnum):
    """Rule lifecycle states, per the addendum-updated lifecycle (ADDENDUM.md, A1/A7/A8).

    See `docs/ADDENDUM.md` "RuleStatus lifecycle, updated" for the full state
    diagram, including how SHADOWED (A1) and PENDING_APPROVAL (A7) branch off
    VALIDATING, and how REMOVED is also the kill-switch (A8) terminal state.
    """

    CANDIDATE = "candidate"
    VALIDATING = "validating"
    REJECTED = "rejected"
    SHADOWED = "shadowed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    DEPLOYED = "deployed"
    ACTIVE = "active"
    EXPIRED = "expired"
    DISABLED = "disabled"
    REMOVED = "removed"


class RuleDirection(StrEnum):
    """Traffic direction a firewall rule applies to, relative to the protected LAN."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"


class Protocol(StrEnum):
    """Transport/network-layer protocol a flow or rule matches on."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    ANY = "any"


class SecurityEventType(StrEnum):
    """Kinds of `SecurityEvent` the system may emit (spec §31)."""

    THREAT_DETECTED = "threat_detected"
    FIREWALL_BLOCK = "firewall_block"
    FIREWALL_ALLOW = "firewall_allow"
    RULE_CREATED = "rule_created"
    RULE_DEPLOYED = "rule_deployed"
    RULE_REJECTED = "rule_rejected"
    RULE_EXPIRED = "rule_expired"
    MODEL_ERROR = "model_error"
    CAPTURE_ERROR = "capture_error"
    FLOW_ERROR = "flow_error"
    FIREWALL_ERROR = "firewall_error"
    AUTHENTICATION_FAILURE = "authentication_failure"
    SYSTEM_WARNING = "system_warning"


class EventSeverity(StrEnum):
    """Severity of a `SecurityEvent`, independent of its event type."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EnforcementMode(StrEnum):
    """Adaptive-enforcement mode (ADDENDUM.md A1). Default is SHADOW."""

    SHADOW = "shadow"
    ASSISTED = "assisted"
    ACTIVE = "active"


class FailureMode(StrEnum):
    """Behavior when `pirewall-core` crashes rather than shuts down cleanly (ADDENDUM.md A6)."""

    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"


class BehaviorPatternType(StrEnum):
    """Deterministic behavioral patterns the behavior analyzer can detect (spec §17)."""

    REPEATED_CONNECTIONS = "repeated_connections"
    HIGH_FREQUENCY = "high_frequency"
    BURST = "burst"
    PERSISTENCE = "persistence"
    DESTINATION_DIVERSITY = "destination_diversity"
    REPEATED_FAILURES = "repeated_failures"
    TEMPORAL_PATTERN = "temporal_pattern"
    SCANNING = "scanning"


class ModelType(StrEnum):
    """ML model kinds used in the detection layer (spec §14)."""

    LIGHTGBM = "lightgbm"
    ISOLATION_FOREST = "isolation_forest"
