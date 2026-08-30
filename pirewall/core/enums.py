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
    """Transport/network-layer protocol a flow or rule matches on.

    OTHER covers an IP payload protocol pirewall doesn't decode further
    (e.g. GRE, ESP) — the packet is still identified at L3, just without
    port/flag information (spec §7 only requires TCP/UDP/ICMP/ICMPv6).
    """

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    OTHER = "other"
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
    # ADDENDUM_2.md B2 — many concurrent long-lived, low-throughput
    # connections from one source to one destination (slowloris-class). A
    # source-level aggregate pattern, same category as SCANNING/BURST, not
    # a per-flow classification of any single ambiguous connection.
    SLOW_RATE_DOS = "slow_rate_dos"


class ModelType(StrEnum):
    """ML model kinds used in the detection layer (spec §14)."""

    LIGHTGBM = "lightgbm"
    ISOLATION_FOREST = "isolation_forest"


class RuleRejectionReason(StrEnum):
    """Why `pirewall.firewall.validator` rejected a `CandidateRule` (spec §24)."""

    INVALID_SCHEMA = "invalid_schema"
    INVALID_NETWORK = "invalid_network"
    ALLOWLISTED = "allowlisted"
    UNSAFE = "unsafe"
    CONFLICT = "conflict"
    DUPLICATE = "duplicate"
    RATE_LIMITED = "rate_limited"
    SHADOWED = "shadowed"
    MISSING_EXPIRATION = "missing_expiration"
    UNAUTHORIZED = "unauthorized"


class AddressFamily(StrEnum):
    """IP address family of a parsed packet (spec §7).

    Both are parsed at the packet level, but only IPV4 is carried into the
    adaptive pipeline in v1 (ADDENDUM.md A5) — this tag is what lets Phase 3
    correctly exclude IPV6 packets from flow aggregation.
    """

    IPV4 = "ipv4"
    IPV6 = "ipv6"
