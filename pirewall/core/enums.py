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
    # Connection-rate flood: new connections from one source to one
    # destination at a rate no ordinary client produces. HIGH_FREQUENCY and
    # BURST fire the same at 3/s and 3,000/s; this is the pattern that
    # measures magnitude (benchmarks/2026-10-15-native-capture/LIVE_AB.md:
    # benign peak 39 per 5 s to one host, real floods 21k-39k).
    FLOOD = "flood"


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
    # v2 set path (ADDENDUM_4.md D1, D4), added by phase 13.
    UNENFORCEABLE = "unenforceable"
    """The rule names no LAN device the adaptive sets can key on (v2 enforces per device)."""
    EXPIRATION_TOO_LONG = "expiration_too_long"
    """The TTL exceeds `policy.max_ttl_seconds` (every adaptive element expires within 1 h)."""
    NO_NEW_EVIDENCE = "no_new_evidence"
    """An escalation (RATE_LIMIT -> BLOCK) without evidence the active rule did not already carry."""
    # MAC identity (ADDENDUM_4.md D3), added by phase 14.
    SPOOFED_SOURCE = "spoofed_source"
    """The evidence frame's MAC is not the one bound to the rule's source IP, and only the IP can be keyed.

    Acting on that IP would punish its bound owner for traffic another device
    sent (audit item 16). The v1 path keys on IPs, so it refuses; the v2 set
    path keys the sender's MAC instead.
    """


class AddressFamily(StrEnum):
    """IP address family of a parsed packet (spec §7).

    Both are parsed at the packet level, but only IPV4 is carried into the
    adaptive pipeline in v1 (ADDENDUM.md A5) — this tag is what lets Phase 3
    correctly exclude IPV6 packets from flow aggregation.
    """

    IPV4 = "ipv4"
    IPV6 = "ipv6"


# --- v2 vocabulary (docs/ADDENDUM_4.md, docs/V2_CONTRACTS.md) ---------------


class PipelineEngine(StrEnum):
    """Which detection/decision pipeline drives enforcement (ADDENDUM_4.md D4).

    V1 is the merged-main pipeline, kept runnable as the evaluation baseline.
    V2 is the policy-table pipeline (phase 17). Both deploy through the same
    set backend.
    """

    V1 = "v1"
    V2 = "v2"


class GuardName(StrEnum):
    """A static guard, named after its `guard_verdict_<name>` chain in `pirewall_static` (D1, D2)."""

    RAW = "raw"
    INPUT = "input"
    FORWARD = "forward"


class GuardMode(StrEnum):
    """Whether a guard's meter hits drop (ENFORCE) or are only recorded (OBSERVE) (ADDENDUM_4.md D2)."""

    OBSERVE = "observe"
    ENFORCE = "enforce"


class BindingSource(StrEnum):
    """Where an IP<->MAC binding came from (ADDENDUM_4.md D3)."""

    LEASE = "lease"
    STATIC = "static"


class EnvTag(StrEnum):
    """Provenance of every measurement artifact (ADDENDUM_4.md D7). Never mixed in one aggregate."""

    PI_LIVE = "pi-live"
    PI_SCRIPTED = "pi-scripted"
    SANDBOX = "sandbox"
    MOCK = "mock"


class D1Detector(StrEnum):
    """The deterministic, MAC-keyed detectors of `pipeline.engine = "v2"` (PLAN_FINAL §4.5)."""

    VERTICAL_SCAN = "vertical_scan"
    HORIZONTAL_SCAN = "horizontal_scan"
    FAILED_HANDSHAKE = "failed_handshake"
    BRUTE_FORCE = "brute_force"
    SLOW_RATE_DOS = "slow_rate_dos"
    FAN_IN = "fan_in"
    NEW_MAC_RATE = "new_mac_rate"
    NEW_LEASE_RATE = "new_lease_rate"
    PORTAL_AUTH_FAILURES = "portal_auth_failures"


class NftTransportKind(StrEnum):
    """How a set backend reaches the kernel (phase 13; V2_CONTRACTS.md §7, CLAUDE.md v2 dependencies)."""

    LIBNFTABLES = "libnftables"
    """`python3-nftables` (ctypes over the system libnftables): ~0.36 ms per set update (sandbox)."""
    SUBPROCESS = "subprocess"
    """`nft -j -f -`, one process per batch: the fallback, ~10 ms per call (sandbox)."""
    FAKE = "fake"
    """`FakeSetBackend`: in memory, for tests."""
