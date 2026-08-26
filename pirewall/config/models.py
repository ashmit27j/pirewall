"""Validated settings models for every configuration section (spec §37).

Security-relevant fields (Admin PC IP, TLS material, credentials) have no
default value in these models — if they're missing from the loaded TOML,
Pydantic raises a validation error that `pirewall.config.loader` turns into
a `ConfigurationError`, rather than the system silently starting with an
insecure or empty value.
"""

from ipaddress import IPv4Address, IPv4Network

from pydantic import Field, model_validator

from pirewall.core.enums import EnforcementMode, FailureMode
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.common import PirewallModel


class NetworkConfig(PirewallModel):
    """WAN/LAN topology (spec §21, §37)."""

    wan_interface: str = Field(min_length=1)
    lan_interface: str = Field(min_length=1)
    protected_network: IPv4Network
    upstream_gateway: IPv4Address


class CaptureConfig(PirewallModel):
    """Packet capture tuning (spec §6)."""

    interface: str = Field(min_length=1)
    snap_len: int = Field(default=65535, gt=0)
    promiscuous: bool = True
    buffer_size_bytes: int = Field(default=2 * 1024 * 1024, gt=0)


class FlowConfig(PirewallModel):
    """Flow-table timeouts and bounds (spec §8)."""

    active_timeout_seconds: int = Field(default=1800, gt=0)
    inactive_timeout_seconds: int = Field(default=60, gt=0)
    max_flows: int = Field(default=100_000, gt=0)
    cleanup_interval_seconds: int = Field(default=30, gt=0)


class FeaturesConfig(PirewallModel):
    """Feature-schema pinning (spec §11)."""

    schema_version: str = Field(default="1.0.0", min_length=1)


class DetectionConfig(PirewallModel):
    """Detection-layer thresholds (spec §17, §18).

    The `behavior_*`/`*_threshold` fields below are the configurable knobs
    for `pirewall.detection.behavior`'s deterministic pattern detection —
    every one of them exists so no threshold is a magic number inline in
    that module (CLAUDE.md).
    """

    known_attack_confidence_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    anomaly_score_threshold: float = 0.0
    behavior_window_seconds: int = Field(default=300, gt=0)

    # Bounded state (spec §17 "behavior state must be bounded").
    max_tracked_sources: int = Field(default=10_000, gt=0)
    max_tracked_destinations_per_source: int = Field(default=200, gt=0)
    max_tracked_ports_per_source: int = Field(default=200, gt=0)
    recent_connections_window: int = Field(default=50, gt=0)

    # Pattern thresholds.
    repeated_connections_threshold: int = Field(default=20, gt=0)
    high_frequency_per_second_threshold: float = Field(default=2.0, gt=0.0)
    burst_window_seconds: float = Field(default=5.0, gt=0.0)
    burst_count_threshold: int = Field(default=10, gt=0)
    persistence_seconds_threshold: float = Field(default=1800.0, gt=0.0)
    destination_diversity_threshold: int = Field(default=15, gt=0)
    scanning_port_threshold: int = Field(default=10, gt=0)
    repeated_failures_threshold: int = Field(default=10, gt=0)
    temporal_pattern_cv_threshold: float = Field(default=0.15, gt=0.0)


class MLConfig(PirewallModel):
    """Model artifact locations and expected feature schema (spec §15)."""

    lightgbm_model_path: str = Field(min_length=1)
    isolation_forest_model_path: str = Field(min_length=1)
    feature_schema_version: str = Field(default="1.0.0", min_length=1)


class ThreatConfig(PirewallModel):
    """Threat-score-to-level thresholds and evidence weights (spec §18).

    Threshold fields must be strictly ascending. `*_weight` fields are the
    maximum 0-100 contribution each evidence type can add to the overall
    score in `pirewall.engine.scoring` — kept here, not inline, so scoring
    has no magic constants (CLAUDE.md).
    """

    low_threshold: float = Field(default=25.0, ge=0.0, le=100.0)
    medium_threshold: float = Field(default=50.0, ge=0.0, le=100.0)
    high_threshold: float = Field(default=75.0, ge=0.0, le=100.0)
    critical_threshold: float = Field(default=90.0, ge=0.0, le=100.0)

    known_attack_weight: float = Field(default=50.0, ge=0.0, le=100.0)
    anomaly_weight: float = Field(default=25.0, ge=0.0, le=100.0)
    behavior_weight: float = Field(default=25.0, ge=0.0, le=100.0)

    @model_validator(mode="after")
    def _check_ascending(self) -> "ThreatConfig":
        thresholds = (
            self.low_threshold,
            self.medium_threshold,
            self.high_threshold,
            self.critical_threshold,
        )
        if list(thresholds) != sorted(thresholds) or len(set(thresholds)) != len(thresholds):
            raise ValueError("threat thresholds must be strictly ascending: low<med<high<critical")
        return self


class FirewallConfig(PirewallModel):
    """Firewall/adaptive-rule policy, including the addendum's safety controls.

    `enforcement_mode` (A1), `assisted_review_threshold` (A7),
    `max_adaptive_rules_per_window`/`rate_window_seconds` (A3), and
    `allowlist` (A2) are documented in `docs/ADDENDUM.md` under their
    respective item letters.
    """

    enforcement_mode: EnforcementMode = EnforcementMode.SHADOW
    assisted_review_threshold: float = Field(default=75.0, ge=0.0, le=100.0)
    max_adaptive_rules_per_window: int = Field(default=20, gt=0)
    rate_window_seconds: int = Field(default=60, gt=0)
    default_rule_ttl_seconds: int = Field(default=3600, gt=0)
    max_active_rules: int = Field(default=500, gt=0)
    allowlist: tuple[AllowlistEntry, ...] = Field(default_factory=tuple)


class APIConfig(PirewallModel):
    """FastAPI network/TLS configuration (spec §28, §29)."""

    host: str = Field(default="127.0.0.1", min_length=1)
    port: int = Field(default=8443, gt=0, le=65535)
    tls_cert_path: str = Field(min_length=1)
    tls_key_path: str = Field(min_length=1)
    cors_origins: tuple[str, ...] = Field(default_factory=tuple)


class AuthenticationConfig(PirewallModel):
    """Single-admin username/password authentication (spec §29: no RBAC beyond one role)."""

    admin_username: str = Field(min_length=1)
    admin_password_hash: str = Field(min_length=1)
    token_expiry_seconds: int = Field(default=3600, gt=0)


class AdminConfig(PirewallModel):
    """The Admin PC that management access is restricted to (spec §29)."""

    admin_pc_ip: IPv4Address


class LoggingConfig(PirewallModel):
    """Structured logging configuration (spec §38)."""

    level: str = Field(default="INFO", min_length=1)
    log_dir: str = Field(default="/var/log/pirewall", min_length=1)
    max_bytes: int = Field(default=10 * 1024 * 1024, gt=0)
    backup_count: int = Field(default=5, ge=0)


class IntegrationConfig(PirewallModel):
    """Optional Wazuh/Netdata forwarding (spec §32, §33)."""

    wazuh_enabled: bool = False
    wazuh_host: str | None = None
    wazuh_port: int | None = Field(default=None, gt=0, le=65535)
    netdata_enabled: bool = False
    netdata_port: int | None = Field(default=None, gt=0, le=65535)


class SecurityConfig(PirewallModel):
    """Cross-cutting security policy (spec §29, §45)."""

    min_tls_version: str = Field(default="TLSv1.3", min_length=1)
    restrict_to_admin_pc: bool = True
    session_timeout_seconds: int = Field(default=1800, gt=0)


class FailureConfig(PirewallModel):
    """Fail-open/fail-closed behavior and crash-loop watchdog (ADDENDUM.md A6)."""

    mode: FailureMode = FailureMode.FAIL_OPEN
    watchdog_sec: int = Field(default=30, gt=0)
    crash_loop_restart_count: int = Field(default=3, gt=0)
    crash_loop_window_seconds: int = Field(default=300, gt=0)


class PirewallConfig(PirewallModel):
    """The complete, validated configuration tree (spec §37)."""

    network: NetworkConfig
    capture: CaptureConfig
    flow: FlowConfig
    features: FeaturesConfig
    detection: DetectionConfig
    ml: MLConfig
    threat: ThreatConfig
    firewall: FirewallConfig
    api: APIConfig
    authentication: AuthenticationConfig
    admin: AdminConfig
    logging: LoggingConfig
    integration: IntegrationConfig
    security: SecurityConfig
    failure: FailureConfig
