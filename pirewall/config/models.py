"""Validated settings models for every configuration section (spec §37).

Security-relevant fields (Admin PC IP, TLS material, credentials) have no
default value in these models — if they're missing from the loaded TOML,
Pydantic raises a validation error that `pirewall.config.loader` turns into
a `ConfigurationError`, rather than the system silently starting with an
insecure or empty value.
"""

from ipaddress import IPv4Address, IPv4Network
from typing import Literal

from pydantic import Field, model_validator

from pirewall.core.enums import (
    BehaviorPatternType,
    EnforcementMode,
    EnvTag,
    FailureMode,
    GuardMode,
    PipelineEngine,
)
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.common import PirewallModel, UnicastMacAddress


class NetworkConfig(PirewallModel):
    """WAN/LAN topology (spec §21, §37)."""

    wan_interface: str = Field(min_length=1)
    lan_interface: str = Field(min_length=1)
    protected_network: IPv4Network
    upstream_gateway: IPv4Address

    # The Pi's *own* LAN-facing address — the default gateway LAN clients
    # route through, and the address the Admin PC reaches the control
    # panel on. Distinct from `upstream_gateway` (the home router, on the
    # WAN side) and from `admin.admin_pc_ip` (the client end of a
    # management connection). Required, no default, because
    # `pirewall.firewall.validator._validate_safety` needs a concrete value
    # to satisfy spec §24's "never block pirewall itself / management
    # access" — see docs/PROGRESS.md's resolution of that open question.
    pirewall_lan_ip: IPv4Address


class CaptureConfig(PirewallModel):
    """Packet capture tuning (spec §6)."""

    interface: str = Field(min_length=1)
    snap_len: int = Field(default=65535, gt=0)
    promiscuous: bool = True
    buffer_size_bytes: int = Field(default=2 * 1024 * 1024, gt=0)

    # Which capture/aggregation path pirewall-core runs. "auto" uses the
    # native extension (TPACKET_V3 ring + Rust flow table, see
    # docs/ARCHITECTURE.md) when it is installed and falls back to the
    # pure-Python AF_PACKET path when it is not; "python" forces the
    # latter; "native" asks for the former and reports a SYSTEM_WARNING
    # if it has to fall back. `snap_len`/`buffer_size_bytes` apply to the
    # Python path only; the ring_* fields to the native path only.
    #
    # "replay" (ADDENDUM_4.md D7) feeds pcaps from `replay_path` through the
    # same flow engine instead of a live interface: no root, no NIC. Accepted
    # by validation since phase 11; the capture itself is phase 15 and its
    # wiring into pirewall-core phase 16. Until then core does not read it.
    backend: Literal["auto", "native", "python", "replay"] = "auto"
    # A pcap/pcapng file or a directory of them. Required when backend is
    # "replay", ignored otherwise.
    replay_path: str | None = Field(default=None, min_length=1)
    # "max" (virtual clock, as fast as possible), "realtime", or a multiplier
    # such as "10x".
    replay_speed: str = Field(default="max", pattern=r"^(max|realtime|[0-9]+(\.[0-9]+)?x)$")
    # TPACKET_V3 ring: block_count blocks of block_size bytes (a multiple
    # of the page size). 16 x 1 MiB holds tens of thousands of small
    # packets — seconds of a 10k pkt/s flood — in 16 MiB of a 768 MiB
    # MemoryMax. A partially filled block is handed over after
    # ring_block_timeout_ms, which bounds added latency at low rates.
    ring_block_size_bytes: int = Field(default=1024 * 1024, gt=0)
    ring_block_count: int = Field(default=16, gt=0)
    ring_block_timeout_ms: int = Field(default=50, gt=0)
    # Native path load shedding: at most this many completed flows / new-flow
    # signals are converted to Python objects per engine drain (~every 100 ms
    # under load); the excess is counted as backpressure and discarded inside
    # the engine. A flood completes tens of thousands of flows a second while
    # detection on a Pi assesses a few hundred, so converting them all would
    # only spend the GIL on objects the bounded queues then drop. The
    # source-level fast path needs far fewer signals than this to see a flood.
    native_max_flows_per_drain: int = Field(default=1_000, gt=0)
    native_max_new_flows_per_drain: int = Field(default=5_000, gt=0)

    @model_validator(mode="after")
    def _check_replay_source(self) -> "CaptureConfig":
        if self.backend == "replay" and self.replay_path is None:
            raise ValueError('capture.backend = "replay" needs capture.replay_path')
        return self


class FlowConfig(PirewallModel):
    """Flow-table timeouts and bounds (spec §8)."""

    # 120 s matches CICFlowMeter, which segmented the CICIDS2017 training data:
    # no training flow is longer than that (max measured 119.99997 s), so a
    # longer runtime flow would be a duration the models have never seen.
    active_timeout_seconds: int = Field(default=120, gt=0)
    inactive_timeout_seconds: int = Field(default=60, gt=0)
    max_flows: int = Field(default=100_000, gt=0)
    cleanup_interval_seconds: int = Field(default=30, gt=0)


class FeaturesConfig(PirewallModel):
    """Feature-schema pinning (spec §11)."""

    schema_version: str = Field(default="2.0.0", min_length=1)


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
    # Connection events (and, separately, failures) remembered per source
    # inside the sliding `behavior_window_seconds` window.
    max_tracked_connections_per_source: int = Field(default=2_000, gt=0)
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
    # FLOOD: new connections per second from one source to *one* destination,
    # measured over `burst_window_seconds`. 100/s = 500 in the default 5 s
    # window, ~12x the busiest benign client measured (39 in 5 s).
    flood_connections_per_second_threshold: float = Field(default=100.0, gt=0.0)

    # ADDENDUM_2.md B2 — slow-rate (slowloris-class) aggregate signal. A
    # flow only counts as a "slow connection" candidate once it has been
    # open at least this long while transferring at most this many
    # bytes/second; `concurrent_slow_connections_threshold` many such
    # candidates to the *same destination* from one source is what
    # actually fires the pattern — a single slow connection never does,
    # by construction (see `pirewall.detection.behavior`'s module
    # docstring for the false-positive reasoning this guards against).
    slow_connection_min_duration_seconds: float = Field(default=15.0, gt=0.0)
    slow_connection_max_bytes_per_second: float = Field(default=5.0, gt=0.0)
    concurrent_slow_connections_threshold: int = Field(default=8, gt=0)

    # ADDENDUM_2.md B5 — seed list of known-attack-tool JA3 fingerprints
    # (pirewall.detection.tls_fingerprint). A missing/malformed file
    # degrades to no JA3 matches ever being reported, same as a missing ML
    # artifact degrades that one evidence type — never a startup failure.
    known_tool_fingerprints_path: str = Field(
        default="config/known_tool_fingerprints.toml", min_length=1
    )

    # ADDENDUM_2 follow-up pass, section 3 — batched Isolation Forest
    # scoring. `IsolationForest.decision_function`'s cost is almost
    # entirely fixed per-call overhead, not tree traversal (measured at
    # ~30.7 ms/call on a real Pi 4 regardless of batch size 1 vs. 200:
    # benchmarks/2026-08-30/REPORT.md §3-4,
    # benchmarks/2026-08-31-anomaly-batching/quick_benchmark.py), so
    # scoring `anomaly_batch_size` flows in one call amortizes that
    # overhead across all of them instead of paying it once per flow.
    # `anomaly_batch_max_wait_seconds` bounds how long a flow can sit
    # waiting for a batch to fill under low load — worst-case *added*
    # detection latency from batching, not a per-flow guarantee.
    anomaly_batch_size: int = Field(default=50, gt=0)
    anomaly_batch_max_wait_seconds: float = Field(default=0.2, gt=0.0)

    # Source-level fast path. When new-connection signals push a source's
    # behavior score to MEDIUM or above, that source is assessed right away
    # from a snapshot of one of its open flows instead of waiting for a
    # flow to complete (a SYN flood's half-open flows only complete at the
    # inactive timeout, 60-90 s later). At most once per source per this
    # many seconds; the validator's duplicate check and the A3 rate cap
    # still apply to anything it proposes.
    source_assessment_cooldown_seconds: float = Field(default=10.0, gt=0.0)


class MLConfig(PirewallModel):
    """Model artifact locations and expected feature schema (spec §15)."""

    lightgbm_model_path: str = Field(min_length=1)
    isolation_forest_model_path: str = Field(min_length=1)
    feature_schema_version: str = Field(default="2.0.0", min_length=1)


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

    # Weights are data-informed as of model v0.4.0, no longer a flat guess.
    # Measured on the held-out CICIDS2017 test split (docs/ML_PIPELINE.md):
    #
    #   known-attack (LightGBM)   precision 0.9927   FPR 0.0018
    #   anomaly (IsolationForest) precision 0.5300   FPR 0.0987
    #
    # The anomaly detector is right about half the times it fires and has
    # ~55x the classifier's false-positive rate, so it must not be able to
    # raise a flow to an actionable level on its own: at 15 it cannot even
    # reach `low_threshold` (25) unaided, only push a score over a line in
    # combination. A confident known-attack detection alone reaches 60 —
    # past `medium` (50) but short of `high` (75), so enforcement still
    # wants corroboration.
    known_attack_weight: float = Field(default=60.0, ge=0.0, le=100.0)
    anomaly_weight: float = Field(default=15.0, ge=0.0, le=100.0)

    # Behavior: the *cap* on the summed per-pattern points below. Was 25
    # with every pattern worth weight/9, which made a behavior-only score
    # top out at 25 + anomaly 15 = 40 < `medium` (50): the attack-lab run
    # (benchmarks/2026-09-10-attack-lab) watched a real SYN flood, UDP flood
    # and port scan get detected and then capped at LOW (KNOWN_ISSUES #20).
    # 80 lets strong attack-shaped behavior reach HIGH (RATE_LIMIT) on its
    # own, while staying below `critical` (90) so BLOCK still needs a
    # second, independent kind of evidence.
    behavior_weight: float = Field(default=80.0, ge=0.0, le=100.0)
    # Points per detected pattern, summed then capped at `behavior_weight`.
    # Patterns are not equally diagnostic: SCANNING (many ports on one
    # host), REPEATED_FAILURES (unanswered attempts concentrated on one
    # host) and SLOW_RATE_DOS are shapes ordinary clients do not produce;
    # BURST/HIGH_FREQUENCY/REPEATED_CONNECTIONS/DESTINATION_DIVERSITY are
    # exactly what one phone loading one web page produces (KNOWN_ISSUES
    # #3). Checked against observed sets: a page load
    # (diversity+repeated+frequency+burst) = 30, and 45 with a spurious
    # anomaly flag -> still LOW (on real benign traffic, 45 + 15 made 10% of
    # a browsing burst MEDIUM: benchmarks/2026-10-15-native-capture/LIVE_AB.md);
    # the nmap scan (scanning+burst+frequency) = 75 -> HIGH; the floods
    # (scanning+failures+slow-rate) = capped 80 -> HIGH.
    behavior_pattern_points: dict[BehaviorPatternType, float] = Field(
        default_factory=lambda: {
            BehaviorPatternType.SCANNING: 55.0,
            BehaviorPatternType.REPEATED_FAILURES: 45.0,
            BehaviorPatternType.SLOW_RATE_DOS: 45.0,
            BehaviorPatternType.FLOOD: 80.0,
            BehaviorPatternType.BURST: 10.0,
            BehaviorPatternType.HIGH_FREQUENCY: 10.0,
            BehaviorPatternType.REPEATED_CONNECTIONS: 5.0,
            BehaviorPatternType.TEMPORAL_PATTERN: 10.0,
            BehaviorPatternType.DESTINATION_DIVERSITY: 5.0,
            BehaviorPatternType.PERSISTENCE: 0.0,
        }
    )

    # ADDENDUM_2.md B4/B5 — a structural TLS protocol-field match
    # (Heartbleed length mismatch, a JA3 fingerprint hit against known
    # attack tooling). Weighted above `known_attack_weight`: a Heartbleed
    # length mismatch is a near-certain structural protocol violation, not
    # a probabilistic classification, so a confident match (confidence=1.0
    # for Heartbleed) alone should already be actionable — see
    # `pirewall.detection.tls_heartbeat`/`tls_fingerprint` for how each
    # detector sets its own `confidence` (JA3 tool matches are honestly
    # weaker/evadable and set a lower one, so this single weight still
    # differentiates them the same way `known_attack_weight * confidence`
    # already does for LightGBM's classifications).
    protocol_signature_weight: float = Field(default=75.0, ge=0.0, le=100.0)

    # ADDENDUM_2.md B3 — the evidence-maturity gate. A source whose evidence
    # never qualifies on its own (no completed-flow classification, no
    # multi-observation behavioral pattern — e.g. anomaly evidence alone)
    # can still reach BLOCK/RATE_LIMIT if the same elevated reading recurs
    # for this many *consecutive* independent assessment windows.
    # `max_tracked_maturity_sources` bounds that tracker's memory the same
    # way `pirewall.detection.behavior`'s state is bounded.
    evidence_maturity_consistency_windows: int = Field(default=3, gt=0)
    max_tracked_maturity_sources: int = Field(default=10_000, gt=0)

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

    @model_validator(mode="after")
    def _check_pattern_points(self) -> "ThreatConfig":
        # Every pattern must be priced explicitly: a pattern silently worth 0
        # because a config file predates it is the kind of unread-setting bug
        # KNOWN_ISSUES #17 already records once.
        missing = sorted(set(BehaviorPatternType) - set(self.behavior_pattern_points))
        if missing:
            raise ValueError(f"behavior_pattern_points is missing pattern(s): {missing}")
        if any(points < 0.0 or points > 100.0 for points in self.behavior_pattern_points.values()):
            raise ValueError("behavior_pattern_points values must be within [0, 100]")
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

    # Where runtime-added allowlist entries (control panel / API) persist
    # across a restart — KNOWN_ISSUES.md #10. `allowlist` above stays the
    # static, deployment-declared seed; entries added at runtime live here
    # instead, following the same single-writer pattern as
    # `portal.user_store_path` (ADDENDUM_3.md C3): only `pirewall-core`
    # ever opens this file.
    allowlist_store_path: str = Field(default="/var/lib/pirewall/allowlist.json", min_length=1)

    # spec §24 "reject any rule broader than the evidence that generated
    # it": v1's adaptive pipeline only ever has single-flow evidence, so no
    # legitimate candidate should need to target anything broader than
    # this prefix length. Checked in the safety validation stage.
    min_rule_prefix_length: int = Field(default=24, ge=0, le=32)

    # Packets/second allowed through before a RATE_LIMIT rule starts
    # dropping (pirewall.firewall.backend.nftables).
    rate_limit_per_second: int = Field(default=10, gt=0)


class APIConfig(PirewallModel):
    """FastAPI network/TLS configuration (spec §28, §29)."""

    host: str = Field(default="127.0.0.1", min_length=1)
    port: int = Field(default=8443, gt=0, le=65535)
    tls_cert_path: str = Field(min_length=1)
    tls_key_path: str = Field(min_length=1)
    cors_origins: tuple[str, ...] = Field(default_factory=tuple)

    # How many recent flows/detections/threats/decisions/events
    # pirewall-core retains in memory for the control panel/API to read
    # (pirewall.ipc.state.CoreStateStore) — bounded, per spec §17/§26's
    # general "state must be bounded" theme.
    history_size: int = Field(default=500, gt=0)

    # The Unix domain socket pirewall-core listens on and pirewall-api
    # connects to (ADDENDUM.md A4). Filesystem permissions restricting it
    # to the two service users are set up in Phase 8's systemd units.
    rpc_socket_path: str = Field(default="/run/pirewall/core.sock", min_length=1)

    # How long pirewall-api waits for one RPC reply from pirewall-core.
    # Rendering the control panel makes roughly a dozen sequential calls,
    # and pirewall-core serializes every RPC — from both sockets — behind a
    # single lock, so a portal login's deliberately-slow scrypt lands in
    # front of a dashboard request that is already in flight. The generic
    # 5s socket default was thin enough for that to surface as a 503
    # "core unavailable" on a perfectly healthy system, which is a
    # misdiagnosis rather than a delay.
    rpc_timeout_seconds: float = Field(default=20.0, gt=0.0)


class AuthenticationConfig(PirewallModel):
    """Single-admin username/password authentication (spec §29: no RBAC beyond one role)."""

    admin_username: str = Field(min_length=1)
    admin_password_hash: str = Field(min_length=1)
    token_expiry_seconds: int = Field(default=3600, gt=0)


class AdminConfig(PirewallModel):
    """The Admin PC's address, and whether the Pi's own console may reach the panel."""

    admin_pc_ip: IPv4Address

    # ADDENDUM_3.md C6. Loopback only — never a routable address. An
    # operator at the Pi's desktop can open the control panel at
    # https://127.0.0.1:<api.port> without the panel becoming reachable
    # from the LAN, the WAN, or anything that can occupy the admin segment.
    # Defaults off: a deployment gets this only by asking for it.
    allow_local_console: bool = False


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
    netdata_host: str | None = None
    netdata_port: int | None = Field(default=None, gt=0, le=65535)


class PortalConfig(PirewallModel):
    """LAN captive portal (ADDENDUM_3.md C1-C5).

    Disabled by default. Turning it on gates *forwarding* for the protected
    network behind a login; it never gates association, DHCP, DNS, or
    reaching the portal itself, so any device can always join the AP and be
    shown the login page.
    """

    enabled: bool = False

    # Shown on the login page. Defaults to the AP's SSID in practice;
    # purely cosmetic, so a wrong value misleads nobody about access.
    network_name: str = Field(default="pirewall-lan", min_length=1, max_length=64)

    # Bound to the Pi's LAN address on an unprivileged port. Port 80 is
    # redirected here by `pirewall_portal`'s nat chain, so the portal
    # process needs no CAP_NET_BIND_SERVICE at all.
    listen_host: IPv4Address = IPv4Address("192.168.100.1")
    listen_port: int = Field(default=8080, gt=1023, le=65535)

    # How long a login lasts. Handed to the kernel as the nft set element's
    # own timeout, so expiry costs nothing at runtime, and shown to the
    # client as the keepalive countdown.
    session_timeout_seconds: int = Field(default=1800, gt=0)
    keepalive_interval_seconds: int = Field(default=20, gt=0)

    # Written and read only by pirewall-core (single writer, ADDENDUM_3.md C3).
    user_store_path: str = Field(default="/var/lib/pirewall/portal_users.json", min_length=1)

    # Its own log directory, separate from `logging.log_dir`. pirewall-core
    # and pirewall-api share `/var/log/pirewall` through the `pirewall-ipc`
    # group; pirewall-portal is deliberately not in that group, so it cannot
    # write there and must not be asked to (ADDENDUM_3.md C1).
    log_dir: str = Field(default="/var/log/pirewall-portal", min_length=1)

    # A second RPC socket, distinct from `api.rpc_socket_path`, serving a
    # dispatcher that exposes only the portal operations. The LAN-facing
    # process must not be able to reach kill-switch or rule mutation.
    #
    # Its own *directory*, not a second file in `/run/pirewall`: that
    # directory is mode 0750 group `pirewall-ipc`, so a process outside that
    # group cannot traverse into it whatever the socket's own permissions
    # say. Putting the portal socket there would have forced either
    # pirewall-portal into `pirewall-ipc` (handing it the privileged socket,
    # defeating the split) or the directory to 0751 (world-traversable).
    rpc_socket_path: str = Field(default="/run/pirewall-portal/portal.sock", min_length=1)
    rpc_socket_group: str = Field(default="pirewall-portal-ipc", min_length=1)

    # A portal login includes scrypt under the same single core-side lock,
    # so this is deliberately far above the generic socket default. Config
    # rather than a literal at the call site: it is the same tuning
    # decision as `api.rpc_timeout_seconds` and belongs next to it.
    rpc_timeout_seconds: float = Field(default=20.0, gt=0.0)

    # Online password guessing against the portal is cheap for anyone who
    # can associate with the AP; scrypt alone only slows it down.
    max_failed_logins_per_ip: int = Field(default=5, gt=0)
    failed_login_window_seconds: int = Field(default=300, gt=0)
    max_sessions: int = Field(default=512, gt=0)

    # Shown on the login page so users know who to contact when a block
    # notice appears (ADDENDUM_3.md C4).
    contact_message: str = Field(default="Please contact your network administrator.", min_length=1)


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


# --- v2 sections (ADDENDUM_4.md). All optional with defaults: a 1.x/2.0 file
# --- without them still loads, and nothing reads them until a later phase.


class PipelineConfig(PirewallModel):
    """Which pipeline drives enforcement (ADDENDUM_4.md D4).

    Stays "v1" (the merged-main pipeline) until phase 17 ships the v2 policy
    engine; v1 then remains selectable as the evaluation baseline (G8).
    """

    engine: PipelineEngine = PipelineEngine.V1


class MeterSetting(PirewallModel):
    """One nft meter's `limit rate over <rate>/<unit> burst <burst> packets`.

    A pair, not two independent knobs: the burst is part of the threshold.
    A 3 s, 30k-packet flood once fitted entirely inside a 40k burst
    (docs/v2/v2/RESULTS.md finding 2), so benign calibration fits both
    together. The unit (per second, or per minute for DHCP) is fixed by the
    template rule the setting renders into.
    """

    rate: int = Field(gt=0)
    burst: int = Field(gt=0)


class GuardsConfig(PirewallModel):
    """Static kernel guards in `pirewall_static` (ADDENDUM_4.md D1, D2).

    Defaults are the template starting values (`docs/v2/v2/render.py`), to be
    replaced by benign-capture calibration. Rendered into the templates by
    `pirewall-start`; core changes only the three modes at runtime, and only
    through `FirewallManager.set_guard_mode`. docs/V2_CONTRACTS.md maps each
    field to its template variable.
    """

    # D2 defaults. `raw_mode = "enforce"` is "enforce if seeded": when the
    # bindings cannot be seeded at startup, the raw guard is forced to
    # observe regardless of this value, because enforcing anti-spoof with an
    # empty binding set would drop every client on the LAN.
    raw_mode: GuardMode = GuardMode.ENFORCE
    input_mode: GuardMode = GuardMode.ENFORCE
    # Observe until the offline benign false-positive check (G5) passes.
    forward_mode: GuardMode = GuardMode.OBSERVE

    # Per-MAC meters. Rates are packets/second except `dhcp_per_minute`.
    dhcp_per_minute: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=10, burst=5))
    unbound: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=50, burst=100))
    syn: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=200, burst=400))
    icmp: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=50, burst=100))
    udp_local: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=500, burst=1000))
    local_pps: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=3000, burst=6000))
    dns: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=100, burst=300))
    closed_port: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=20, burst=40))
    newconn: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=100, burst=200))
    newconn_dst: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=50, burst=100))
    udp_fwd: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=20000, burst=40000))
    # Keyless global backstops: they engage when a meter set is full or many
    # MACs flood together (RESULTS.md test 11).
    global_unbound: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=500, burst=1000))
    global_syn: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=2000, burst=4000))
    global_icmp: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=500, burst=1000))
    global_udp_local: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=3000, burst=6000))
    global_newconn: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=1000, burst=2000))
    # `ct count over` per MAC on the portal ports.
    portal_concurrency: int = Field(default=20, gt=0)
    # The adaptive table's `ratelimit_mac` meter (written by FirewallManager,
    # rendered from here like the guards).
    ratelimit: MeterSetting = Field(default_factory=lambda: MeterSetting(rate=20, burst=40))

    # Set sizes. A full dynamic meter stops policing new keys (it fails open),
    # so meter sets are sized to at least twice the DHCP pool and every class
    # has a global backstop behind it.
    binding_set_size: int = Field(default=1024, gt=0)
    meter_set_size: int = Field(default=256, gt=0)
    pair_meter_set_size: int = Field(default=4096, gt=0)
    offender_set_size: int = Field(default=4096, gt=0)
    adaptive_set_size: int = Field(default=4096, gt=0)


class StaticBindingEntry(PirewallModel):
    """One `[[antispoof.static]]` entry: a device with a fixed address and no DHCP lease (D3)."""

    ip: IPv4Address
    mac: UnicastMacAddress
    reason: str = Field(min_length=1)


class AntispoofConfig(PirewallModel):
    """IP<->MAC binding sources for the anti-spoof guard (ADDENDUM_4.md D3)."""

    # NetworkManager shared mode's dnsmasq lease file for the LAN interface:
    # /var/lib/NetworkManager/dnsmasq-<lan_interface>.leases. Read-only; only
    # the expiry, MAC and IP fields are parsed, never hostname or client-id.
    lease_file: str = Field(default="/var/lib/NetworkManager/dnsmasq-wlan0.leases", min_length=1)
    static: tuple[StaticBindingEntry, ...] = Field(default_factory=tuple)
    # Added to a lease's expiry when it becomes the binding's element timeout,
    # so a renewal that lands in the lease file a moment late (file-write lag
    # plus the poll interval) does not briefly unbind the device.
    grace_seconds: int = Field(default=60, ge=0)
    # Lease-file poll interval, alongside inotify where available.
    poll_seconds: float = Field(default=2.0, gt=0.0)

    @model_validator(mode="after")
    def _check_static_unique(self) -> "AntispoofConfig":
        ips = [entry.ip for entry in self.static]
        macs = [entry.mac for entry in self.static]
        if len(set(ips)) != len(ips) or len(set(macs)) != len(macs):
            raise ValueError("antispoof.static: each IP and each MAC may appear in only one entry")
        return self


class PolicyConfig(PirewallModel):
    """v2 policy-table parameters (ADDENDUM_4.md D4, PLAN_FINAL §4.6)."""

    rate_limit_ttl_seconds: int = Field(default=300, gt=0)
    block_ttl_seconds: int = Field(default=300, gt=0)
    # A repeat with new independent evidence multiplies the TTL by this,
    # capped at `max_ttl_seconds`.
    escalation_ttl_multiplier: int = Field(default=2, ge=1)
    # Every adaptive element expires; 3600 s is also the template ceiling.
    max_ttl_seconds: int = Field(default=3600, gt=0, le=3600)
    # Consecutive 1 s polls an enforce-mode offender must persist before it
    # may cause RATE_LIMIT. Never below 2 (critique_round2.md item 6).
    sustained_polls: int = Field(default=2, ge=2)

    @model_validator(mode="after")
    def _check_ttls_within_cap(self) -> "PolicyConfig":
        if max(self.rate_limit_ttl_seconds, self.block_ttl_seconds) > self.max_ttl_seconds:
            raise ValueError("policy TTLs must not exceed policy.max_ttl_seconds")
        return self


class LabConfig(PirewallModel):
    """Evaluation provenance and the on-Pi forward-path victim (ADDENDUM_4.md D7).

    `env_tag` labels every artifact this process writes. It defaults to
    "sandbox", never a `pi-*` tag: a Pi result has to be claimed explicitly
    (pirewall-start sets it per `--data-mode`), so a forgotten setting can
    only under-claim.
    """

    env_tag: EnvTag = EnvTag.SANDBOX
    victim_netns: str = Field(default="labvictim", min_length=1)
    # Host side of the veth into the victim namespace. LAN -> lab0 crosses
    # the forward hook exactly as Internet-bound traffic does.
    victim_host_interface: str = Field(default="lab0", min_length=1, max_length=15)
    # A routed /30: the host side takes the first usable address, the victim
    # the second.
    victim_network: IPv4Network = IPv4Network("10.250.0.0/30")

    @model_validator(mode="after")
    def _check_victim_network(self) -> "LabConfig":
        if self.victim_network.prefixlen != 30:
            raise ValueError("lab.victim_network must be a /30")
        return self


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
    portal: PortalConfig = PortalConfig()
    logging: LoggingConfig
    integration: IntegrationConfig
    security: SecurityConfig
    failure: FailureConfig
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    guards: GuardsConfig = Field(default_factory=GuardsConfig)
    antispoof: AntispoofConfig = Field(default_factory=AntispoofConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    lab: LabConfig = Field(default_factory=LabConfig)
