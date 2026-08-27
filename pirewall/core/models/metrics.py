"""The `NetdataMetricsSnapshot` domain model (spec §33, ADDENDUM.md A3).

A point-in-time snapshot of every operational metric spec §33 asks pirewall
to expose to Netdata, plus one addendum addition: adaptive-rule creation
rate and how close it is to `firewall.max_adaptive_rules_per_window` (A3).
Kept as a real Pydantic model — crossing the boundary into
`pirewall.integration.netdata` — rather than a raw dict, per CLAUDE.md.

Nothing in this module assembles a snapshot from live state: no running
main loop exists yet to poll capture statistics/flow-table size/rate
limiter state on a schedule (see `docs/PROGRESS.md` Phase 7's note on
`pirewall/main.py` being out of scope until that loop is built). This model
and `pirewall.integration.netdata.NetdataExporter` are the payload-shaping
half of the addendum's Netdata deliverable; wiring a periodic collector
that constructs one of these from `pirewall.ipc.state.CoreStateStore` +
`CaptureStatistics` + `RuleCreationRateLimiter` is deployment/runtime work,
not this phase's scope.
"""

from pydantic import Field, NonNegativeFloat, NonNegativeInt

from pirewall.core.models.common import PirewallModel


class NetdataMetricsSnapshot(PirewallModel):
    """One point-in-time reading of every metric `pirewall.integration.netdata` exports."""

    cpu_percent: float = Field(ge=0.0, le=100.0)
    memory_percent: float = Field(ge=0.0, le=100.0)

    packet_rate_per_second: NonNegativeFloat
    packet_drops: NonNegativeInt
    active_flows: NonNegativeInt
    flow_creation_rate_per_second: NonNegativeFloat
    flow_expiration_rate_per_second: NonNegativeFloat

    inference_count: NonNegativeInt
    inference_latency_ms: NonNegativeFloat

    detection_count: NonNegativeInt
    block_count: NonNegativeInt

    rule_count: NonNegativeInt
    rule_rejection_count: NonNegativeInt

    api_health: bool
    capture_health: bool
    firewall_health: bool

    # ADDENDUM.md A3: how fast adaptive rules are being created, and how
    # close that is to `firewall.max_adaptive_rules_per_window` for the
    # current window (1.0 == budget fully spent).
    adaptive_rule_creation_rate_per_window: NonNegativeInt
    adaptive_rule_budget_fraction: float = Field(ge=0.0, le=1.0)
