"""The `StatusResult` domain model — pirewall-core's live system status for the API's `/status`."""

from pydantic import AwareDatetime, Field, NonNegativeInt

from pirewall.core.enums import EnforcementMode, FailureMode
from pirewall.core.models.common import PirewallModel


class StatusResult(PirewallModel):
    """A snapshot of pirewall-core's own health and configuration state (spec §30 "System")."""

    started_at: AwareDatetime
    uptime_seconds: float = Field(ge=0.0)
    enforcement_mode: EnforcementMode
    failure_mode: FailureMode
    active_rule_count: NonNegativeInt
    pending_approval_count: NonNegativeInt
    tracked_flow_count: NonNegativeInt
    lightgbm_loaded: bool
    isolation_forest_loaded: bool
