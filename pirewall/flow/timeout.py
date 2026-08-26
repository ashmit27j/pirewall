"""Flow closure decisions: active/inactive timeouts and TCP completion (spec §8)."""

from datetime import datetime
from enum import StrEnum

from pirewall.core.enums import Protocol
from pirewall.flow.state import FlowState


class FlowCloseReason(StrEnum):
    """Why a flow was finalized and removed from the flow table."""

    TCP_COMPLETED = "tcp_completed"
    ACTIVE_TIMEOUT = "active_timeout"
    INACTIVE_TIMEOUT = "inactive_timeout"


def is_tcp_completed(state: FlowState) -> bool:
    """A TCP flow is complete on a RST, or on FIN observed in both directions."""
    if state.protocol is not Protocol.TCP:
        return False
    return state.saw_rst or (state.saw_fin_forward and state.saw_fin_backward)


def check_closure(
    state: FlowState,
    now: datetime,
    active_timeout_seconds: float,
    inactive_timeout_seconds: float,
) -> FlowCloseReason | None:
    """Decide whether `state` should be closed as of `now`, and why.

    Checked in order: TCP completion first (a definite signal, regardless of
    timing), then active timeout (total flow lifetime), then inactive
    timeout (time since the last packet). Returns `None` if the flow should
    stay open.
    """
    if is_tcp_completed(state):
        return FlowCloseReason.TCP_COMPLETED
    if (now - state.first_seen).total_seconds() >= active_timeout_seconds:
        return FlowCloseReason.ACTIVE_TIMEOUT
    if (now - state.last_seen).total_seconds() >= inactive_timeout_seconds:
        return FlowCloseReason.INACTIVE_TIMEOUT
    return None
