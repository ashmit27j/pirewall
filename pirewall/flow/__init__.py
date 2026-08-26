"""Flow aggregation: converts packets into canonical bidirectional flows (Phase 3)."""

from pirewall.flow.aggregator import FlowAggregator
from pirewall.flow.key import FlowKey, compute_flow_key
from pirewall.flow.state import FlowState, FlowTable, RunningStats
from pirewall.flow.timeout import FlowCloseReason, check_closure, is_tcp_completed

__all__ = [
    "FlowAggregator",
    "FlowCloseReason",
    "FlowKey",
    "FlowState",
    "FlowTable",
    "RunningStats",
    "check_closure",
    "compute_flow_key",
    "is_tcp_completed",
]
