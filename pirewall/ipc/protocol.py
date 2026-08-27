"""The typed pirewall-core <-> pirewall-api RPC protocol (ADDENDUM.md A4).

`RpcRequest.params`/`RpcResponse.data` are the one deliberately untyped
(`dict[str, Any]`/`Any`) boundary in this module — a generic transport
envelope inherently carries heterogeneous payloads per operation, the same
way an HTTP request/response body is opaque JSON until a specific endpoint
deserializes it. Every operation's *actual* shape is fully typed:
`pirewall.ipc.client.RpcClient` methods take/return real Pydantic models
(`FirewallRule`, `SecurityEvent`, ...) or plain JSON-safe primitives, never
a raw dict, to their own callers.
"""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RpcOperation(StrEnum):
    """Every operation pirewall-api may invoke on pirewall-core. A closed set — no arbitrary commands."""

    GET_STATUS = "get_status"
    LIST_FLOWS = "list_flows"
    LIST_DETECTIONS = "list_detections"
    LIST_THREATS = "list_threats"
    LIST_DECISIONS = "list_decisions"
    LIST_RULES = "list_rules"
    LIST_EVENTS = "list_events"
    LIST_MODELS = "list_models"
    DISABLE_RULE = "disable_rule"
    REMOVE_RULE = "remove_rule"
    APPROVE_RULE = "approve_rule"
    REJECT_RULE = "reject_rule"
    LIST_ALLOWLIST = "list_allowlist"
    ADD_ALLOWLIST_ENTRY = "add_allowlist_entry"
    REMOVE_ALLOWLIST_ENTRY = "remove_allowlist_entry"
    KILL_SWITCH = "kill_switch"
    RECORD_EVENT = "record_event"


class RpcRequest(BaseModel):
    """One RPC call: a closed-set operation name plus its (operation-specific) parameters."""

    model_config = ConfigDict(extra="forbid")

    operation: RpcOperation
    params: dict[str, Any] = Field(default_factory=dict)  # Any: generic envelope, see module docstring


class RpcResponse(BaseModel):
    """One RPC result: either `ok` with `data`, or not-`ok` with `error`."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    data: Any = None  # Any: generic envelope, see module docstring
    error: str | None = None
