"""The pirewall-api side of the RPC protocol (ADDENDUM.md A4).

`BaseRpcClient` is the typed surface every route in `pirewall/api/routes/`
actually calls — never a raw `RpcRequest`/`RpcResponse`, and never
`pirewall.firewall.manager`/`pirewall.firewall.backend`/`pirewall.capture`
directly. `UnixSocketRpcClient` is the real, Linux-only transport; see
`pirewall.ipc.loopback.LoopbackRpcClient` for the test double.
"""

import socket
from abc import ABC, abstractmethod
from typing import Any, cast

from pydantic import ValidationError

from pirewall.core.exceptions import RpcError
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.capture_stats import CaptureStatistics
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.detection_record import DetectionRecord
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.flow import Flow
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.core.models.rule import FirewallRule
from pirewall.core.models.status import StatusResult
from pirewall.core.models.threat import ThreatAssessment
from pirewall.ipc._framing import read_all
from pirewall.ipc.protocol import RpcOperation, RpcRequest, RpcResponse


class BaseRpcClient(ABC):
    """Typed RPC methods, implemented once here in terms of one abstract `_call`."""

    @abstractmethod
    def _call(self, operation: RpcOperation, params: dict[str, Any] | None = None) -> RpcResponse:
        """Perform one RPC round-trip. Raises `RpcError` on transport failure."""
        ...

    def get_status(self) -> StatusResult:
        return StatusResult.model_validate(self._require_data(RpcOperation.GET_STATUS))

    def get_capture_stats(self) -> CaptureStatistics | None:
        """Current capture counters, or `None` if pirewall-core has not reported any yet."""
        data = self._optional_data(RpcOperation.GET_CAPTURE_STATS)
        return CaptureStatistics.model_validate(data) if data is not None else None

    def list_flows(self) -> list[Flow]:
        return [Flow.model_validate(item) for item in self._require_list(RpcOperation.LIST_FLOWS)]

    def list_detections(self) -> list[DetectionRecord]:
        items = self._require_list(RpcOperation.LIST_DETECTIONS)
        return [DetectionRecord.model_validate(item) for item in items]

    def list_threats(self) -> list[ThreatAssessment]:
        items = self._require_list(RpcOperation.LIST_THREATS)
        return [ThreatAssessment.model_validate(item) for item in items]

    def list_decisions(self) -> list[FirewallDecision]:
        items = self._require_list(RpcOperation.LIST_DECISIONS)
        return [FirewallDecision.model_validate(item) for item in items]

    def list_rules(self) -> list[FirewallRule]:
        return [FirewallRule.model_validate(item) for item in self._require_list(RpcOperation.LIST_RULES)]

    def list_events(self) -> list[SecurityEvent]:
        return [SecurityEvent.model_validate(item) for item in self._require_list(RpcOperation.LIST_EVENTS)]

    def list_models(self) -> list[ModelMetadata]:
        items = self._require_list(RpcOperation.LIST_MODELS)
        return [ModelMetadata.model_validate(item) for item in items]

    def disable_rule(self, rule_id: str) -> FirewallRule | None:
        data = self._optional_data(RpcOperation.DISABLE_RULE, {"rule_id": rule_id})
        return FirewallRule.model_validate(data) if data is not None else None

    def remove_rule(self, rule_id: str) -> FirewallRule | None:
        data = self._optional_data(RpcOperation.REMOVE_RULE, {"rule_id": rule_id})
        return FirewallRule.model_validate(data) if data is not None else None

    def approve_rule(self, rule_id: str) -> FirewallRule | None:
        data = self._optional_data(RpcOperation.APPROVE_RULE, {"rule_id": rule_id})
        return FirewallRule.model_validate(data) if data is not None else None

    def reject_rule(self, rule_id: str) -> FirewallRule | None:
        data = self._optional_data(RpcOperation.REJECT_RULE, {"rule_id": rule_id})
        return FirewallRule.model_validate(data) if data is not None else None

    def list_allowlist(self) -> list[AllowlistEntry]:
        items = self._require_list(RpcOperation.LIST_ALLOWLIST)
        return [AllowlistEntry.model_validate(item) for item in items]

    def add_allowlist_entry(self, entry: AllowlistEntry) -> AllowlistEntry:
        data = self._require_data(RpcOperation.ADD_ALLOWLIST_ENTRY, entry.model_dump(mode="json"))
        return AllowlistEntry.model_validate(data)

    def remove_allowlist_entry(self, entry_id: str) -> bool:
        data = self._require_data(RpcOperation.REMOVE_ALLOWLIST_ENTRY, {"entry_id": entry_id})
        return bool(data)

    def kill_switch(self) -> SecurityEvent:
        return SecurityEvent.model_validate(self._require_data(RpcOperation.KILL_SWITCH))

    def record_event(self, event: SecurityEvent) -> SecurityEvent:
        data = self._require_data(RpcOperation.RECORD_EVENT, event.model_dump(mode="json"))
        return SecurityEvent.model_validate(data)

    def _require_data(self, operation: RpcOperation, params: dict[str, Any] | None = None) -> Any:
        response = self._call(operation, params)
        if not response.ok:
            raise RpcError(response.error or f"RPC call {operation.value} failed")
        if response.data is None:
            raise RpcError(f"RPC call {operation.value} returned no data")
        return response.data

    def _optional_data(self, operation: RpcOperation, params: dict[str, Any] | None = None) -> Any | None:
        response = self._call(operation, params)
        if not response.ok:
            raise RpcError(response.error or f"RPC call {operation.value} failed")
        return response.data

    def _require_list(self, operation: RpcOperation, params: dict[str, Any] | None = None) -> list[Any]:
        data = self._require_data(operation, params)
        if not isinstance(data, list):
            raise RpcError(f"RPC call {operation.value} did not return a list")
        return cast("list[Any]", data)


class UnixSocketRpcClient(BaseRpcClient):
    """The real transport: one connection per call over a Unix domain socket.

    Linux-only (`socket.AF_UNIX`) — cannot be exercised on this dev
    machine. See `docs/PROGRESS.md` Phase 7 for the Environment-dependent
    label.
    """

    def __init__(self, socket_path: str, timeout_seconds: float = 5.0) -> None:
        self._socket_path = socket_path
        self._timeout_seconds = timeout_seconds

    def _call(self, operation: RpcOperation, params: dict[str, Any] | None = None) -> RpcResponse:
        request = RpcRequest(operation=operation, params=params or {})
        payload = request.model_dump_json().encode("utf-8")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self._timeout_seconds)
                sock.connect(self._socket_path)
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
                raw = read_all(sock)
        except OSError as exc:
            raise RpcError(f"failed to reach pirewall-core at {self._socket_path}: {exc}") from exc

        try:
            return RpcResponse.model_validate_json(raw)
        except ValidationError as exc:
            raise RpcError(f"malformed response from pirewall-core: {exc}") from exc
