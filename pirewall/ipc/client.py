"""The pirewall-api side of the RPC protocol (ADDENDUM.md A4).

`BaseRpcClient` is the typed surface every route in `pirewall/api/routes/`
actually calls — never a raw `RpcRequest`/`RpcResponse`, and never
`pirewall.firewall.manager`/`pirewall.firewall.backend`/`pirewall.capture`
directly. `UnixSocketRpcClient` is the real, Linux-only transport; see
`pirewall.ipc.loopback.LoopbackRpcClient` for the test double.
"""

import socket
from abc import ABC, abstractmethod
from ipaddress import IPv4Address
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
from pirewall.core.models.portal import PortalClientState, PortalSession, PortalUser
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

    def add_allowlist_entry_with_portal_user(
        self, entry: AllowlistEntry, portal_username: str | None
    ) -> dict[str, Any]:
        """Add an entry, optionally provisioning a portal account alongside it.

        Returns the raw response object rather than an `AllowlistEntry`
        because it may carry `portal_username`/`portal_password` — the one
        and only appearance of a generated portal password (ADDENDUM_3.md
        C3). Parsing it into `AllowlistEntry` here would discard exactly the
        field the caller needs.
        """
        params = entry.model_dump(mode="json")
        if portal_username:
            params["portal_username"] = portal_username
        data = self._require_data(RpcOperation.ADD_ALLOWLIST_ENTRY, params)
        if not isinstance(data, dict):
            raise RpcError("add_allowlist_entry did not return an object")
        return cast("dict[str, Any]", data)

    def remove_allowlist_entry(self, entry_id: str) -> bool:
        data = self._require_data(RpcOperation.REMOVE_ALLOWLIST_ENTRY, {"entry_id": entry_id})
        return bool(data)

    def kill_switch(self) -> SecurityEvent:
        return SecurityEvent.model_validate(self._require_data(RpcOperation.KILL_SWITCH))

    def record_event(self, event: SecurityEvent) -> SecurityEvent:
        data = self._require_data(RpcOperation.RECORD_EVENT, event.model_dump(mode="json"))
        return SecurityEvent.model_validate(data)

    # --- captive portal, client-facing (ADDENDUM_3.md C1) ------------------
    # Available on both sockets' clients as typed methods, but only the
    # portal socket's dispatcher implements these four; calling them against
    # pirewall-core's own socket returns "unknown operation".

    def portal_status(self) -> dict[str, Any]:
        """Login-page prerequisites: demo-account warning, contact text, timings."""
        data = self._require_data(RpcOperation.PORTAL_STATUS)
        if not isinstance(data, dict):
            raise RpcError("portal_status did not return an object")
        return cast("dict[str, Any]", data)

    def portal_login(self, username: str, password: str, client_ip: IPv4Address) -> PortalSession:
        data = self._require_data(
            RpcOperation.PORTAL_LOGIN,
            {"username": username, "password": password, "client_ip": str(client_ip)},
        )
        return PortalSession.model_validate(data)

    def portal_keepalive(self, token: str | None, client_ip: IPv4Address) -> PortalClientState:
        data = self._require_data(
            RpcOperation.PORTAL_KEEPALIVE, {"token": token or "", "client_ip": str(client_ip)}
        )
        return PortalClientState.model_validate(data)

    def portal_logout(self, token: str, client_ip: IPv4Address) -> bool:
        data = self._require_data(
            RpcOperation.PORTAL_LOGOUT, {"token": token, "client_ip": str(client_ip)}
        )
        return bool(data)

    # --- captive portal, admin-facing --------------------------------------

    def portal_list_users(self) -> list[PortalUser]:
        items = self._require_list(RpcOperation.PORTAL_LIST_USERS)
        return [PortalUser.model_validate(item) for item in items]

    def portal_add_user(
        self, username: str, created_by: str, password: str | None = None, note: str = ""
    ) -> tuple[PortalUser, str | None]:
        """Create an account. Returns the user and the generated password, if one was generated."""
        data = self._require_data(
            RpcOperation.PORTAL_ADD_USER,
            {"username": username, "created_by": created_by, "password": password or "", "note": note},
        )
        return _unpack_user_result(data)

    def portal_set_password(
        self, username: str, password: str | None = None
    ) -> tuple[PortalUser, str | None]:
        data = self._require_data(
            RpcOperation.PORTAL_SET_PASSWORD, {"username": username, "password": password or ""}
        )
        return _unpack_user_result(data)

    def portal_remove_user(self, username: str) -> bool:
        return bool(self._require_data(RpcOperation.PORTAL_REMOVE_USER, {"username": username}))

    def portal_list_sessions(self) -> list[PortalSession]:
        items = self._require_list(RpcOperation.PORTAL_LIST_SESSIONS)
        return [PortalSession.model_validate(item) for item in items]

    def portal_force_logout(self, client_ip: IPv4Address) -> bool:
        return bool(
            self._require_data(RpcOperation.PORTAL_FORCE_LOGOUT, {"client_ip": str(client_ip)})
        )

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


def _unpack_user_result(data: Any) -> tuple[PortalUser, str | None]:
    """Split the `{user, generated_password}` envelope the user-mutating operations return."""
    if not isinstance(data, dict):
        raise RpcError("portal user operation did not return an object")
    payload = cast("dict[str, Any]", data)
    generated = payload.get("generated_password")
    return PortalUser.model_validate(payload.get("user")), generated if isinstance(generated, str) else None


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
