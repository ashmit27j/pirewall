"""`CoreRpcDispatcher`: the actual RPC operation logic (ADDENDUM.md A4).

Pure Python — no networking. `pirewall.ipc.server.UnixSocketRpcServer`
(the real transport) and `pirewall.ipc.loopback.LoopbackRpcClient`
(the test double) both just deserialize a request, call
`handle()`, and serialize the response; all the actual behavior — and all
of its test coverage — lives here.
"""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, ClassVar

from pydantic import BaseModel, ValidationError

from pirewall.config.models import PirewallConfig
from pirewall.core.enums import RuleStatus
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.status import StatusResult
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.protocol import RpcOperation, RpcRequest, RpcResponse
from pirewall.ipc.state import CoreStateStore


def _dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")


def _dump_list(models: list[BaseModel]) -> list[dict[str, Any]]:
    return [_dump(model) for model in models]


class CoreRpcDispatcher:
    """Handles every `RpcOperation` against a `CoreStateStore` + `FirewallManager`."""

    def __init__(
        self,
        state: CoreStateStore,
        manager: FirewallManager,
        config: PirewallConfig,
        now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._state = state
        self._manager = manager
        self._config = config
        self._now_fn = now_fn

    def handle(self, request: RpcRequest) -> RpcResponse:
        try:
            return self._dispatch(request)
        except _RpcError as exc:
            return RpcResponse(ok=False, error=str(exc))
        except Exception as exc:  # never let an unexpected error look like success or leak internals
            return RpcResponse(ok=False, error=f"internal error handling {request.operation.value}: {exc}")

    def _dispatch(self, request: RpcRequest) -> RpcResponse:
        handler = self._HANDLERS.get(request.operation)
        if handler is None:
            return RpcResponse(ok=False, error=f"unknown operation: {request.operation.value}")
        return RpcResponse(ok=True, data=handler(self, request.params))

    def _get_status(self, _params: dict[str, Any]) -> dict[str, Any]:
        now = self._now_fn()
        result = StatusResult(
            started_at=self._state.started_at,
            uptime_seconds=(now - self._state.started_at).total_seconds(),
            enforcement_mode=self._manager.enforcement_mode,
            failure_mode=self._config.failure.mode,
            active_rule_count=len(self._manager.active_rules()),
            pending_approval_count=sum(
                1 for rule in self._manager.all_rules() if rule.status is RuleStatus.PENDING_APPROVAL
            ),
            tracked_flow_count=len(self._state.flows),
            lightgbm_loaded=self._state.lightgbm_metadata is not None,
            isolation_forest_loaded=self._state.isolation_forest_metadata is not None,
        )
        return _dump(result)

    def _get_capture_stats(self, _params: dict[str, Any]) -> dict[str, Any] | None:
        """Current packet capture counters, or `None` before the first reading.

        `None` rather than a zeroed snapshot: pirewall-core populates this
        once the capture loop has actually run, so a `None` here honestly
        means "capture has not reported yet", not "zero packets seen".
        """
        stats = self._state.capture_stats
        return _dump(stats) if stats is not None else None

    def _list_flows(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return _dump_list(list(self._state.flows))

    def _list_detections(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return _dump_list(list(self._state.detections))

    def _list_threats(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return _dump_list(list(self._state.threats))

    def _list_decisions(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return _dump_list(list(self._state.decisions))

    def _list_rules(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return _dump_list(list(self._manager.all_rules()))

    def _list_events(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return _dump_list(list(self._state.events))

    def _list_models(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        metadata = [self._state.lightgbm_metadata, self._state.isolation_forest_metadata]
        return _dump_list([m for m in metadata if m is not None])

    def _disable_rule(self, params: dict[str, Any]) -> dict[str, Any] | None:
        rule = self._manager.disable_rule(_require_str(params, "rule_id"), self._now_fn())
        return _dump(rule) if rule is not None else None

    def _remove_rule(self, params: dict[str, Any]) -> dict[str, Any] | None:
        rule = self._manager.remove_rule(_require_str(params, "rule_id"), self._now_fn())
        return _dump(rule) if rule is not None else None

    def _approve_rule(self, params: dict[str, Any]) -> dict[str, Any] | None:
        result = self._manager.approve_pending(_require_str(params, "rule_id"), self._now_fn())
        return _dump(result.rule) if result is not None and result.rule is not None else None

    def _reject_rule(self, params: dict[str, Any]) -> dict[str, Any] | None:
        rule = self._manager.reject_pending(_require_str(params, "rule_id"), self._now_fn())
        return _dump(rule) if rule is not None else None

    def _list_allowlist(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return _dump_list(list(self._manager.allowlist))

    def _add_allowlist_entry(self, params: dict[str, Any]) -> dict[str, Any]:
        try:
            entry = AllowlistEntry.model_validate(params)
        except ValidationError as exc:
            raise _RpcError(f"invalid allowlist entry: {exc}") from exc
        self._manager.add_allowlist_entry(entry)
        return _dump(entry)

    def _remove_allowlist_entry(self, params: dict[str, Any]) -> bool:
        return self._manager.remove_allowlist_entry(_require_str(params, "entry_id"))

    def _kill_switch(self, _params: dict[str, Any]) -> dict[str, Any]:
        event = self._manager.revert_to_base(self._now_fn())
        return _dump(event)

    def _record_event(self, params: dict[str, Any]) -> dict[str, Any]:
        """Let pirewall-api report events (e.g. AUTHENTICATION_FAILURE) into the shared audit trail.

        pirewall-api owns no state of its own (ADDENDUM.md A4) — even its
        own authentication failures have to be recorded here, in
        pirewall-core's `CoreStateStore`, to show up in `/events`.
        """
        try:
            event = SecurityEvent.model_validate(params)
        except ValidationError as exc:
            raise _RpcError(f"invalid security event: {exc}") from exc
        self._state.record_event(event)
        return _dump(event)

    _HANDLERS: ClassVar[dict[RpcOperation, Callable[["CoreRpcDispatcher", dict[str, Any]], Any]]] = {
        RpcOperation.GET_STATUS: _get_status,
        RpcOperation.GET_CAPTURE_STATS: _get_capture_stats,
        RpcOperation.LIST_FLOWS: _list_flows,
        RpcOperation.LIST_DETECTIONS: _list_detections,
        RpcOperation.LIST_THREATS: _list_threats,
        RpcOperation.LIST_DECISIONS: _list_decisions,
        RpcOperation.LIST_RULES: _list_rules,
        RpcOperation.LIST_EVENTS: _list_events,
        RpcOperation.LIST_MODELS: _list_models,
        RpcOperation.DISABLE_RULE: _disable_rule,
        RpcOperation.REMOVE_RULE: _remove_rule,
        RpcOperation.APPROVE_RULE: _approve_rule,
        RpcOperation.REJECT_RULE: _reject_rule,
        RpcOperation.LIST_ALLOWLIST: _list_allowlist,
        RpcOperation.ADD_ALLOWLIST_ENTRY: _add_allowlist_entry,
        RpcOperation.REMOVE_ALLOWLIST_ENTRY: _remove_allowlist_entry,
        RpcOperation.KILL_SWITCH: _kill_switch,
        RpcOperation.RECORD_EVENT: _record_event,
    }


class _RpcError(Exception):
    """Raised by a handler for an expected, user-facing failure (bad params, not found)."""


def _require_str(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str):
        raise _RpcError(f"missing or invalid required parameter: {key!r}")
    return value
