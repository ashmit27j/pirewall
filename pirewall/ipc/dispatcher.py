"""`CoreRpcDispatcher`: the actual RPC operation logic (ADDENDUM.md A4).

Pure Python — no networking. `pirewall.ipc.server.UnixSocketRpcServer`
(the real transport) and `pirewall.ipc.loopback.LoopbackRpcClient`
(the test double) both just deserialize a request, call
`handle()`, and serialize the response; all the actual behavior — and all
of its test coverage — lives here.

The six v2 operations (docs/V2_CONTRACTS.md §9) live here too. The four
reads come from `V2Snapshots` and are listed in `LOCK_FREE_OPERATIONS`, so
core's synchronising wrapper serves them without its RPC lock.
`set_guard_mode` and `panic` write through `FirewallManager` like every
other mutation, and every call of either is an audit event.
"""

from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import AddressValueError, IPv4Address
from typing import Any, ClassVar

from pydantic import BaseModel, ValidationError

from pirewall.config.models import PirewallConfig
from pirewall.core.enums import GuardMode, GuardName, RuleStatus
from pirewall.core.exceptions import FirewallError
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.status import StatusResult
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.portal_service import PortalService
from pirewall.ipc.protocol import RpcOperation, RpcRequest, RpcResponse
from pirewall.ipc.snapshots import V2Snapshots
from pirewall.ipc.state import CoreStateStore

EventSink = Callable[[SecurityEvent], None]


def _dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")


def _dump_list(models: list[BaseModel]) -> list[dict[str, Any]]:
    return [_dump(model) for model in models]


class CoreRpcDispatcher:
    """Handles every `RpcOperation` against a `CoreStateStore` + `FirewallManager`."""

    # Served from `V2Snapshots`, never under core's RPC lock (V2_CONTRACTS §9).
    LOCK_FREE_OPERATIONS: ClassVar[frozenset[RpcOperation]] = frozenset(
        {
            RpcOperation.GET_GUARD_MODES,
            RpcOperation.LIST_OFFENDERS,
            RpcOperation.LIST_BINDINGS,
            RpcOperation.GET_ENGINE_STATS,
        }
    )

    def __init__(
        self,
        state: CoreStateStore,
        manager: FirewallManager,
        config: PirewallConfig,
        now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
        portal: PortalService | None = None,
        snapshots: V2Snapshots | None = None,
        on_event: EventSink | None = None,
    ) -> None:
        """`on_event` is core's `EventForwarder`: the audit trail *and* Wazuh.

        Without one, events go to `state` only, as before phase 16. That was
        why no API-reported event (a failed login, an allowlist addition)
        ever reached Wazuh. `snapshots` serves the v2 reads; without it they
        report that v2 status is unavailable.
        """
        self._state = state
        self._manager = manager
        self._config = config
        self._now_fn = now_fn
        # `None` when `portal.enabled` is false. The admin-side portal
        # operations then report that plainly instead of half-working.
        self._portal = portal
        self._snapshots = snapshots
        self._emit: EventSink = on_event if on_event is not None else state.record_event

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
        """Add an allowlist entry, optionally provisioning a portal account alongside it.

        ADDENDUM_3.md C3: an allowlist entry is a CIDR and a portal account
        is a credential, so the mapping is not one-to-one — a gateway or a
        printer belongs on the allowlist and can never log in. The username
        is therefore optional. When supplied, the account is created with a
        generated password returned **once**, in this response, for the
        control panel to show the admin; it is never stored in the clear
        and never appears in an event or a log line.
        """
        # Copy rather than pop: the caller owns `params`, and
        # `AllowlistEntry` forbids extra fields, so the username has to
        # come out before validation.
        portal_username = params.get("portal_username")
        entry_fields = {key: value for key, value in params.items() if key != "portal_username"}
        try:
            entry = AllowlistEntry.model_validate(entry_fields)
        except ValidationError as exc:
            raise _RpcError(f"invalid allowlist entry: {exc}") from exc
        self._manager.add_allowlist_entry(entry)
        payload = _dump(entry)
        if isinstance(portal_username, str) and portal_username.strip():
            if self._portal is None:
                raise _RpcError("cannot provision a portal user: the captive portal is disabled")
            _user, generated = self._portal.add_user(
                username=portal_username.strip(),
                password=None,
                created_by=entry.created_by,
                note=f"provisioned with allowlist entry {entry.target}",
            )
            payload["portal_username"] = portal_username.strip()
            payload["portal_password"] = generated
        return payload

    def _remove_allowlist_entry(self, params: dict[str, Any]) -> bool:
        return self._manager.remove_allowlist_entry(_require_str(params, "entry_id"))

    def _kill_switch(self, _params: dict[str, Any]) -> dict[str, Any]:
        event = self._manager.revert_to_base(self._now_fn())
        # D5 step 4: the kill switch writes an audit entry (and reaches Wazuh).
        self._emit(event)
        return _dump(event)

    def _portal_list_users(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return _dump_list(list(self._require_portal().list_users()))

    def _portal_add_user(self, params: dict[str, Any]) -> dict[str, Any]:
        password = params.get("password")
        user, generated = self._require_portal().add_user(
            username=_require_str(params, "username"),
            password=password if isinstance(password, str) and password else None,
            created_by=_require_str(params, "created_by"),
            note=_optional_str(params, "note"),
        )
        return {"user": _dump(user), "generated_password": generated}

    def _portal_set_password(self, params: dict[str, Any]) -> dict[str, Any]:
        password = params.get("password")
        user, generated = self._require_portal().set_password(
            _require_str(params, "username"),
            password if isinstance(password, str) and password else None,
        )
        return {"user": _dump(user), "generated_password": generated}

    def _portal_remove_user(self, params: dict[str, Any]) -> bool:
        return self._require_portal().remove_user(_require_str(params, "username"))

    def _portal_list_sessions(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return _dump_list(list(self._require_portal().list_sessions()))

    def _portal_force_logout(self, params: dict[str, Any]) -> bool:
        raw = _require_str(params, "client_ip")
        try:
            client_ip = IPv4Address(raw)
        except (AddressValueError, ValueError) as exc:
            raise _RpcError(f"invalid client_ip: {raw!r}") from exc
        return self._require_portal().force_logout(client_ip)

    def _require_portal(self) -> PortalService:
        if self._portal is None:
            raise _RpcError("the captive portal is disabled (set portal.enabled in the config)")
        return self._portal

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
        self._emit(event)
        return _dump(event)

    # --- v2 (docs/V2_CONTRACTS.md §9) ---------------------------------------

    def _get_guard_modes(self, _params: dict[str, Any]) -> dict[str, Any]:
        snapshots = self._require_snapshots()
        modes = snapshots.guard_modes
        if modes is None:
            raise _RpcError(f"guard modes unavailable: {snapshots.guard_modes_error}")
        return _dump(modes)

    def _set_guard_mode(self, params: dict[str, Any]) -> dict[str, Any]:
        """Flip one guard through `FirewallManager` (D1's single static write), audited.

        Re-authentication for ENFORCE happens in pirewall-api before this is
        called; core audits every flip whoever asked.
        """
        guard = _require_enum(params, "guard", GuardName)
        mode = _require_enum(params, "mode", GuardMode)
        actor = _require_actor(params)
        now = self._now_fn()
        try:
            event = self._manager.set_guard_mode(guard, mode, actor, now)
            modes = self._manager.guard_modes(now)
        except FirewallError as exc:
            raise _RpcError(f"set_guard_mode failed: {exc}") from exc
        self._emit(event)
        if self._snapshots is not None:
            self._snapshots.publish_guard_modes(modes)
        return _dump(modes)

    def _panic(self, params: dict[str, Any]) -> dict[str, Any]:
        """Delete the v2 tables (ADDENDUM_4.md D5), audited at CRITICAL. Restore is `pirewall-start`."""
        actor = _require_actor(params)
        try:
            result, event = self._manager.panic(actor, self._now_fn())
        except FirewallError as exc:
            raise _RpcError(f"panic failed: {exc}") from exc
        self._emit(event)
        if self._snapshots is not None:
            self._snapshots.publish_guard_modes(None, f"pirewall_static was deleted by panic ({actor})")
        return _dump(result)

    def _list_offenders(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return _dump_list(list(self._require_snapshots().offenders))

    def _list_bindings(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return _dump_list(list(self._require_snapshots().bindings()))

    def _get_engine_stats(self, _params: dict[str, Any]) -> dict[str, Any]:
        stats = self._require_snapshots().engine_stats
        if stats is None:
            raise _RpcError("engine statistics have not been published yet")
        return _dump(stats)

    def _require_snapshots(self) -> V2Snapshots:
        if self._snapshots is None:
            raise _RpcError("v2 status is not available in this pirewall-core")
        return self._snapshots

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
        RpcOperation.PORTAL_LIST_USERS: _portal_list_users,
        RpcOperation.PORTAL_ADD_USER: _portal_add_user,
        RpcOperation.PORTAL_SET_PASSWORD: _portal_set_password,
        RpcOperation.PORTAL_REMOVE_USER: _portal_remove_user,
        RpcOperation.PORTAL_LIST_SESSIONS: _portal_list_sessions,
        RpcOperation.PORTAL_FORCE_LOGOUT: _portal_force_logout,
        RpcOperation.GET_GUARD_MODES: _get_guard_modes,
        RpcOperation.SET_GUARD_MODE: _set_guard_mode,
        RpcOperation.PANIC: _panic,
        RpcOperation.LIST_OFFENDERS: _list_offenders,
        RpcOperation.LIST_BINDINGS: _list_bindings,
        RpcOperation.GET_ENGINE_STATS: _get_engine_stats,
    }


class _RpcError(Exception):
    """Raised by a handler for an expected, user-facing failure (bad params, not found)."""


def _require_enum[E: GuardName | GuardMode](params: dict[str, Any], key: str, enum: type[E]) -> E:
    """A required parameter that must be one of `enum`'s values."""
    raw = _require_str(params, key)
    try:
        return enum(raw)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in enum)
        raise _RpcError(f"invalid {key} {raw!r}: expected one of {allowed}") from exc


def _require_actor(params: dict[str, Any]) -> str:
    """The authenticated admin username pirewall-api passes for the audit entry."""
    actor = _require_str(params, "actor").strip()
    if not actor:
        raise _RpcError("missing or invalid required parameter: 'actor'")
    return actor


def _optional_str(params: dict[str, Any], key: str) -> str:
    """A string parameter that may be absent, empty, or the wrong type — all read as empty."""
    value = params.get(key)
    return value if isinstance(value, str) else ""


def _require_str(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str):
        raise _RpcError(f"missing or invalid required parameter: {key!r}")
    return value
