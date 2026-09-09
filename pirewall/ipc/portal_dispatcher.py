"""`PortalRpcDispatcher`: the restricted RPC surface the LAN-facing process may call.

ADDENDUM_3.md C1. `/run/pirewall/core.sock` exposes `KILL_SWITCH`,
`ADD_ALLOWLIST_ENTRY`, and every rule mutation. pirewall-portal is the
process untrusted LAN clients actually talk to, so putting it in that
socket's group would hand those operations to anything that compromises it
— a privilege escalation, and a regression against the reasoning ADDENDUM.md
A4 spent a process boundary on.

So pirewall-core serves a **second** socket with **this** dispatcher, and
pirewall-portal is a member of only that socket's group.

The restriction is structural, not a check. This class has its own
`_HANDLERS` table containing four entries; there is no handler for
`kill_switch` to reach, no branch to get wrong, and no ordering bug that
could expose one. A filtered view over `CoreRpcDispatcher` would have been
one missing `if` away from full privilege;
`test_portal_dispatcher_exposes_no_privileged_operation` asserts the
resulting surface directly.
"""

from collections.abc import Callable
from ipaddress import AddressValueError, IPv4Address
from typing import Any, ClassVar

from pirewall.ipc.portal_service import PortalLoginError, PortalService
from pirewall.ipc.protocol import RpcOperation, RpcRequest, RpcResponse

_PORTAL_OPERATIONS = frozenset(
    {
        RpcOperation.PORTAL_STATUS,
        RpcOperation.PORTAL_LOGIN,
        RpcOperation.PORTAL_KEEPALIVE,
        RpcOperation.PORTAL_LOGOUT,
    }
)


class PortalRpcDispatcher:
    """Handles only the four client-facing portal operations. Nothing else exists here."""

    def __init__(self, service: PortalService) -> None:
        self._service = service

    def handle(self, request: RpcRequest) -> RpcResponse:
        try:
            handler = self._HANDLERS.get(request.operation)
            if handler is None:
                # Deliberately the same message for "not a portal operation"
                # and "not an operation at all": the portal process has no
                # business learning which privileged operations exist.
                return RpcResponse(ok=False, error=f"unknown operation: {request.operation.value}")
            return RpcResponse(ok=True, data=handler(self, request.params))
        except PortalLoginError as exc:
            return RpcResponse(ok=False, error=str(exc))
        except _PortalParamError as exc:
            return RpcResponse(ok=False, error=str(exc))
        except Exception as exc:  # never let an unexpected error look like success or leak internals
            return RpcResponse(ok=False, error=f"internal error handling {request.operation.value}: {exc}")

    def _portal_status(self, _params: dict[str, Any]) -> dict[str, object]:
        return self._service.status()

    def _portal_login(self, params: dict[str, Any]) -> dict[str, Any]:
        session = self._service.login(
            _require_str(params, "username"),
            _require_str(params, "password"),
            _require_ip(params, "client_ip"),
        )
        return session.model_dump(mode="json")

    def _portal_keepalive(self, params: dict[str, Any]) -> dict[str, Any]:
        token = params.get("token")
        state = self._service.keepalive(
            token if isinstance(token, str) and token else None,
            _require_ip(params, "client_ip"),
        )
        return state.model_dump(mode="json")

    def _portal_logout(self, params: dict[str, Any]) -> bool:
        return self._service.logout(_require_str(params, "token"), _require_ip(params, "client_ip"))

    _HANDLERS: ClassVar[dict[RpcOperation, Callable[["PortalRpcDispatcher", dict[str, Any]], Any]]] = {
        RpcOperation.PORTAL_STATUS: _portal_status,
        RpcOperation.PORTAL_LOGIN: _portal_login,
        RpcOperation.PORTAL_KEEPALIVE: _portal_keepalive,
        RpcOperation.PORTAL_LOGOUT: _portal_logout,
    }


class _PortalParamError(Exception):
    """A malformed parameter — reportable to the caller, never a traceback."""


def _require_str(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str):
        raise _PortalParamError(f"missing or invalid required parameter: {key!r}")
    return value


def _require_ip(params: dict[str, Any], key: str) -> IPv4Address:
    """Parse a client address, rejecting anything that isn't a literal IPv4 address.

    The portal process derives `client_ip` from the peer address of the TCP
    connection, never from a header — but this parses defensively anyway,
    because an address that reached here wrong would be used to grant
    forwarding.
    """
    try:
        return IPv4Address(_require_str(params, key))
    except (AddressValueError, ValueError) as exc:
        raise _PortalParamError(f"parameter {key!r} is not a valid IPv4 address") from exc
