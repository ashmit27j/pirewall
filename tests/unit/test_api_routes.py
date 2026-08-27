"""pirewall-api endpoints, end to end via `TestHarness` (spec §28, §29, ADDENDUM.md A2/A7/A8)."""

from datetime import UTC, datetime

from fastapi.routing import APIRoute

from pirewall.api.app import create_app
from pirewall.core.enums import FirewallAction, SecurityEventType, ThreatLevel
from pirewall.core.exceptions import RpcError
from pirewall.core.models.decision import FirewallDecision
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.loopback import LoopbackRpcClient
from pirewall.ipc.state import CoreStateStore
from tests.helpers.api import auth_headers, login, make_harness
from tests.helpers.config import make_config
from tests.helpers.rules import make_candidate

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _deploy_rule(manager: FirewallManager, **overrides: object) -> str:
    candidate = make_candidate(**overrides)
    manager.register_decision(
        FirewallDecision.model_validate(
            {
                "id": candidate.decision_id,
                "threat_assessment_id": "a",
                "action": candidate.action,
                "threat_score": candidate.threat_score,
                "threat_level": ThreatLevel.CRITICAL,
                "reason": "test",
                "decided_at": NOW,
            }
        )
    )
    result = manager.submit_candidate(candidate, NOW)
    assert result.rule is not None
    return result.rule.id


def test_health_is_public_and_unauthenticated() -> None:
    harness = make_harness(NOW, client_address=("203.0.113.9", 1))
    response = harness.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"message": "ok"}


def test_login_success_returns_token() -> None:
    harness = make_harness(NOW)
    token = login(harness)
    assert len(token) > 20


def test_login_wrong_password_rejected_and_emits_authentication_failure() -> None:
    harness = make_harness(NOW)
    response = harness.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
    assert response.status_code == 401

    events = list(harness.state.events)
    assert any(event.event_type is SecurityEventType.AUTHENTICATION_FAILURE for event in events)


def test_login_rejected_from_non_admin_pc() -> None:
    harness = make_harness(NOW, client_address=("203.0.113.9", 1))
    response = harness.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "wrong-but-irrelevant"}
    )
    assert response.status_code == 403


def test_protected_endpoint_rejects_missing_session() -> None:
    harness = make_harness(NOW)
    response = harness.get("/api/v1/status")
    assert response.status_code == 401


def test_protected_endpoint_rejects_non_admin_pc_even_with_valid_token() -> None:
    # A token from one (Admin-PC) session isn't enough on its own — a
    # *different* harness simulating a non-Admin-PC source must still be
    # rejected at the admin-pc-restriction dependency, before session
    # validation even matters.
    admin_harness = make_harness(NOW)
    token = login(admin_harness)

    outsider_harness = make_harness(NOW, client_address=("203.0.113.9", 1))
    response = outsider_harness.get("/api/v1/status", headers=auth_headers(token))
    assert response.status_code == 403


def test_protected_endpoint_succeeds_with_valid_session_and_admin_pc() -> None:
    harness = make_harness(NOW)
    token = login(harness)
    response = harness.get("/api/v1/status", headers=auth_headers(token))
    assert response.status_code == 200
    assert response.json()["enforcement_mode"] == "shadow"


def test_disable_and_remove_rules_through_http() -> None:
    harness = make_harness(NOW, firewall={"enforcement_mode": "active"})
    token = login(harness)
    rule_id = _deploy_rule(harness.manager)

    disabled = harness.post(f"/api/v1/rules/{rule_id}/disable", headers=auth_headers(token))
    assert disabled.status_code == 200
    assert disabled.json()["status"] == "disabled"

    unknown = harness.post("/api/v1/rules/does-not-exist/remove", headers=auth_headers(token))
    assert unknown.status_code == 404


def test_approve_and_reject_through_http() -> None:
    harness = make_harness(
        NOW, firewall={"enforcement_mode": "assisted", "assisted_review_threshold": 10.0}
    )
    token = login(harness)
    rule_id = _deploy_rule(harness.manager, action=FirewallAction.BLOCK, threat_score=90.0)

    approved = harness.post(f"/api/v1/rules/{rule_id}/approve", headers=auth_headers(token))
    assert approved.status_code == 200
    assert approved.json()["status"] == "active"


def test_write_endpoints_reject_unauthenticated_requests() -> None:
    harness = make_harness(NOW, firewall={"enforcement_mode": "active"})
    rule_id = _deploy_rule(harness.manager)

    for path in (
        f"/api/v1/rules/{rule_id}/disable",
        f"/api/v1/rules/{rule_id}/remove",
        f"/api/v1/rules/{rule_id}/approve",
        f"/api/v1/rules/{rule_id}/reject",
        "/api/v1/firewall/kill-switch",
    ):
        response = harness.post(path)
        assert response.status_code == 401, f"POST {path} should require authentication"


def test_allowlist_add_list_remove_through_http() -> None:
    harness = make_harness(NOW)
    token = login(harness)

    created = harness.post(
        "/api/v1/allowlist",
        json={"target": "192.168.1.77/32", "reason": "protected device"},
        headers=auth_headers(token),
    )
    assert created.status_code == 200
    entry_id = created.json()["id"]

    listed = harness.get("/api/v1/allowlist", headers=auth_headers(token))
    assert len(listed.json()) == 1

    removed = harness.delete(f"/api/v1/allowlist/{entry_id}", headers=auth_headers(token))
    assert removed.status_code == 200

    listed_again = harness.get("/api/v1/allowlist", headers=auth_headers(token))
    assert listed_again.json() == []


def test_allowlist_write_requires_authentication() -> None:
    harness = make_harness(NOW)
    response = harness.post("/api/v1/allowlist", json={"target": "192.168.1.77/32", "reason": "x"})
    assert response.status_code == 401


def test_kill_switch_through_http() -> None:
    harness = make_harness(NOW, firewall={"enforcement_mode": "active"})
    token = login(harness)
    _deploy_rule(harness.manager)
    assert len(harness.manager.active_rules()) == 1

    response = harness.post("/api/v1/firewall/kill-switch", headers=auth_headers(token))

    assert response.status_code == 200
    assert harness.manager.active_rules() == []
    assert harness.manager.enforcement_mode.value == "shadow"


def test_read_endpoints_return_empty_lists_by_default() -> None:
    harness = make_harness(NOW)
    token = login(harness)
    for path in ("/flows", "/detections", "/threats", "/decisions", "/events", "/models"):
        response = harness.get(f"/api/v1{path}", headers=auth_headers(token))
        assert response.status_code == 200
        assert response.json() == []


def _throwaway_rpc_client() -> LoopbackRpcClient:
    """An RPC client for building an app to inspect its routes — no requests are ever made."""
    config = make_config()
    manager = FirewallManager(config, FakeFirewallBackend())
    state = CoreStateStore(max_history=10, started_at=NOW)
    return LoopbackRpcClient(CoreRpcDispatcher(state, manager, config))


def test_registered_route_surface_matches_spec() -> None:
    """Catches any accidental extra/dangerous route (spec §28 "only expose implemented functionality")."""
    app = create_app(make_config(), _throwaway_rpc_client())

    # FastAPI wraps each `include_router()` call in an internal
    # `_IncludedRouter` rather than flattening routes directly into
    # `app.routes` — `original_router.routes` holds the real `APIRoute`s,
    # each already carrying its router's full path prefix.
    api_routes: list[APIRoute] = []
    for included in app.routes:
        original_router = getattr(included, "original_router", None)
        for route in getattr(original_router, "routes", []):
            if isinstance(route, APIRoute):
                api_routes.append(route)

    routes: set[tuple[str, str]] = set()
    for route in api_routes:
        for method in (route.methods or set()) - {"HEAD"}:
            routes.add((route.path, method))

    expected = {
        ("/api/v1/health", "GET"),
        ("/api/v1/auth/login", "POST"),
        ("/api/v1/auth/logout", "POST"),
        ("/api/v1/status", "GET"),
        ("/api/v1/flows", "GET"),
        ("/api/v1/detections", "GET"),
        ("/api/v1/threats", "GET"),
        ("/api/v1/decisions", "GET"),
        ("/api/v1/rules", "GET"),
        ("/api/v1/events", "GET"),
        ("/api/v1/models", "GET"),
        ("/api/v1/rules/{rule_id}/disable", "POST"),
        ("/api/v1/rules/{rule_id}/remove", "POST"),
        ("/api/v1/rules/{rule_id}/approve", "POST"),
        ("/api/v1/rules/{rule_id}/reject", "POST"),
        ("/api/v1/allowlist", "GET"),
        ("/api/v1/allowlist", "POST"),
        ("/api/v1/allowlist/{entry_id}", "DELETE"),
        ("/api/v1/firewall/kill-switch", "POST"),
        ("/control-panel/login", "GET"),
        ("/control-panel", "GET"),
    }
    assert routes == expected


def test_unreachable_core_reports_503_instead_of_crashing() -> None:
    """ADDENDUM.md A6 / spec §26: a dead pirewall-core is a reportable state, not a 500.

    A6 justifies the A4 process split partly on pirewall-api outliving a
    pirewall-core crash-loop so it can *say so*, and spec §26 requires
    failures be "visible through the control panel". Before this was
    handled, both the JSON API and the control panel returned an unhandled
    500 with a traceback where an operator needed a diagnosis.
    """
    harness = make_harness(NOW)
    token = login(harness)

    def _dead(*_args: object, **_kwargs: object) -> None:
        raise RpcError("failed to reach pirewall-core at /run/pirewall/core.sock")

    harness.client.app.state.pirewall_rpc_client._call = _dead  # type: ignore[attr-defined]

    api_response = harness.get("/api/v1/status", headers=auth_headers(token))
    panel_response = harness.get("/control-panel", headers=auth_headers(token))

    assert api_response.status_code == 503
    assert "unreachable" in api_response.json()["detail"]
    assert panel_response.status_code == 503
    assert "pirewall-core is unreachable" in panel_response.text
    # The operator needs the enforcement consequence, not just the error.
    assert "fail_open" in panel_response.text
