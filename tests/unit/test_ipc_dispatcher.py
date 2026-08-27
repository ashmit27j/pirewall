"""`CoreRpcDispatcher` via `LoopbackRpcClient`: every operation, end to end in-process (ADDENDUM.md A4)."""

from datetime import UTC, datetime

from pirewall.core.enums import EnforcementMode, FirewallAction, RuleStatus, ThreatLevel
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.decision import FirewallDecision
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.loopback import LoopbackRpcClient
from pirewall.ipc.protocol import RpcOperation, RpcRequest
from pirewall.ipc.state import CoreStateStore
from tests.helpers.config import make_config
from tests.helpers.rules import make_candidate

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _client(
    **config_overrides: dict[str, object],
) -> tuple[LoopbackRpcClient, FirewallManager, FakeFirewallBackend]:
    config = make_config(**config_overrides)
    backend = FakeFirewallBackend()
    manager = FirewallManager(config, backend)
    state = CoreStateStore(max_history=10, started_at=NOW)
    dispatcher = CoreRpcDispatcher(state, manager, config, now_fn=lambda: NOW)
    return LoopbackRpcClient(dispatcher), manager, backend


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


def test_get_status_reflects_manager_state() -> None:
    client, manager, _backend = _client(firewall={"enforcement_mode": "active"})
    _deploy_rule(manager)

    status = client.get_status()

    assert status.enforcement_mode is EnforcementMode.ACTIVE
    assert status.active_rule_count == 1
    assert status.started_at == NOW


def test_list_rules_returns_all_statuses() -> None:
    client, manager, _backend = _client(firewall={"enforcement_mode": "active"})
    _deploy_rule(manager)

    rules = client.list_rules()

    assert len(rules) == 1
    assert rules[0].status is RuleStatus.ACTIVE


def test_disable_rule_through_rpc() -> None:
    client, manager, backend = _client(firewall={"enforcement_mode": "active"})
    rule_id = _deploy_rule(manager)

    disabled = client.disable_rule(rule_id)

    assert disabled is not None
    assert disabled.status is RuleStatus.DISABLED
    assert rule_id not in backend.list_active_rule_ids()


def test_disable_unknown_rule_returns_none() -> None:
    client, _manager, _backend = _client()
    assert client.disable_rule("does-not-exist") is None


def test_remove_rule_through_rpc() -> None:
    client, manager, backend = _client(firewall={"enforcement_mode": "active"})
    rule_id = _deploy_rule(manager)

    removed = client.remove_rule(rule_id)

    assert removed is not None
    assert removed.status is RuleStatus.REMOVED
    assert rule_id not in backend.list_active_rule_ids()


def test_approve_and_reject_pending_through_rpc() -> None:
    client, manager, backend = _client(
        firewall={"enforcement_mode": "assisted", "assisted_review_threshold": 10.0}
    )
    rule_id = _deploy_rule(manager, action=FirewallAction.BLOCK, threat_score=90.0)

    approved = client.approve_rule(rule_id)
    assert approved is not None
    assert approved.status is RuleStatus.ACTIVE
    assert rule_id in backend.list_active_rule_ids()

    # a second, freshly pending rule (different target, to avoid duplicate detection) to test rejection
    rule_id_2 = _deploy_rule(
        manager,
        decision_id="decision-2",
        action=FirewallAction.BLOCK,
        threat_score=90.0,
        destination="192.168.1.20/32",
    )
    rejected = client.reject_rule(rule_id_2)
    assert rejected is not None
    assert rejected.status is RuleStatus.REJECTED


def test_allowlist_add_list_remove_through_rpc() -> None:
    client, _manager, _backend = _client()
    entry = AllowlistEntry.model_validate(
        {"target": "192.168.1.77/32", "reason": "test", "created_by": "admin", "created_at": NOW.isoformat()}
    )

    added = client.add_allowlist_entry(entry)
    assert added.id == entry.id
    assert len(client.list_allowlist()) == 1

    assert client.remove_allowlist_entry(entry.id) is True
    assert client.list_allowlist() == []
    assert client.remove_allowlist_entry(entry.id) is False


def test_kill_switch_through_rpc() -> None:
    client, manager, backend = _client(firewall={"enforcement_mode": "active"})
    _deploy_rule(manager)

    event = client.kill_switch()

    assert "kill-switch" in (event.reason or "").lower()
    assert manager.enforcement_mode is EnforcementMode.SHADOW
    assert backend.list_active_rule_ids() == frozenset()


def test_list_events_and_models_are_empty_but_well_typed_by_default() -> None:
    client, _manager, _backend = _client()
    assert client.list_events() == []
    assert client.list_models() == []
    assert client.list_flows() == []
    assert client.list_detections() == []
    assert client.list_threats() == []
    assert client.list_decisions() == []


def test_dispatcher_returns_error_response_for_missing_required_param() -> None:
    config = make_config()
    manager = FirewallManager(config, FakeFirewallBackend())
    state = CoreStateStore(max_history=10, started_at=NOW)
    dispatcher = CoreRpcDispatcher(state, manager, config, now_fn=lambda: NOW)

    response = dispatcher.handle(RpcRequest(operation=RpcOperation.DISABLE_RULE, params={}))

    assert response.ok is False
    assert response.error is not None


def test_dispatcher_never_raises_on_malformed_allowlist_params() -> None:
    config = make_config()
    manager = FirewallManager(config, FakeFirewallBackend())
    state = CoreStateStore(max_history=10, started_at=NOW)
    dispatcher = CoreRpcDispatcher(state, manager, config, now_fn=lambda: NOW)

    response = dispatcher.handle(
        RpcRequest(operation=RpcOperation.ADD_ALLOWLIST_ENTRY, params={"target": "not-a-network"})
    )

    assert response.ok is False
    assert response.error is not None
