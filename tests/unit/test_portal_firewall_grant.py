"""`FirewallManager`'s portal grant, and the nftables backend's set commands.

ADDENDUM_3.md C2: a portal grant is an nft set element, not a `FirewallRule`.
It is still routed through `FirewallManager` because that class holds the
only reference to a `FirewallBackend` (CLAUDE.md, "exactly one authorized
code path may deploy to the firewall backend").
"""

import json
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import Any

import pytest

from pirewall.core.enums import EnforcementMode, FirewallAction, RuleStatus, ThreatLevel
from pirewall.core.exceptions import FirewallError
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.rule import FirewallRule
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.nftables import NftablesBackend
from pirewall.firewall.interface import FirewallBackend
from pirewall.firewall.manager import FirewallManager, rules_targeting
from tests.helpers.config import make_config
from tests.helpers.rules import make_candidate, make_firewall_rule

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def manager() -> FirewallManager:
    """A manager in ACTIVE enforcement, so submitted candidates really deploy."""
    config = make_config()
    config = config.model_copy(
        update={"firewall": config.firewall.model_copy(
            update={"enforcement_mode": EnforcementMode.ACTIVE, "min_rule_prefix_length": 0}
        )}
    )
    return FirewallManager(config, FakeFirewallBackend())

def _deploy(
    manager: FirewallManager, source: str, destination: str, action: FirewallAction, reason: str
) -> FirewallRule:
    """Deploy a rule through the real validated path, not by writing to `_rules`.

    Going through `register_decision` + `submit_candidate` means these tests
    exercise the same lifecycle the detection pipeline uses, so a rule that
    the validation chain would have rejected cannot silently become an
    ACTIVE rule here and make the portal's block detection look correct
    against state it would never really see.
    """
    candidate = make_candidate(
        action=action,
        source=source,
        destination=destination,
        reason=reason,
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    manager.register_decision(
        FirewallDecision(
            id=candidate.decision_id,
            threat_assessment_id="assessment-1",
            flow_id="flow-1",
            action=candidate.action,
            threat_score=candidate.threat_score or 0.0,
            threat_level=ThreatLevel.CRITICAL,
            reason=candidate.reason,
            decided_at=NOW,
        )
    )
    result = manager.submit_candidate(candidate, NOW)
    assert result.rule is not None, "the candidate should have deployed"
    assert result.rule.status is RuleStatus.ACTIVE, result.rule.status
    return result.rule




PROTECTED = make_config().network.protected_network
# A plausible remote peer: outside the protected network, so it is never
# mistaken for a LAN client by `rules_targeting`.
REMOTE = "203.0.113.9/32"


def _lan_client(index: int = 9) -> IPv4Address:
    return list(PROTECTED.hosts())[index]


def test_authorizing_and_deauthorizing_a_lan_client(manager: FirewallManager) -> None:
    client = _lan_client()
    manager.authorize_portal_client(client, 1800)
    assert manager.authorized_portal_clients() == frozenset({client})
    manager.deauthorize_portal_client(client)
    assert manager.authorized_portal_clients() == frozenset()


def test_deauthorizing_an_unknown_client_is_not_an_error(manager: FirewallManager) -> None:
    """The kernel may have expired the element a moment ago; that is the common case."""
    manager.deauthorize_portal_client(_lan_client())


@pytest.mark.parametrize("address", ["8.8.8.8", "203.0.113.9", "10.0.0.1"])
def test_an_address_outside_the_protected_network_is_refused(
    manager: FirewallManager, address: str
) -> None:
    """A portal grant only ever means "this LAN client signed in"."""
    with pytest.raises(FirewallError, match="not inside the protected network"):
        manager.authorize_portal_client(IPv4Address(address), 1800)


def test_a_portal_grant_creates_no_rule_and_no_lifecycle_transition(manager: FirewallManager) -> None:
    """C2: portal elements stay out of the `RuleStatus` lifecycle entirely."""
    manager.authorize_portal_client(_lan_client(), 1800)
    assert manager.all_rules() == []
    assert manager.transitions == ()


def test_a_portal_grant_does_not_consume_the_a3_rate_cap(manager: FirewallManager) -> None:
    """It is an admin-vouched grant, not an ML-driven restriction."""
    for index in range(30):
        manager.authorize_portal_client(_lan_client(index), 1800)
    assert manager.adaptive_rules_in_window(NOW) == 0


def test_an_unreachable_backend_reports_no_clients_rather_than_raising() -> None:
    """Fail-open (ADDENDUM.md A6): "who is online" must always have an answer."""

    class _Broken(FakeFirewallBackend):
        def list_portal_clients(self) -> frozenset[IPv4Address]:
            raise FirewallError("backend down")

    manager = FirewallManager(make_config(), _Broken())
    assert manager.authorized_portal_clients() == frozenset()


# ------------------------------------------- finding the rules that block a client


def test_restrictive_rules_matching_finds_a_block_on_the_source(manager: FirewallManager) -> None:
    client = _lan_client()
    rule = _deploy(manager, f"{client}/32", REMOTE, FirewallAction.BLOCK, "port scan detected")
    assert [found.id for found in manager.restrictive_rules_matching(client)] == [rule.id]


def test_restrictive_rules_matching_finds_a_block_on_the_destination(manager: FirewallManager) -> None:
    client = _lan_client()
    rule = _deploy(manager, REMOTE, f"{client}/32", FirewallAction.BLOCK, "inbound probe")
    assert [found.id for found in manager.restrictive_rules_matching(client)] == [rule.id]


def test_a_rate_limit_also_counts_as_restrictive(manager: FirewallManager) -> None:
    client = _lan_client()
    _deploy(manager, f"{client}/32", REMOTE, FirewallAction.RATE_LIMIT, "flooding")
    assert len(manager.restrictive_rules_matching(client)) == 1


def _manager_in(mode: EnforcementMode) -> FirewallManager:
    config = make_config()
    config = config.model_copy(
        update={
            "firewall": config.firewall.model_copy(
                update={
                    "enforcement_mode": mode,
                    "min_rule_prefix_length": 0,
                    "assisted_review_threshold": 50.0,
                }
            )
        }
    )
    return FirewallManager(config, FakeFirewallBackend())


def _submit(manager: FirewallManager, client: IPv4Address) -> None:
    candidate = make_candidate(
        action=FirewallAction.BLOCK,
        source=f"{client}/32",
        destination=REMOTE,
        threat_score=95.0,
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    manager.register_decision(
        FirewallDecision(
            id=candidate.decision_id,
            threat_assessment_id="assessment-1",
            flow_id="flow-1",
            action=candidate.action,
            threat_score=95.0,
            threat_level=ThreatLevel.CRITICAL,
            reason=candidate.reason,
            decided_at=NOW,
        )
    )
    manager.submit_candidate(candidate, NOW)


def test_a_shadowed_rule_does_not_block_anyone() -> None:
    """SHADOW mode never touched the backend, so telling a client it did would be a lie (A1)."""
    manager = _manager_in(EnforcementMode.SHADOW)
    client = _lan_client()
    _submit(manager, client)
    assert any(rule.status is RuleStatus.SHADOWED for rule in manager.all_rules())
    assert manager.restrictive_rules_matching(client) == []


def test_a_rule_awaiting_approval_does_not_block_anyone() -> None:
    """A7: a pending BLOCK has not been deployed, so the client is not actually blocked."""
    manager = _manager_in(EnforcementMode.ASSISTED)
    client = _lan_client()
    _submit(manager, client)
    assert any(rule.status is RuleStatus.PENDING_APPROVAL for rule in manager.all_rules())
    assert manager.restrictive_rules_matching(client) == []


def test_a_removed_rule_stops_blocking() -> None:
    """Once an admin removes the rule the client must stop being told it is blocked."""
    manager = _manager_in(EnforcementMode.ACTIVE)
    client = _lan_client()
    rule = _deploy(manager, f"{client}/32", REMOTE, FirewallAction.BLOCK, "port scan")
    assert len(manager.restrictive_rules_matching(client)) == 1
    manager.remove_rule(rule.id, NOW)
    assert manager.restrictive_rules_matching(client) == []


def test_a_rule_against_a_different_client_is_not_reported(manager: FirewallManager) -> None:
    _deploy(manager, f"{_lan_client(20)}/32", REMOTE, FirewallAction.BLOCK, "port scan")
    assert manager.restrictive_rules_matching(_lan_client(9)) == []


# ------------------------------------------------- the real backend's JSON


def test_the_nftables_backend_satisfies_the_extended_protocol() -> None:
    assert isinstance(NftablesBackend(rate_limit_per_second=10), FirewallBackend)


def test_the_fake_backend_satisfies_the_extended_protocol() -> None:
    assert isinstance(FakeFirewallBackend(), FirewallBackend)


def test_authorize_builds_a_json_element_with_a_kernel_timeout(monkeypatch: Any) -> None:
    """Structured JSON to `nft -j`, never an interpolated command string (spec §20)."""
    captured: dict[str, Any] = {}

    def _fake_run(self: NftablesBackend, args: list[str], stdin_json: Any = None) -> str:
        captured["args"] = args
        captured["payload"] = stdin_json
        return "{}"

    monkeypatch.setattr(NftablesBackend, "_run_command", _fake_run)
    NftablesBackend(rate_limit_per_second=10).authorize_portal_client(IPv4Address("192.168.100.50"), 1800)

    assert captured["args"] == ["-j", "-f", "-"]
    element = captured["payload"]["nftables"][0]["add"]["element"]
    assert element["table"] == "pirewall_portal"
    assert element["name"] == "authed"
    assert element["elem"] == [{"elem": {"val": "192.168.100.50", "timeout": 1800}}]
    # It must survive JSON serialization — this is what is fed to nft's stdin.
    json.dumps(captured["payload"])


def test_a_non_positive_timeout_is_refused() -> None:
    """A zero or negative timeout would mean "never expires", which is not a session."""
    backend = NftablesBackend(rate_limit_per_second=10)
    for timeout in (0, -1):
        with pytest.raises(FirewallError, match="timeout must be positive"):
            backend.authorize_portal_client(IPv4Address("192.168.100.50"), timeout)


def test_deleting_an_already_expired_element_is_idempotent(monkeypatch: Any) -> None:
    """The kernel expiring an element out from under us is normal, not a failure."""

    def _missing(self: NftablesBackend, args: list[str], stdin_json: Any = None) -> str:
        raise FirewallError("nft command failed: Error: No such file or directory")

    monkeypatch.setattr(NftablesBackend, "_run_command", _missing)
    NftablesBackend(rate_limit_per_second=10).deauthorize_portal_client(IPv4Address("192.168.100.50"))


def test_a_real_delete_failure_is_still_raised(monkeypatch: Any) -> None:
    def _broken(self: NftablesBackend, args: list[str], stdin_json: Any = None) -> str:
        raise FirewallError("nft command failed: Operation not permitted")

    monkeypatch.setattr(NftablesBackend, "_run_command", _broken)
    with pytest.raises(FirewallError, match="Operation not permitted"):
        NftablesBackend(rate_limit_per_second=10).deauthorize_portal_client(IPv4Address("192.168.100.50"))


def test_listing_parses_both_element_shapes_nft_emits(monkeypatch: Any) -> None:
    """Timeout-bearing elements are objects; bare ones are strings. Read both."""
    payload = {
        "nftables": [
            {
                "set": {
                    "name": "authed",
                    "elem": [
                        {"elem": {"val": "192.168.100.50", "timeout": 1800, "expires": 1200}},
                        "192.168.100.51",
                        {"elem": {"val": "not-an-address"}},
                    ],
                }
            }
        ]
    }
    def _list(_self: NftablesBackend, _args: list[str], _stdin_json: Any = None) -> str:
        return json.dumps(payload)

    monkeypatch.setattr(NftablesBackend, "_run_command", _list)
    clients = NftablesBackend(rate_limit_per_second=10).list_portal_clients()
    assert clients == frozenset({IPv4Address("192.168.100.50"), IPv4Address("192.168.100.51")})


# --------------------------------- the matching predicate, tested directly
#
# `rules_targeting` is pure, so these can use rule shapes the validation
# chain currently refuses. That is the point: the predicate must be correct
# regardless of what the pipeline happens to produce today, because the cost
# of getting it wrong is telling innocent users their device is infected.


def _rule(source: str, destination: str, action: FirewallAction = FirewallAction.BLOCK) -> FirewallRule:
    return make_firewall_rule(
        id=f"{source}->{destination}",
        status=RuleStatus.ACTIVE,
        action=action,
        source=source,
        destination=destination,
        created_at=NOW,
    )


def test_a_broad_destination_does_not_implicate_every_client() -> None:
    """Regression: `0.0.0.0/0` contains every address, including innocent ones.

    A plain containment check reported a block on *one* device as blocking
    *everybody*. Spec §24 refuses `0.0.0.0/0` today, so the adaptive
    pipeline cannot produce this — the predicate is defensive about it
    anyway.
    """
    offender = _lan_client(20)
    innocent = _lan_client(9)
    rules = [_rule(f"{offender}/32", "0.0.0.0/0")]
    assert len(rules_targeting(rules, offender, PROTECTED)) == 1
    assert rules_targeting(rules, innocent, PROTECTED) == []


def test_a_rule_against_the_whole_protected_lan_targets_every_client() -> None:
    """An equal network is not a supernet to be ignored — it really does cover everyone."""
    rules = [_rule(str(PROTECTED), "0.0.0.0/0", FirewallAction.RATE_LIMIT)]
    assert len(rules_targeting(rules, _lan_client(9), PROTECTED)) == 1
    assert len(rules_targeting(rules, _lan_client(20), PROTECTED)) == 1


def test_a_block_on_two_remote_hosts_implicates_no_lan_client() -> None:
    """Blocking an external attacker must not tell our own users they are malicious."""
    rules = [_rule("203.0.113.5/32", "198.51.100.7/32")]
    assert rules_targeting(rules, _lan_client(9), PROTECTED) == []


def test_a_supernet_of_the_protected_network_is_not_read_as_targeting_anyone() -> None:
    """A /8 containing the LAN names no particular client, so it implicates none of them."""
    rules = [_rule("192.0.0.0/8", "0.0.0.0/0")]
    assert rules_targeting(rules, _lan_client(9), PROTECTED) == []


@pytest.mark.parametrize("action", [FirewallAction.ALLOW, FirewallAction.MONITOR])
def test_a_non_restrictive_action_never_implicates_a_client(action: FirewallAction) -> None:
    """MONITOR logs and counts; it does not stop traffic, so nobody should be told it did."""
    client = _lan_client(9)
    rules = [_rule(f"{client}/32", REMOTE, action)]
    assert rules_targeting(rules, client, PROTECTED) == []


def test_an_empty_rule_set_implicates_nobody() -> None:
    assert rules_targeting([], _lan_client(9), PROTECTED) == []
