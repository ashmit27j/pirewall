"""`FirewallManager`'s MAC identity paths (ADDENDUM_4.md D3; phase 14), over `FakeSetBackend`.

Binding sync and its delete-before-add ordering (checked on the fake's op
log), the allowlist's `allow_bound` pairs, MAC-aware "am I blocked?" (C4),
and the spoofed-source cases on both paths (audit item 16).
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
from typing import Any

import pytest

from pirewall.core import nft_names
from pirewall.core.bindings import LeaseBindingTable
from pirewall.core.enums import BindingSource, FirewallAction, RuleRejectionReason, ThreatLevel
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.identity import Binding, BindingChange, RuleTarget
from pirewall.core.models.rule import CandidateRule
from pirewall.firewall import validator
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from pirewall.firewall.local_addresses import LocalAddresses
from pirewall.firewall.manager import FirewallManager, SubmissionResult
from pirewall.firewall.sets import SetOp, SetOpKind
from tests.helpers.config import make_config
from tests.helpers.rules import make_candidate
from tests.helpers.ruleset_diff import assert_only_allowed_changes

NOW = datetime(2026, 1, 1, tzinfo=UTC)
DEVICE = "192.168.1.20"
DEVICE_MAC = "02:00:00:00:00:20"
OTHER_MAC = "02:00:00:00:00:99"
ST = (nft_names.INET_FAMILY, nft_names.STATIC_TABLE)
ARP = (nft_names.ARP_FAMILY, nft_names.STATIC_ARP_TABLE)


@pytest.fixture(autouse=True)
def no_host_addresses(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    empty = LocalAddresses(host=frozenset(), broadcast=frozenset())
    monkeypatch.setattr(validator, "cached_local_addresses", lambda: empty)
    yield


class _Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


def _lease(ip: str, mac: str, seconds: int = 7200) -> Binding:
    return Binding(
        ip=IPv4Address(ip), mac=mac, source=BindingSource.LEASE, expires_at=NOW + timedelta(seconds=seconds)
    )


def _static(ip: str, mac: str) -> Binding:
    return Binding(ip=IPv4Address(ip), mac=mac, source=BindingSource.STATIC)


class _Harness:
    def __init__(self, *, v2: bool = True, mode: str = "active", **config: dict[str, Any]) -> None:
        self.clock = _Clock()
        self.config = make_config(firewall={"enforcement_mode": mode, **config.pop("firewall", {})}, **config)
        self.sets = FakeSetBackend(self.clock)
        self.v1 = FakeFirewallBackend()
        self.bindings = LeaseBindingTable()
        self.manager = FirewallManager(
            self.config,
            self.v1,
            set_backend=self.sets if v2 else None,
            mac_resolver=self.bindings.resolve_mac,
        )
        self._decisions = 0

    def bind(self, *bindings: Binding) -> None:
        self.manager.sync_bindings(self.bindings.apply_leases(bindings, self.clock.now), self.clock.now)

    def submit(self, **overrides: Any) -> SubmissionResult:
        self._decisions += 1
        fields: dict[str, Any] = {
            "decision_id": f"d{self._decisions}",
            "source": f"{DEVICE}/32",
            "destination": "203.0.113.9/32",
            "created_at": self.clock.now,
            "expires_at": self.clock.now + timedelta(seconds=300),
            "evidence": (f"evidence-{self._decisions}",),
        }
        fields.update(overrides)
        candidate = make_candidate(**fields)
        self._register(candidate)
        return self.manager.submit_candidate(candidate, self.clock.now)

    def _register(self, candidate: CandidateRule) -> None:
        self.manager.register_decision(
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

    def keys(
        self, set_name: str, location: tuple[str, str] = ("inet", nft_names.ADAPTIVE_TABLE)
    ) -> list[object]:
        family, table = location
        return [state.key for state in self.sets.list_set(set_name, table=table, family=family)]

    def last_batch(self) -> tuple[SetOp, ...]:
        kind, ops = self.sets.ops[-1]
        assert kind == "apply"
        return tuple(op for op in ops if isinstance(op, SetOp))


# ------------------------------------------------------------ sync_bindings


def test_a_lease_binding_is_written_to_both_binding_tables_with_lease_plus_grace() -> None:
    harness = _Harness()
    harness.bind(_lease(DEVICE, DEVICE_MAC, seconds=7200))
    for location in (ST, ARP):
        assert harness.keys(nft_names.SET_BOUND4, location) == [DEVICE]
        assert harness.keys(nft_names.SET_MACBIND, location) == [(DEVICE, DEVICE_MAC)]
    grace = harness.config.antispoof.grace_seconds
    assert {op.timeout_seconds for op in harness.last_batch()} == {7200 + grace}
    assert len(harness.sets.ops) == 1, "one nft batch per sync"


def test_a_lease_longer_than_an_hour_is_bound_for_all_of_it() -> None:
    """The one-hour ceiling is for enforcement elements; a binding lives as long as its lease."""
    harness = _Harness()
    harness.bind(_lease(DEVICE, DEVICE_MAC, seconds=12 * 3600))
    states = harness.sets.list_set(nft_names.SET_MACBIND, table=nft_names.STATIC_TABLE)
    assert states[0].expires_in_seconds == 12 * 3600 + harness.config.antispoof.grace_seconds


def test_a_moved_lease_deletes_the_old_pair_before_adding_the_new_one_in_one_batch() -> None:
    harness = _Harness()
    harness.bind(_lease(DEVICE, DEVICE_MAC))
    harness.bind(_lease(DEVICE, OTHER_MAC))
    batch = harness.last_batch()
    kinds = [op.kind for op in batch]
    assert kinds == sorted(kinds, key=lambda kind: kind is SetOpKind.ADD), "every delete precedes every add"
    deleted = {op.key for op in batch if op.kind is SetOpKind.DELETE and op.set_name == nft_names.SET_MACBIND}
    added = {op.key for op in batch if op.kind is SetOpKind.ADD and op.set_name == nft_names.SET_MACBIND}
    assert deleted == {(DEVICE, DEVICE_MAC)} and added == {(DEVICE, OTHER_MAC)}
    for location in (ST, ARP):
        assert harness.keys(nft_names.SET_MACBIND, location) == [(DEVICE, OTHER_MAC)]
    assert len(harness.sets.ops) == 2, "one batch per sync, so the move is atomic"


def test_an_unchanged_lease_set_writes_nothing() -> None:
    harness = _Harness()
    harness.bind(_lease(DEVICE, DEVICE_MAC))
    assert harness.manager.sync_bindings(BindingChange(), NOW) == 0
    harness.bind(_lease(DEVICE, DEVICE_MAC))
    assert len(harness.sets.ops) == 1


def test_static_bindings_carry_no_timeout() -> None:
    harness = _Harness()
    harness.manager.sync_bindings(BindingChange(added=(_static(DEVICE, DEVICE_MAC),)), NOW)
    assert {op.timeout_seconds for op in harness.last_batch()} == {None}
    harness.clock.now += timedelta(days=30)
    assert harness.keys(nft_names.SET_BOUND4, ST) == [DEVICE]


def test_binding_sync_is_a_no_op_on_the_v1_path() -> None:
    harness = _Harness(v2=False)
    assert harness.manager.sync_bindings(BindingChange(added=(_lease(DEVICE, DEVICE_MAC),)), NOW) == 0
    assert harness.manager.replace_bindings((_lease(DEVICE, DEVICE_MAC),), NOW) == 0
    assert harness.sets.ops == []


def test_replace_bindings_removes_pairs_left_by_a_previous_run_and_refreshes_the_rest() -> None:
    harness = _Harness()
    harness.bind(_lease(DEVICE, DEVICE_MAC, seconds=60), _lease("192.168.1.30", "02:00:00:00:00:30"))
    harness.manager.replace_bindings((_lease(DEVICE, DEVICE_MAC, seconds=7200),), NOW)
    for location in (ST, ARP):
        assert harness.keys(nft_names.SET_BOUND4, location) == [DEVICE]
        assert harness.keys(nft_names.SET_MACBIND, location) == [(DEVICE, DEVICE_MAC)]
    states = harness.sets.list_set(nft_names.SET_MACBIND, table=nft_names.STATIC_TABLE)
    assert states[0].expires_in_seconds == 7200 + harness.config.antispoof.grace_seconds
    batch = harness.last_batch()
    first_add = next(index for index, op in enumerate(batch) if op.kind is SetOpKind.ADD)
    assert all(op.kind is SetOpKind.ADD for op in batch[first_add:])


def test_binding_writes_stay_inside_d1s_allowance() -> None:
    harness = _Harness()
    before = harness.sets.snapshot()
    harness.bind(_lease(DEVICE, DEVICE_MAC))
    harness.bind(_lease(DEVICE, OTHER_MAC))
    harness.manager.replace_bindings((), NOW)
    assert_only_allowed_changes(before, harness.sets.snapshot())


# ---------------------------------------------------------------- allowlist


def _allow(
    target: str = f"{DEVICE}/32", mac: str | None = DEVICE_MAC, entry_id: str = "a1"
) -> AllowlistEntry:
    return AllowlistEntry(
        id=entry_id, target=IPv4Network(target), reason="trusted", created_at=NOW, created_by="admin", mac=mac
    )


def test_an_allowlist_entry_with_a_mac_and_a_32_is_written_to_both_allow_bound_sets() -> None:
    harness = _Harness()
    harness.manager.add_allowlist_entry(_allow())
    for table in (nft_names.STATIC_TABLE, nft_names.ADAPTIVE_TABLE):
        assert harness.keys(nft_names.SET_ALLOW_BOUND, ("inet", table)) == [(DEVICE_MAC, DEVICE)]
    assert len(harness.sets.ops) == 1, "both copies in one batch"
    harness.manager.remove_allowlist_entry("a1")
    for table in (nft_names.STATIC_TABLE, nft_names.ADAPTIVE_TABLE):
        assert harness.keys(nft_names.SET_ALLOW_BOUND, ("inet", table)) == []


def test_ip_only_or_range_entries_write_no_pair() -> None:
    harness = _Harness()
    harness.manager.add_allowlist_entry(_allow(mac=None))
    harness.manager.add_allowlist_entry(_allow(target="192.168.1.0/28", mac=None, entry_id="a2"))
    assert harness.sets.ops == []


def test_a_mac_pinned_entry_needs_a_single_address() -> None:
    with pytest.raises(ValueError, match="/32"):
        _allow(target="192.168.1.0/28")


def test_a_pair_pinned_twice_stays_until_the_last_entry_goes() -> None:
    harness = _Harness()
    harness.manager.add_allowlist_entry(_allow(entry_id="a1"))
    harness.manager.add_allowlist_entry(_allow(entry_id="a2"))
    assert len(harness.sets.ops) == 1
    harness.manager.remove_allowlist_entry("a1")
    assert harness.keys(nft_names.SET_ALLOW_BOUND, ("inet", nft_names.STATIC_TABLE)) == [(DEVICE_MAC, DEVICE)]
    harness.manager.remove_allowlist_entry("a2")
    assert harness.keys(nft_names.SET_ALLOW_BOUND, ("inet", nft_names.STATIC_TABLE)) == []


def test_sync_allowlist_reconciles_the_kernel_with_the_allowlist_at_startup() -> None:
    harness = _Harness(firewall={"allowlist": [_allow().model_dump(mode="json")]})
    stale = ("02:00:00:00:00:77", "192.168.1.77")
    harness.sets.apply([SetOp(SetOpKind.ADD, nft_names.SET_ALLOW_BOUND, stale, table=nft_names.STATIC_TABLE)])
    written = harness.manager.sync_allowlist()
    assert written == 3  # one stale delete, two adds
    for table in (nft_names.STATIC_TABLE, nft_names.ADAPTIVE_TABLE):
        assert harness.keys(nft_names.SET_ALLOW_BOUND, ("inet", table)) == [(DEVICE_MAC, DEVICE)]
    assert harness.manager.sync_allowlist() == 0


@pytest.mark.parametrize("v2", [True, False])
def test_an_allowlisted_mac_is_protected_at_any_address(v2: bool) -> None:
    """D3 + A2: the validator refuses a target whose MAC is allowlisted, even at a new IP."""
    harness = _Harness(v2=v2)
    harness.manager.add_allowlist_entry(_allow(target="192.168.1.21/32"))
    harness.bind(_lease(DEVICE, DEVICE_MAC))
    target = RuleTarget(ip=IPv4Address(DEVICE), mac=DEVICE_MAC)
    result = harness.submit(target=target)
    assert result.rule is None
    assert result.event.reason == f"allowlist:{RuleRejectionReason.ALLOWLISTED.value}"


# --------------------------------------------------------- targets and spoofing


def test_a_bound_device_is_blocked_by_mac() -> None:
    harness = _Harness()
    harness.bind(_lease(DEVICE, DEVICE_MAC))
    result = harness.submit()
    assert result.rule is not None and result.rule.target == RuleTarget(
        ip=IPv4Address(DEVICE), mac=DEVICE_MAC
    )
    assert harness.keys(nft_names.SET_BLOCK_MAC) == [DEVICE_MAC]
    assert harness.keys(nft_names.SET_BLOCK4) == []


def test_v2_a_spoofed_source_blocks_the_sender_and_never_the_bound_owner() -> None:
    """Audit item 16: the candidate names the frame's MAC; the neighbour never enters a set."""
    harness = _Harness()
    harness.bind(_lease(DEVICE, DEVICE_MAC))
    attacker = RuleTarget(ip=IPv4Address(DEVICE), mac=OTHER_MAC)
    result = harness.submit(target=attacker)
    assert result.rule is not None
    assert harness.keys(nft_names.SET_BLOCK_MAC) == [OTHER_MAC]
    for set_name in nft_names.ADAPTIVE_ENFORCEMENT_SETS:
        assert DEVICE_MAC not in harness.keys(set_name) and DEVICE not in harness.keys(set_name)
    assert harness.manager.blocking_rules_matching(IPv4Address(DEVICE)) == [], (
        "the owner is not told it is blocked"
    )


def test_v1_a_spoofed_source_is_refused_because_v1_can_only_block_the_address() -> None:
    harness = _Harness(v2=False)
    harness.bind(_lease(DEVICE, DEVICE_MAC))
    result = harness.submit(target=RuleTarget(ip=IPv4Address(DEVICE), mac=OTHER_MAC))
    assert result.rule is None
    assert result.event.reason == f"network:{RuleRejectionReason.SPOOFED_SOURCE.value}"
    assert harness.v1.deployed_rules == {}


def test_v1_a_matching_target_deploys_and_keeps_the_target_on_the_rule() -> None:
    harness = _Harness(v2=False)
    harness.bind(_lease(DEVICE, DEVICE_MAC))
    target = RuleTarget(ip=IPv4Address(DEVICE), mac=DEVICE_MAC)
    result = harness.submit(target=target)
    assert result.rule is not None and result.rule.target == target
    assert result.rule.id in harness.v1.deployed_rules


def test_a_target_must_be_the_rules_source() -> None:
    with pytest.raises(ValueError, match="source"):
        make_candidate(source=f"{DEVICE}/32", target=RuleTarget(ip=IPv4Address("192.168.1.21")))


# ------------------------------------------------------------- C4 matching


def test_a_mac_keyed_block_follows_the_device_to_a_new_address() -> None:
    harness = _Harness()
    harness.bind(_lease(DEVICE, DEVICE_MAC))
    assert harness.submit().rule is not None
    harness.bind(_lease("192.168.1.40", DEVICE_MAC))
    assert harness.manager.blocking_rules_matching(IPv4Address("192.168.1.40"))


def test_a_device_that_inherits_a_blocked_devices_address_is_not_told_it_is_blocked() -> None:
    harness = _Harness()
    harness.bind(_lease(DEVICE, DEVICE_MAC))
    assert harness.submit().rule is not None
    harness.bind(_lease(DEVICE, OTHER_MAC))
    assert harness.manager.blocking_rules_matching(IPv4Address(DEVICE)) == []


def test_an_ip_keyed_block_matches_by_address() -> None:
    harness = _Harness()
    assert harness.submit().rule is not None
    assert harness.keys(nft_names.SET_BLOCK4) == [DEVICE]
    harness.bind(_lease(DEVICE, OTHER_MAC))
    assert harness.manager.blocking_rules_matching(IPv4Address(DEVICE))


def test_with_no_binding_left_a_mac_keyed_block_still_matches_its_address() -> None:
    """C4 errs toward telling a client why: its lease lapsed, the kernel may still block its MAC."""
    harness = _Harness()
    harness.bind(_lease(DEVICE, DEVICE_MAC))
    assert harness.submit().rule is not None
    harness.bind()
    assert harness.manager.blocking_rules_matching(IPv4Address(DEVICE))


def test_rate_limits_are_restrictive_but_never_blocking() -> None:
    harness = _Harness()
    harness.bind(_lease(DEVICE, DEVICE_MAC))
    assert harness.submit(action=FirewallAction.RATE_LIMIT).rule is not None
    assert harness.manager.restrictive_rules_matching(IPv4Address(DEVICE))
    assert harness.manager.blocking_rules_matching(IPv4Address(DEVICE)) == []


# ------------------------------------------------------------------ portal


def test_a_portal_grant_is_the_ip_and_mac_pair_and_is_revoked_by_address_alone() -> None:
    harness = _Harness()
    harness.manager.authorize_portal_client(IPv4Address(DEVICE), 600, DEVICE_MAC)
    assert harness.manager.authorized_portal_grants() == frozenset({(IPv4Address(DEVICE), DEVICE_MAC)})
    harness.manager.deauthorize_portal_client(IPv4Address(DEVICE))
    assert harness.manager.authorized_portal_grants() == frozenset()


def test_revoking_a_pair_with_the_wrong_mac_leaves_it() -> None:
    harness = _Harness()
    harness.manager.authorize_portal_client(IPv4Address(DEVICE), 600, DEVICE_MAC)
    harness.manager.deauthorize_portal_client(IPv4Address(DEVICE), OTHER_MAC)
    assert harness.manager.authorized_portal_clients() == frozenset({IPv4Address(DEVICE)})
