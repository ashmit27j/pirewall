"""`FirewallManager`'s v2 set path over `FakeSetBackend` (phase 13; ADDENDUM_4.md D1, D4, D5).

The validator's view of the host's own addresses is pinned empty, so no
result here depends on the machine the suite runs on (KNOWN_ISSUES.md #19).
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network
from typing import Any

import pytest

from pirewall.core import nft_names
from pirewall.core.enums import (
    EnforcementMode,
    EventSeverity,
    FirewallAction,
    GuardMode,
    GuardName,
    RuleRejectionReason,
    RuleStatus,
    SecurityEventType,
    ThreatLevel,
)
from pirewall.core.exceptions import FirewallError
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.rule import CandidateRule
from pirewall.firewall import validator
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from pirewall.firewall.local_addresses import LocalAddresses
from pirewall.firewall.manager import FirewallManager, SubmissionResult
from pirewall.firewall.sets import SetOpKind
from tests.helpers.config import make_config
from tests.helpers.rules import make_candidate
from tests.helpers.ruleset_diff import assert_only_allowed_changes

NOW = datetime(2026, 1, 1, tzinfo=UTC)
DEVICE = "192.168.1.20"
DEVICE_MAC = "02:00:00:00:00:20"


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


class _Harness:
    def __init__(self, mode: str = "active", mac: str | None = None, **config: dict[str, Any]) -> None:
        self.clock = _Clock()
        self.config = make_config(firewall={"enforcement_mode": mode, **config.pop("firewall", {})}, **config)
        self.sets = FakeSetBackend(self.clock)
        self.manager = FirewallManager(
            self.config,
            FakeFirewallBackend(),
            set_backend=self.sets,
            mac_resolver=(lambda _ip: mac) if mac is not None else None,
        )
        self._decisions = 0

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

    def keys(self, set_name: str) -> list[object]:
        return [state.key for state in self.sets.list_set(set_name)]


def _rejected_reason(result: SubmissionResult) -> str:
    assert result.rule is None
    return result.event.reason or ""


# ----------------------------------------------------------------- deploy


def test_a_block_becomes_one_block4_element_with_its_ttl() -> None:
    harness = _Harness()
    result = harness.submit()
    assert result.rule is not None and result.rule.status is RuleStatus.ACTIVE
    states = harness.sets.list_set(nft_names.SET_BLOCK4)
    assert [state.key for state in states] == [DEVICE]
    assert states[0].expires_in_seconds == 300
    assert result.event.event_type is SecurityEventType.FIREWALL_BLOCK


def test_a_rate_limit_without_a_mac_goes_to_ratelimit4() -> None:
    harness = _Harness()
    harness.submit(action=FirewallAction.RATE_LIMIT)
    assert harness.keys(nft_names.SET_RATELIMIT4) == [DEVICE]


def test_a_resolved_mac_selects_the_mac_keyed_sets() -> None:
    harness = _Harness(mac=DEVICE_MAC)
    harness.submit()
    assert harness.keys(nft_names.SET_BLOCK_MAC) == [DEVICE_MAC]
    assert harness.keys(nft_names.SET_BLOCK4) == []


def test_a_scan_of_many_ports_is_one_element_not_one_rule_per_port() -> None:
    """Audit item 14: duplicate detection is per device, not per (src, dst, dport) tuple."""
    harness = _Harness()
    results = [harness.submit(destination_port=port) for port in range(20, 40)]
    assert sum(result.rule is not None for result in results) == 1
    assert all("duplicate" in _rejected_reason(result) for result in results[1:])
    assert harness.keys(nft_names.SET_BLOCK4) == [DEVICE]
    assert harness.manager.adaptive_rules_in_window(NOW) == 1, "A3 counts element insertions"


def test_shadow_writes_nothing() -> None:
    harness = _Harness(mode="shadow")
    result = harness.submit()
    assert result.rule is not None and result.rule.status is RuleStatus.SHADOWED
    assert harness.sets.ops == []


def test_assisted_holds_a_high_confidence_block_and_deploys_it_on_approval() -> None:
    harness = _Harness(mode="assisted")
    pending = harness.submit(threat_score=99.0)
    assert pending.rule is not None and pending.rule.status is RuleStatus.PENDING_APPROVAL
    assert harness.sets.ops == []
    approved = harness.manager.approve_pending(pending.rule.id, NOW)
    assert approved is not None and approved.rule is not None and approved.rule.status is RuleStatus.ACTIVE
    assert harness.keys(nft_names.SET_BLOCK4) == [DEVICE]


def test_a_failed_write_rejects_the_rule() -> None:
    harness = _Harness()
    harness.sets.fail_next = True
    result = harness.submit()
    assert result.rule is not None and result.rule.status is RuleStatus.REJECTED
    assert result.event.event_type is SecurityEventType.FIREWALL_ERROR
    assert result.event.severity is EventSeverity.CRITICAL


# --------------------------------------------------- upgrades and conflicts


def test_a_block_upgrades_a_rate_limit_in_one_atomic_batch() -> None:
    harness = _Harness()
    limited = harness.submit(action=FirewallAction.RATE_LIMIT)
    assert limited.rule is not None
    harness.sets.ops.clear()
    blocked = harness.submit(action=FirewallAction.BLOCK)
    assert blocked.rule is not None and blocked.rule.status is RuleStatus.ACTIVE

    assert len(harness.sets.ops) == 1, "delete + add must be one batch"
    kind, ops = harness.sets.ops[0]
    assert kind == "apply"
    assert [(op.kind, op.set_name) for op in ops] == [  # type: ignore[attr-defined]
        (SetOpKind.DELETE, nft_names.SET_RATELIMIT4),
        (SetOpKind.ADD, nft_names.SET_BLOCK4),
    ]
    assert harness.keys(nft_names.SET_RATELIMIT4) == []
    assert harness.keys(nft_names.SET_BLOCK4) == [DEVICE]
    old = harness.manager.get_rule(limited.rule.id)
    assert old is not None and old.status is RuleStatus.REMOVED


def test_an_upgrade_needs_new_evidence() -> None:
    harness = _Harness()
    harness.submit(action=FirewallAction.RATE_LIMIT, evidence=("scan",))
    repeat = harness.submit(action=FirewallAction.BLOCK, evidence=("scan",))
    assert RuleRejectionReason.NO_NEW_EVIDENCE.value in _rejected_reason(repeat)
    assert harness.keys(nft_names.SET_RATELIMIT4) == [DEVICE]


def test_a_rate_limit_on_a_blocked_device_is_a_conflict() -> None:
    harness = _Harness()
    harness.submit(action=FirewallAction.BLOCK)
    result = harness.submit(action=FirewallAction.RATE_LIMIT)
    assert RuleRejectionReason.CONFLICT.value in _rejected_reason(result)


# ----------------------------------------------------------- validation


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        ("203.0.113.9/32", RuleRejectionReason.UNENFORCEABLE),
        ("192.168.1.0/28", RuleRejectionReason.UNENFORCEABLE),
        ("192.168.1.2/32", RuleRejectionReason.UNSAFE),  # the Pi's LAN address
        ("192.168.1.50/32", RuleRejectionReason.UNSAFE),  # the Admin PC
        ("192.168.1.255/32", RuleRejectionReason.UNSAFE),  # the LAN broadcast
    ],
)
def test_targets_that_are_not_a_safe_lan_device_are_refused(source: str, reason: RuleRejectionReason) -> None:
    harness = _Harness()
    result = harness.submit(source=source)
    assert reason.value in _rejected_reason(result)
    assert harness.sets.ops == []


def test_the_admin_pc_mac_is_infrastructure_too() -> None:
    harness = _Harness(mac=DEVICE_MAC, admin={"admin_pc_ip": "192.168.1.50", "admin_pc_mac": DEVICE_MAC})
    result = harness.submit()
    assert RuleRejectionReason.UNSAFE.value in _rejected_reason(result)


def test_a_port_scoped_allowlist_entry_still_protects_the_whole_device() -> None:
    entry = AllowlistEntry(
        target=IPv4Network(f"{DEVICE}/32"),
        port=443,
        reason="printer",
        created_at=NOW,
        created_by="admin",  # type: ignore[arg-type]
    )
    harness = _Harness(firewall={"allowlist": [entry.model_dump(mode="json")]})
    result = harness.submit()
    assert RuleRejectionReason.ALLOWLISTED.value in _rejected_reason(result)


def test_a_ttl_longer_than_policy_max_is_refused() -> None:
    harness = _Harness(
        policy={"max_ttl_seconds": 600, "rate_limit_ttl_seconds": 300, "block_ttl_seconds": 300}
    )
    result = harness.submit(expires_at=NOW + timedelta(seconds=601))
    assert RuleRejectionReason.EXPIRATION_TOO_LONG.value in _rejected_reason(result)


# --------------------------------------------------------- lifecycle ends


def test_expiry_and_removal_delete_the_element() -> None:
    harness = _Harness()
    first = harness.submit()
    assert first.rule is not None
    harness.manager.remove_rule(first.rule.id, NOW)
    assert harness.keys(nft_names.SET_BLOCK4) == []

    second = harness.submit(source="192.168.1.21/32")
    assert second.rule is not None
    harness.clock.now = NOW + timedelta(seconds=301)
    expired = harness.manager.expire_rules(harness.clock.now)
    assert [rule.id for rule in expired] == [second.rule.id]


def test_the_kill_switch_flushes_sets_and_sets_every_guard_to_observe() -> None:
    harness = _Harness()
    harness.submit()
    harness.submit(source="192.168.1.21/32", action=FirewallAction.RATE_LIMIT)
    before = harness.sets.snapshot()
    event = harness.manager.revert_to_base(NOW)
    assert_only_allowed_changes(before, harness.sets.snapshot())

    assert harness.manager.enforcement_mode is EnforcementMode.SHADOW
    for set_name in nft_names.ADAPTIVE_ENFORCEMENT_SETS:
        assert harness.keys(set_name) == []
    assert all(harness.sets.guard_mode(guard) is GuardMode.OBSERVE for guard in GuardName)
    assert harness.manager.active_rules() == []
    assert event.severity is EventSeverity.WARNING
    assert harness.sets.table_exists(nft_names.INET_FAMILY, nft_names.STATIC_TABLE)


def test_fail_open_shutdown_flushes_sets_but_leaves_the_guards() -> None:
    """Audit item 17: a crash loop must not switch the kernel guards off."""
    harness = _Harness()
    harness.submit()
    harness.manager.fail_open_shutdown(NOW)
    assert harness.keys(nft_names.SET_BLOCK4) == []
    assert harness.sets.guard_mode(GuardName.RAW) is GuardMode.ENFORCE
    assert harness.sets.guard_mode(GuardName.INPUT) is GuardMode.ENFORCE
    assert harness.manager.enforcement_mode is EnforcementMode.ACTIVE


def test_panic_deletes_the_v2_tables_only_and_matches_state() -> None:
    harness = _Harness()
    harness.submit()
    before = harness.sets.snapshot()
    result, event = harness.manager.panic("admin", NOW)
    assert_only_allowed_changes(before, harness.sets.snapshot(), allow_panic=True)
    assert result.deleted_tables == tuple(f"{family} {table}" for family, table in nft_names.PANIC_TABLES)
    assert harness.manager.active_rules() == []
    assert harness.manager.enforcement_mode is EnforcementMode.SHADOW
    assert event.severity is EventSeverity.CRITICAL
    assert harness.manager.missing_tables() == list(nft_names.PANIC_TABLES)


def test_a_guard_flip_is_audited_and_read_back() -> None:
    harness = _Harness()
    before = harness.sets.snapshot()
    event = harness.manager.set_guard_mode(GuardName.FORWARD, GuardMode.ENFORCE, "admin", NOW)
    assert_only_allowed_changes(before, harness.sets.snapshot())
    assert "forward set to enforce by admin" in (event.reason or "")
    modes = harness.manager.guard_modes(NOW)
    assert (modes.raw, modes.input, modes.forward) == (
        GuardMode.ENFORCE,
        GuardMode.ENFORCE,
        GuardMode.ENFORCE,
    )


def test_every_manager_operation_stays_inside_d1s_allowance() -> None:
    harness = _Harness()
    before = harness.sets.snapshot()
    harness.submit()
    harness.submit(source="192.168.1.21/32", action=FirewallAction.RATE_LIMIT)
    harness.submit(source="192.168.1.21/32", action=FirewallAction.BLOCK)
    harness.manager.expire_rules(NOW + timedelta(hours=1))
    harness.manager.fail_open_shutdown(NOW)
    assert_only_allowed_changes(before, harness.sets.snapshot())


# --------------------------------------------------------------- reconcile


def test_reconcile_adopts_retires_and_reports() -> None:
    harness = _Harness()
    kept = harness.submit()
    gone = harness.submit(source="192.168.1.21/32")
    assert kept.rule is not None and gone.rule is not None
    harness.sets.delete_element(nft_names.SET_BLOCK4, "192.168.1.21")
    harness.sets.add_element(nft_names.SET_RATELIMIT4, "192.168.1.30", 120)
    harness.sets.add_element(nft_names.SET_BLOCK_MAC, "02:00:00:00:00:99", 120)

    report = harness.manager.reconcile(NOW)
    assert report.retired == [gone.rule.id]
    assert report.adopted == [f"reconciled:{nft_names.SET_RATELIMIT4}:192.168.1.30"]
    assert report.unattributed == [(nft_names.SET_BLOCK_MAC, "02:00:00:00:00:99")]
    assert report.missing_tables == []
    adopted = harness.manager.get_rule(report.adopted[0])
    assert adopted is not None and adopted.action is FirewallAction.RATE_LIMIT
    assert adopted.expires_at == NOW + timedelta(seconds=120)
    assert harness.manager.restrictive_rules_matching(adopted.source.network_address)
    # The unexplained MAC block is left for the kernel to expire, not deleted.
    assert harness.keys(nft_names.SET_BLOCK_MAC) == ["02:00:00:00:00:99"]


def test_reconcile_never_recreates_a_missing_table() -> None:
    harness = _Harness()
    harness.sets.panic()
    report = harness.manager.reconcile(NOW)
    assert report.missing_tables == list(nft_names.PANIC_TABLES)
    assert not harness.sets.table_exists(nft_names.INET_FAMILY, nft_names.ADAPTIVE_TABLE)


# --------------------------------------------------------------- v1 intact


def test_without_a_set_backend_the_v1_path_is_unchanged() -> None:
    config = make_config(firewall={"enforcement_mode": "active"})
    backend = FakeFirewallBackend()
    manager = FirewallManager(config, backend)
    assert not manager.uses_set_backend
    with pytest.raises(FirewallError):
        manager.panic("admin", NOW)
    assert manager.reconcile(NOW).adopted == []
