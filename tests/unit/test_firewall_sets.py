"""`pirewall.firewall.sets`, `pirewall.firewall.guards` and `FakeSetBackend` (phase 13)."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network

import pytest

from pirewall.core import nft_names
from pirewall.core.enums import FirewallAction, GuardMode, GuardName
from pirewall.core.exceptions import FirewallError
from pirewall.core.models.identity import RuleTarget
from pirewall.core.models.rule import FirewallRule
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from pirewall.firewall.guards import (
    ALL_OBSERVE,
    effective_raw_mode,
    guard_mode_commands,
    mode_from_rules,
    verdict_expressions,
)
from pirewall.firewall.sets import (
    MAX_ELEMENT_TIMEOUT_SECONDS,
    SetOp,
    SetOpKind,
    device_target,
    element_key,
    element_timeout_seconds,
    enforcement_set_for,
    validate_element,
)
from tests.helpers.rules import make_firewall_rule

NOW = datetime(2026, 1, 1, tzinfo=UTC)
LAN = IPv4Network("192.168.1.0/24")
MAC = "02:00:00:00:00:20"


class _Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


def _rule(source: str) -> FirewallRule:
    return make_firewall_rule(source=source)


# --------------------------------------------------------------- validation


def test_only_manager_writable_sets_can_be_written() -> None:
    for kernel_set in (nft_names.SET_OFFENDERS, nft_names.SET_SYN_METER, nft_names.SET_INFRA4):
        table = nft_names.STATIC_TABLE if kernel_set != nft_names.SET_INFRA4 else nft_names.ADAPTIVE_TABLE
        with pytest.raises(FirewallError, match="not this set's writer"):
            validate_element(SetOp(SetOpKind.ADD, kernel_set, MAC, 60, table=table))


def test_enforcement_elements_need_a_timeout_within_an_hour() -> None:
    with pytest.raises(FirewallError, match="without a timeout"):
        validate_element(SetOp(SetOpKind.ADD, nft_names.SET_BLOCK4, "192.168.1.20"))
    with pytest.raises(FirewallError, match="outside"):
        validate_element(
            SetOp(SetOpKind.ADD, nft_names.SET_BLOCK4, "192.168.1.20", MAX_ELEMENT_TIMEOUT_SECONDS + 1)
        )
    validate_element(SetOp(SetOpKind.ADD, nft_names.SET_BLOCK4, "192.168.1.20", MAX_ELEMENT_TIMEOUT_SECONDS))


@pytest.mark.parametrize(
    "bad_mac", ["ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "00:00:00:00:00:00", "AA:BB:CC:00:11:22"]
)
def test_mac_keys_must_be_normalised_unicast(bad_mac: str) -> None:
    with pytest.raises(FirewallError):
        validate_element(SetOp(SetOpKind.ADD, nft_names.SET_BLOCK_MAC, bad_mac, 60))


def test_concatenated_binding_keys_are_checked_part_by_part() -> None:
    validate_element(
        SetOp(SetOpKind.ADD, nft_names.SET_MACBIND, ("192.168.1.20", MAC), 60, table=nft_names.STATIC_TABLE)
    )
    with pytest.raises(FirewallError):
        validate_element(
            SetOp(
                SetOpKind.ADD, nft_names.SET_MACBIND, (MAC, "192.168.1.20"), 60, table=nft_names.STATIC_TABLE
            )
        )


# ------------------------------------------------------------ translation


def test_device_target_is_a_lan_single_address_source_only() -> None:
    assert device_target(_rule("192.168.1.20/32"), LAN) == RuleTarget(ip=IPv4Address("192.168.1.20"))
    assert device_target(_rule("203.0.113.9/32"), LAN) is None, "a WAN source has no device"
    assert device_target(_rule("192.168.1.0/28"), LAN) is None, "a range is not one device"
    with_mac = device_target(_rule("192.168.1.20/32"), LAN, mac=MAC)
    assert with_mac is not None and with_mac.mac == MAC


def test_a_known_mac_selects_the_mac_keyed_sets() -> None:
    ip_only = RuleTarget(ip=IPv4Address("192.168.1.20"))
    with_mac = RuleTarget(ip=IPv4Address("192.168.1.20"), mac=MAC)
    assert enforcement_set_for(FirewallAction.BLOCK, ip_only) == nft_names.SET_BLOCK4
    assert enforcement_set_for(FirewallAction.RATE_LIMIT, ip_only) == nft_names.SET_RATELIMIT4
    assert enforcement_set_for(FirewallAction.BLOCK, with_mac) == nft_names.SET_BLOCK_MAC
    assert enforcement_set_for(FirewallAction.RATE_LIMIT, with_mac) == nft_names.SET_RATELIMIT_MAC
    assert enforcement_set_for(FirewallAction.MONITOR, with_mac) is None
    assert element_key(nft_names.SET_BLOCK_MAC, with_mac) == MAC
    assert element_key(nft_names.SET_BLOCK4, with_mac) == "192.168.1.20"


def test_element_timeouts_are_whole_seconds_capped_and_at_least_one() -> None:
    assert element_timeout_seconds(NOW + timedelta(seconds=300), NOW, 3600) == 300
    assert element_timeout_seconds(NOW + timedelta(hours=5), NOW, 3600) == 3600
    assert element_timeout_seconds(NOW + timedelta(seconds=900), NOW, 600) == 600
    assert element_timeout_seconds(NOW, NOW, 3600) == 1


# ------------------------------------------------------------------- guards


def test_a_verdict_chain_keeps_its_counter_in_both_modes() -> None:
    assert verdict_expressions(GuardName.RAW, GuardMode.OBSERVE) == [{"counter": "c_verdict_raw"}]
    assert verdict_expressions(GuardName.RAW, GuardMode.ENFORCE) == [
        {"counter": "c_verdict_raw"},
        {"drop": None},
    ]


def test_a_guard_flip_is_a_flush_and_one_rule_per_guard() -> None:
    commands = guard_mode_commands(ALL_OBSERVE)
    assert [next(iter(command)) for command in commands] == ["flush", "add"] * 3
    flushed = [command["flush"] for command in commands if "flush" in command]
    assert {str(item) for item in flushed} == {
        str({"chain": {"family": "inet", "table": nft_names.STATIC_TABLE, "name": chain}})
        for chain in nft_names.GUARD_VERDICT_CHAINS.values()
    }


def test_reading_a_chain_back_into_a_mode() -> None:
    assert mode_from_rules([[{"counter": "c_verdict_raw"}, {"drop": None}]]) is GuardMode.ENFORCE
    assert mode_from_rules([[{"counter": "c_verdict_raw"}]]) is GuardMode.OBSERVE


def test_an_unseeded_raw_guard_observes_whatever_the_config_says() -> None:
    assert effective_raw_mode(GuardMode.ENFORCE, bindings_seeded=False) is GuardMode.OBSERVE
    assert effective_raw_mode(GuardMode.ENFORCE, bindings_seeded=True) is GuardMode.ENFORCE
    assert effective_raw_mode(GuardMode.OBSERVE, bindings_seeded=True) is GuardMode.OBSERVE


# --------------------------------------------------------- FakeSetBackend


def test_fake_elements_expire_on_the_clock_without_being_told() -> None:
    clock = _Clock()
    backend = FakeSetBackend(clock)
    backend.add_element(nft_names.SET_BLOCK4, "192.168.1.20", 60)
    assert [state.key for state in backend.list_set(nft_names.SET_BLOCK4)] == ["192.168.1.20"]
    clock.now = NOW + timedelta(seconds=61)
    assert backend.list_set(nft_names.SET_BLOCK4) == []


def test_a_full_fake_set_refuses_and_the_batch_applies_nothing() -> None:
    backend = FakeSetBackend(_Clock(), adaptive_size=1)
    backend.add_element(nft_names.SET_BLOCK4, "192.168.1.20", 60)
    with pytest.raises(FirewallError, match="full"):
        backend.apply(
            [
                SetOp(SetOpKind.ADD, nft_names.SET_RATELIMIT4, "192.168.1.30", 60),
                SetOp(SetOpKind.ADD, nft_names.SET_BLOCK4, "192.168.1.21", 60),
            ]
        )
    assert backend.list_set(nft_names.SET_RATELIMIT4) == [], "the batch must be all-or-nothing"


def test_fake_delete_of_an_absent_element_is_not_an_error() -> None:
    backend = FakeSetBackend(_Clock())
    backend.delete_element(nft_names.SET_BLOCK4, "192.168.1.20")


def test_fake_panic_deletes_only_the_v2_tables() -> None:
    backend = FakeSetBackend(_Clock())
    assert backend.panic() == nft_names.PANIC_TABLES
    for family, table in nft_names.PANIC_TABLES:
        assert not backend.table_exists(family, table)
    assert backend.table_exists(nft_names.INET_FAMILY, nft_names.BASE_TABLE)
    assert backend.table_exists(nft_names.INET_FAMILY, nft_names.PORTAL_TABLE)
    with pytest.raises(FirewallError):
        backend.add_element(nft_names.SET_BLOCK4, "192.168.1.20", 60)
    assert backend.guard_mode(GuardName.RAW) is None


def test_fake_reload_keeps_elements_and_rerenders_guards() -> None:
    backend = FakeSetBackend(_Clock())
    backend.add_element(nft_names.SET_BLOCK4, "192.168.1.20", 600)
    backend.set_guard_mode(GuardName.FORWARD, GuardMode.ENFORCE)
    backend.load_tables()
    assert len(backend.list_set(nft_names.SET_BLOCK4)) == 1
    assert backend.guard_mode(GuardName.FORWARD) is GuardMode.ENFORCE
    backend.load_tables({GuardName.FORWARD: GuardMode.OBSERVE})
    assert backend.guard_mode(GuardName.FORWARD) is GuardMode.OBSERVE
