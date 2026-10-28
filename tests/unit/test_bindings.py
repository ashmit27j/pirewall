"""The dnsmasq lease parser and `LeaseBindingTable` (ADDENDUM_4.md D3; phase 14).

The lease file is client-controlled text (hostnames and client-ids are
whatever a DHCP client sent), so the parser cases here are deliberately
hostile: malformed lines, injected newlines, IPv6, duplicates, expiry 0.
"""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network

import pytest

from pirewall.config.models import StaticBindingEntry
from pirewall.core.binding_table import BindingTable
from pirewall.core.bindings import (
    IgnoredLease,
    LeaseBindingTable,
    parse_leases,
    static_bindings,
)
from pirewall.core.enums import BindingSource
from pirewall.core.models.identity import Binding
from tests.helpers.config import make_config

NETWORK = IPv4Network("192.168.100.0/24")
NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
LATER = int((NOW + timedelta(hours=1)).timestamp())
MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"


def _line(ip: str = "192.168.100.10", mac: str = MAC_A, expiry: int = LATER, rest: str = "phone *") -> str:
    return f"{expiry} {mac} {ip} {rest}"


def _lease(ip: str, mac: str, expires_at: datetime) -> Binding:
    return Binding(ip=IPv4Address(ip), mac=mac, source=BindingSource.LEASE, expires_at=expires_at)


# ------------------------------------------------------------------ parser


def test_a_well_formed_lease_becomes_a_binding_with_its_expiry() -> None:
    parsed = parse_leases(_line() + "\n", NETWORK)
    assert parsed.bindings == (_lease("192.168.100.10", MAC_A, datetime.fromtimestamp(LATER, tz=UTC)),)
    assert parsed.ignored_total == 0


def test_macs_are_normalised_and_client_ids_are_never_read() -> None:
    parsed = parse_leases(_line(mac="02:AB:00:00:00:0A", rest="* ff:00:11:22:33:44:55") + "\n", NETWORK)
    (binding,) = parsed.bindings
    assert binding.mac == "02:ab:00:00:00:0a"


@pytest.mark.parametrize(
    "line",
    [
        "garbage",
        "1700000000 02:00:00:00:00:0a",  # too few fields
        "1700000000 02:00:00:00:00:0a 192.168.100.10",  # hostname and client-id missing
        "1700000000 02:00:00:00:00:0a 192.168.100.10 phone * extra",  # six fields
        "1700000000  02:00:00:00:00:0a 192.168.100.10 phone *",  # double space
        "1700000000\t02:00:00:00:00:0a\t192.168.100.10\tphone\t*",  # tabs
        "-5 02:00:00:00:00:0a 192.168.100.10 phone *",
        "17e9 02:00:00:00:00:0a 192.168.100.10 phone *",
        "1700000000 02-00-00-00-00-0a 192.168.100.10 phone *",  # dnsmasq writes colons
        "1700000000 02:00:00:00:00 192.168.100.10 phone *",  # five octets
        "1700000000 06-02:00:00:00:00:0a 192.168.100.10 phone *",  # non-Ethernet hwtype form
        "1700000000 02:00:00:00:00:0a 192.168.100.999 phone *",
        "1700000000 02:00:00:00:00:0a 192.168.100 phone *",
        "123456789012 02:00:00:00:00:0a 192.168.100.10 phone *",  # 12-digit expiry
    ],
)
def test_malformed_lines_are_ignored_and_counted(line: str) -> None:
    parsed = parse_leases(line + "\n", NETWORK)
    assert parsed.bindings == ()
    assert parsed.ignored == {IgnoredLease.MALFORMED: 1}


def test_an_injected_newline_in_a_hostname_cannot_forge_a_lease() -> None:
    """A hostname holding a newline splits into two lines; the fragment matches no lease.

    dnsmasq refuses such hostnames itself; this holds even if one got through.
    """
    hostile_hostname = "phone\nAAAA 02:00:00:00:00:66 192.168.100.66 evil"
    text = _line(rest=f"{hostile_hostname} *") + "\n"
    parsed = parse_leases(text, NETWORK)
    assert parsed.bindings == ()
    assert parsed.ignored == {IgnoredLease.MALFORMED: 2}


def test_a_crafted_injection_cannot_take_a_neighbours_address() -> None:
    """The worst case: the attacker's hostname ends in a complete, well-formed fake line.

    The attacker (MAC A, leased .20) names the victim's address (.10). Its
    own line is cut short and dropped as malformed. Then two MACs claim .10,
    and an ambiguous address binds to nobody: the victim is metered as
    unbound, never dropped as the spoofer, and the attacker gains nothing.
    """
    victim = _line(ip="192.168.100.10", mac=MAC_B)
    attacker = _line(ip="192.168.100.20", mac=MAC_A, rest=f"x\n{LATER} {MAC_A} 192.168.100.10 y *")
    parsed = parse_leases(victim + "\n" + attacker + "\n", NETWORK)
    assert parsed.bindings == ()
    assert parsed.ignored == {IgnoredLease.MALFORMED: 1, IgnoredLease.CONFLICT: 2}


def test_ipv6_lease_lines_and_the_duid_line_are_ignored() -> None:
    text = (
        _line()
        + "\nduid 00:01:00:01:2c:5f:aa:bb:02:00:00:00:00:0a\n"
        + f"{LATER} 1234567 fd00::10 phone 00:01:00:01:2c\n"
    )
    parsed = parse_leases(text, NETWORK)
    assert [str(binding.ip) for binding in parsed.bindings] == ["192.168.100.10"]
    assert parsed.ignored == {IgnoredLease.IPV6: 2}


def test_expiry_zero_is_an_infinite_lease_and_is_not_bound() -> None:
    parsed = parse_leases(_line(expiry=0) + "\n", NETWORK)
    assert parsed.bindings == ()
    assert parsed.ignored == {IgnoredLease.INFINITE: 1}


def test_an_exact_duplicate_keeps_the_later_expiry() -> None:
    text = _line(expiry=LATER) + "\n" + _line(expiry=LATER + 600) + "\n" + _line(expiry=LATER - 600) + "\n"
    parsed = parse_leases(text, NETWORK)
    (binding,) = parsed.bindings
    assert binding.expires_at == datetime.fromtimestamp(LATER + 600, tz=UTC)
    assert parsed.ignored == {IgnoredLease.DUPLICATE: 2}


def test_one_address_leased_to_two_macs_binds_neither() -> None:
    text = _line(mac=MAC_A) + "\n" + _line(mac=MAC_B) + "\n" + _line(ip="192.168.100.11") + "\n"
    parsed = parse_leases(text, NETWORK)
    assert [(str(binding.ip), binding.mac) for binding in parsed.bindings] == [("192.168.100.11", MAC_A)]
    assert parsed.ignored == {IgnoredLease.CONFLICT: 2}


def test_one_mac_with_two_addresses_binds_both() -> None:
    text = _line(ip="192.168.100.10") + "\n" + _line(ip="192.168.100.11") + "\n"
    assert len(parse_leases(text, NETWORK).bindings) == 2


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        (_line(ip="10.0.0.5"), IgnoredLease.OUTSIDE_NETWORK),
        (_line(mac="01:00:5e:00:00:01"), IgnoredLease.NOT_UNICAST),
        (_line(mac="ff:ff:ff:ff:ff:ff"), IgnoredLease.NOT_UNICAST),
        (_line(mac="00:00:00:00:00:00"), IgnoredLease.NOT_UNICAST),
        (_line(rest="h" * 600 + " *"), IgnoredLease.TOO_LONG),
    ],
)
def test_leases_that_cannot_identify_a_lan_device_are_ignored(line: str, reason: IgnoredLease) -> None:
    parsed = parse_leases(line + "\n", NETWORK)
    assert parsed.bindings == ()
    assert parsed.ignored == {reason: 1}


def test_blank_lines_and_an_empty_file_are_fine() -> None:
    assert parse_leases("", NETWORK).bindings == ()
    assert parse_leases("\n\n  \n", NETWORK).ignored_total == 0


# ------------------------------------------------------------------- table


def _table() -> LeaseBindingTable:
    config = make_config(
        antispoof={"static": [{"ip": "192.168.100.5", "mac": "02:00:00:00:00:05", "reason": "printer"}]}
    )
    return LeaseBindingTable(static_bindings(config.antispoof.static))


def test_the_table_satisfies_the_frozen_protocol() -> None:
    table: BindingTable = _table()
    assert table.resolve_mac(IPv4Address("192.168.100.5")) == "02:00:00:00:00:05"
    assert table.resolve_ip("02:00:00:00:00:05") == IPv4Address("192.168.100.5")
    assert table.resolve_mac(IPv4Address("192.168.100.9")) is None


def test_apply_leases_reports_additions_then_resolves_them() -> None:
    table = _table()
    lease = _lease("192.168.100.10", MAC_A, NOW + timedelta(hours=1))
    change = table.apply_leases([lease], NOW)
    assert change.added == (lease,) and change.removed == ()
    assert table.resolve_mac(IPv4Address("192.168.100.10")) == MAC_A
    assert table.resolve_ip(MAC_A) == IPv4Address("192.168.100.10")
    assert table.apply_leases([lease], NOW) == type(change)()  # unchanged: nothing to write


def test_a_moved_lease_is_the_old_pair_removed_and_the_new_pair_added() -> None:
    table = _table()
    old = _lease("192.168.100.10", MAC_A, NOW + timedelta(hours=1))
    table.apply_leases([old], NOW)
    new = _lease("192.168.100.10", MAC_B, NOW + timedelta(hours=1))
    change = table.apply_leases([new], NOW)
    assert change.removed == (old,)
    assert change.added == (new,)
    assert table.resolve_mac(IPv4Address("192.168.100.10")) == MAC_B


def test_a_renewal_is_a_change_so_the_kernel_timeout_moves_too() -> None:
    table = _table()
    first = _lease("192.168.100.10", MAC_A, NOW + timedelta(hours=1))
    table.apply_leases([first], NOW)
    renewed = _lease("192.168.100.10", MAC_A, NOW + timedelta(hours=2))
    change = table.apply_leases([renewed], NOW)
    assert (change.removed, change.added) == ((first,), (renewed,))


def test_an_expired_or_vanished_lease_is_removed() -> None:
    table = _table()
    lease = _lease("192.168.100.10", MAC_A, NOW + timedelta(seconds=30))
    table.apply_leases([lease], NOW)
    assert table.apply_leases([lease], NOW + timedelta(seconds=30)).removed == (lease,)
    assert table.resolve_mac(IPv4Address("192.168.100.10")) is None


def test_a_static_binding_always_wins_over_a_lease_for_its_ip_or_its_mac() -> None:
    table = _table()
    same_ip = _lease("192.168.100.5", MAC_A, NOW + timedelta(hours=1))
    same_mac = _lease("192.168.100.40", "02:00:00:00:00:05", NOW + timedelta(hours=1))
    change = table.apply_leases([same_ip, same_mac], NOW)
    assert change.added == ()
    assert table.resolve_mac(IPv4Address("192.168.100.5")) == "02:00:00:00:00:05"
    assert table.resolve_ip("02:00:00:00:00:05") == IPv4Address("192.168.100.5")


def test_snapshot_is_an_immutable_copy_static_first() -> None:
    table = _table()
    table.apply_leases([_lease("192.168.100.10", MAC_A, NOW + timedelta(hours=1))], NOW)
    snapshot = table.snapshot()
    assert isinstance(snapshot, tuple)
    assert [binding.source for binding in snapshot] == [BindingSource.STATIC, BindingSource.LEASE]
    table.apply_leases([], NOW)
    assert len(snapshot) == 2, "a later change does not reach an earlier snapshot"


def test_the_table_refuses_the_wrong_binding_source_on_each_side() -> None:
    with pytest.raises(ValueError, match="STATIC"):
        LeaseBindingTable([_lease("192.168.100.10", MAC_A, NOW + timedelta(hours=1))])
    with pytest.raises(ValueError, match="LEASE"):
        _table().apply_leases(static_bindings(_table_config_static()), NOW)


def _table_config_static() -> tuple[StaticBindingEntry, ...]:
    return make_config(
        antispoof={"static": [{"ip": "192.168.100.6", "mac": "02:00:00:00:00:06", "reason": "nas"}]}
    ).antispoof.static
