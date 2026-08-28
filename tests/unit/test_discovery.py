"""`scripts.deployment.discovery` — parsing the live network layout from `ip -j` output.

Every test here works on captured JSON rather than a live `ip` invocation,
so the parsing is exercised on any machine. The fixtures are real
`ip -j route show default` / `ip -j addr show` / `ip -j neigh show` shapes
from a Raspberry Pi OS Bookworm gateway (eth0 uplink, wlan0 hotspot).

What the tests are really guarding: the two values safety validation
refuses to ever block — `pirewall_lan_ip` and `upstream_gateway` (spec §24)
— must come out of detection exactly right, because a wrong value there
silently removes that protection.
"""

import ipaddress

import pytest
from scripts.deployment.discovery import (
    DiscoveryError,
    InterfaceAddress,
    choose_lan_interface,
    parse_addresses,
    parse_default_route,
    parse_neighbours,
)

_ROUTES = [
    {
        "dst": "default",
        "gateway": "192.168.1.1",
        "dev": "eth0",
        "protocol": "dhcp",
        "prefsrc": "192.168.1.42",
        "metric": 100,
    }
]

_ADDRESSES = [
    {
        "ifindex": 1,
        "ifname": "lo",
        "flags": ["LOOPBACK", "UP", "LOWER_UP"],
        "operstate": "UNKNOWN",
        "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}],
    },
    {
        "ifindex": 2,
        "ifname": "eth0",
        "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
        "operstate": "UP",
        "addr_info": [
            {"family": "inet", "local": "192.168.1.42", "prefixlen": 24},
            {"family": "inet6", "local": "fe80::1", "prefixlen": 64},
        ],
    },
    {
        "ifindex": 3,
        "ifname": "wlan0",
        "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
        "operstate": "UP",
        "addr_info": [{"family": "inet", "local": "192.168.100.1", "prefixlen": 24}],
    },
]


class TestParseDefaultRoute:
    def test_extracts_the_wan_interface_and_upstream_gateway(self) -> None:
        interface, gateway = parse_default_route(_ROUTES)
        assert interface == "eth0"
        assert gateway == ipaddress.IPv4Address("192.168.1.1")

    def test_ignores_an_ipv6_default_route(self) -> None:
        """ADDENDUM.md A5: v1 is IPv4-only, so a v6 default route is not an answer."""
        routes = [
            {"dst": "default", "gateway": "fe80::1", "dev": "eth0"},
            {"dst": "default", "gateway": "10.0.0.1", "dev": "eth1"},
        ]
        interface, gateway = parse_default_route(routes)
        assert (interface, gateway) == ("eth1", ipaddress.IPv4Address("10.0.0.1"))

    def test_no_default_route_is_an_actionable_error(self) -> None:
        """The operator needs to be told which config fields to fill in, not just that it failed."""
        with pytest.raises(DiscoveryError) as excinfo:
            parse_default_route([])
        message = str(excinfo.value)
        assert "wan_interface" in message
        assert "upstream_gateway" in message

    def test_a_route_with_no_gateway_is_skipped(self) -> None:
        """A link-scope default (no `gateway` key) gives no upstream address."""
        with pytest.raises(DiscoveryError):
            parse_default_route([{"dst": "default", "dev": "eth0"}])


class TestParseAddresses:
    def test_extracts_ipv4_addresses_with_their_prefix(self) -> None:
        found = parse_addresses(_ADDRESSES)
        assert [(a.interface, str(a.address), a.prefix_length) for a in found] == [
            ("eth0", "192.168.1.42", 24),
            ("wlan0", "192.168.100.1", 24),
        ]

    def test_loopback_and_ipv6_are_excluded(self) -> None:
        found = parse_addresses(_ADDRESSES)
        assert all(a.interface != "lo" for a in found)
        assert all(isinstance(a.address, ipaddress.IPv4Address) for a in found)

    def test_a_down_interface_is_excluded(self) -> None:
        """An interface with no carrier cannot be the LAN pirewall is protecting."""
        payload = [
            {
                "ifname": "eth1",
                "flags": ["BROADCAST", "MULTICAST"],
                "addr_info": [{"family": "inet", "local": "10.9.9.9", "prefixlen": 24}],
            }
        ]
        assert parse_addresses(payload) == []

    def test_network_is_derived_from_the_address_and_prefix(self) -> None:
        address = InterfaceAddress("wlan0", ipaddress.IPv4Address("192.168.100.1"), 24)
        assert address.network == ipaddress.IPv4Network("192.168.100.0/24")


class TestParseNeighbours:
    def test_returns_reachable_hosts_sorted_and_deduplicated(self) -> None:
        payload = [
            {"dst": "192.168.100.20", "state": ["STALE"]},
            {"dst": "192.168.100.10", "state": ["REACHABLE"]},
            {"dst": "192.168.100.10", "state": ["DELAY"]},
        ]
        assert parse_neighbours(payload) == [
            ipaddress.IPv4Address("192.168.100.10"),
            ipaddress.IPv4Address("192.168.100.20"),
        ]

    def test_unreachable_entries_are_not_offered_as_candidates(self) -> None:
        payload = [
            {"dst": "192.168.100.30", "state": ["FAILED"]},
            {"dst": "192.168.100.31", "state": ["INCOMPLETE"]},
        ]
        assert parse_neighbours(payload) == []

    def test_ipv6_neighbours_are_ignored(self) -> None:
        assert parse_neighbours([{"dst": "fe80::abcd", "state": ["REACHABLE"]}]) == []


class TestChooseLanInterface:
    def test_picks_the_interface_that_is_not_the_wan(self) -> None:
        lan, warnings = choose_lan_interface(parse_addresses(_ADDRESSES), "eth0")
        assert lan.interface == "wlan0"
        assert lan.address == ipaddress.IPv4Address("192.168.100.1")
        assert lan.network == ipaddress.IPv4Network("192.168.100.0/24")
        assert warnings == ()

    def test_an_ambiguous_choice_warns_rather_than_deciding_silently(self) -> None:
        """Capturing on the wrong side of the firewall is not something to guess at."""
        addresses = [
            InterfaceAddress("eth0", ipaddress.IPv4Address("192.168.1.42"), 24),
            InterfaceAddress("eth1", ipaddress.IPv4Address("10.0.0.1"), 24),
            InterfaceAddress("wlan0", ipaddress.IPv4Address("192.168.100.1"), 24),
        ]
        lan, warnings = choose_lan_interface(addresses, "eth0")
        assert lan.interface == "eth1"  # deterministic: first by name
        assert len(warnings) == 1
        assert "eth1, wlan0" in warnings[0]

    def test_a_wan_only_machine_is_an_actionable_error(self) -> None:
        addresses = [InterfaceAddress("eth0", ipaddress.IPv4Address("192.168.1.42"), 24)]
        with pytest.raises(DiscoveryError) as excinfo:
            choose_lan_interface(addresses, "eth0")
        assert "lan_interface" in str(excinfo.value)
