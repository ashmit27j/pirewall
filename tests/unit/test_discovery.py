"""`scripts.deployment.discovery` — parsing the live network layout from `ip -j` output.

Every test here works on captured JSON rather than a live `ip` invocation,
so the parsing is exercised on any machine. The fixtures are real
`ip -j route show default` / `ip -j addr show` / `ip -j neigh show` shapes
from a Raspberry Pi OS Bookworm gateway: `_ROUTES`/`_ADDRESSES` for a wired
uplink (eth0 WAN, wlan0 hotspot LAN), and `_WIRELESS_ROUTES`/
`_WIRELESS_ADDRESSES` for the all-wireless layout of `docs/DEPLOYMENT.md`
§4 — the onboard radio associated to an upstream Wi-Fi network as WAN, a
USB RTL8188EUS dongle running an AP as LAN. Both wlan-named, which is the
case no other fixture covered.

Discovery is deliberately interface-*name* agnostic: the WAN is whichever
device carries the IPv4 default route and the LAN is the first addressed
device that isn't it, with ties broken alphabetically for determinism.
Nothing anywhere reads `eth`/`wlan` out of a name, and `TestWirelessLayout`
is what holds that true.

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
    discover,
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

# The all-wireless deployment (docs/DEPLOYMENT.md §4): wlan0 is the onboard
# brcmfmac radio associated as a *client* to the upstream Wi-Fi network, so
# it carries the default route and is the WAN. wlan1 is the RTL8188EUS USB
# dongle running as an access point, so it holds `pirewall_lan_ip` and is
# the LAN. Both names start with "wlan" — the point of the fixture.
_WIRELESS_ROUTES = [
    {
        "dst": "default",
        "gateway": "192.168.1.1",
        "dev": "wlan0",
        "protocol": "dhcp",
        "prefsrc": "192.168.1.42",
        "metric": 600,
    }
]

_WIRELESS_ADDRESSES = [
    {
        "ifindex": 1,
        "ifname": "lo",
        "flags": ["LOOPBACK", "UP", "LOWER_UP"],
        "operstate": "UNKNOWN",
        "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}],
    },
    {
        "ifindex": 2,
        "ifname": "wlan0",
        "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
        "operstate": "UP",
        "addr_info": [
            {"family": "inet", "local": "192.168.1.42", "prefixlen": 24},
            {"family": "inet6", "local": "fe80::2", "prefixlen": 64},
        ],
    },
    {
        "ifindex": 3,
        "ifname": "wlan1",
        "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
        "operstate": "UP",
        "addr_info": [{"family": "inet", "local": "192.168.100.1", "prefixlen": 24}],
    },
]

_WIRELESS_NEIGHBOURS = [
    {"dst": "192.168.100.10", "state": ["REACHABLE"]},
    {"dst": "192.168.100.23", "state": ["STALE"]},
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


class TestWirelessLayout:
    """The all-wireless deployment: wlan-named WAN *and* a different wlan-named LAN.

    `docs/DEPLOYMENT.md` §4 documents the onboard Pi radio as a Wi-Fi client
    (WAN) and an RTL8188EUS USB dongle as an access point (LAN). No other
    fixture in this file has a wlan-named WAN, so without these tests
    nothing would catch a name-based assumption creeping into discovery.
    Each assertion below is deliberately the same one made for the
    eth0/wlan0 fixture — "behaves identically" is the whole claim.
    """

    def test_a_wlan_named_interface_can_be_the_wan(self) -> None:
        interface, gateway = parse_default_route(_WIRELESS_ROUTES)
        assert interface == "wlan0"
        assert gateway == ipaddress.IPv4Address("192.168.1.1")

    def test_both_wireless_interfaces_are_parsed_with_their_prefixes(self) -> None:
        found = parse_addresses(_WIRELESS_ADDRESSES)
        assert [(a.interface, str(a.address), a.prefix_length) for a in found] == [
            ("wlan0", "192.168.1.42", 24),
            ("wlan1", "192.168.100.1", 24),
        ]

    def test_the_lan_is_the_ap_dongle_not_the_wan_radio(self) -> None:
        """The AP-mode dongle holds `pirewall_lan_ip`; the client-mode radio must not be chosen."""
        wan, _ = parse_default_route(_WIRELESS_ROUTES)
        lan, warnings = choose_lan_interface(parse_addresses(_WIRELESS_ADDRESSES), wan)
        assert lan.interface == "wlan1"
        assert lan.address == ipaddress.IPv4Address("192.168.100.1")
        assert lan.network == ipaddress.IPv4Network("192.168.100.0/24")
        assert warnings == ()

    def test_two_wlan_interfaces_are_no_more_ambiguous_than_two_eth_ones(self) -> None:
        """A third addressed interface warns here exactly as it does for eth0/eth1."""
        addresses = [
            InterfaceAddress("wlan0", ipaddress.IPv4Address("192.168.1.42"), 24),
            InterfaceAddress("wlan1", ipaddress.IPv4Address("192.168.100.1"), 24),
            InterfaceAddress("wlan2", ipaddress.IPv4Address("10.0.0.1"), 24),
        ]
        lan, warnings = choose_lan_interface(addresses, "wlan0")
        assert lan.interface == "wlan1"  # deterministic: first by name
        assert len(warnings) == 1
        assert "wlan1, wlan2" in warnings[0]

    def test_discover_end_to_end_on_the_all_wireless_layout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`discover()` itself, with `ip` stubbed — the values that reach the config file.

        `pirewall_lan_ip` and `upstream_gateway` are the two addresses safety
        validation refuses to ever block (spec §24), so this asserts them
        against a wireless layout rather than trusting that the parsers
        composing correctly for eth0/wlan0 implies it here.
        """
        seen: list[tuple[str, ...]] = []

        def fake_run_ip(*arguments: str) -> object:
            seen.append(arguments)
            if arguments[:2] == ("route", "show"):
                return _WIRELESS_ROUTES
            if arguments[:2] == ("addr", "show"):
                return _WIRELESS_ADDRESSES
            if arguments[:2] == ("neigh", "show"):
                return _WIRELESS_NEIGHBOURS
            raise AssertionError(f"unexpected ip invocation: {arguments}")

        monkeypatch.setattr("scripts.deployment.discovery._run_ip", fake_run_ip)
        result = discover()

        assert result.wan_interface == "wlan0"
        assert result.lan_interface == "wlan1"
        assert result.upstream_gateway == ipaddress.IPv4Address("192.168.1.1")
        assert result.pirewall_lan_ip == ipaddress.IPv4Address("192.168.100.1")
        assert result.protected_network == ipaddress.IPv4Network("192.168.100.0/24")
        assert result.admin_pc_candidates == (
            ipaddress.IPv4Address("192.168.100.10"),
            ipaddress.IPv4Address("192.168.100.23"),
        )
        assert result.warnings == ()
        # Neighbours are scanned on the AP interface, not the uplink radio:
        # the Admin PC lives on the protected LAN.
        assert ("neigh", "show", "dev", "wlan1") in seen
