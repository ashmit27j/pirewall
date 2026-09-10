"""`pirewall.core.network_drift` — KNOWN_ISSUES.md #16's startup cross-check.

Real ioctls and `/proc/net/route` aren't portable to a test host, so every
test monkeypatches the module's small stdlib-facing helpers
(`_default_route`, `_interface_ipv4`, `_local_ipv4_networks`) rather than
touching the kernel — the logic under test is the comparison, not the
syscalls.
"""

from collections.abc import Callable
from ipaddress import IPv4Address, IPv4Network

import pytest

from pirewall.core import network_drift
from tests.helpers.config import make_config

# Mirrors network_drift's own _SIOCGIFADDR/_SIOCGIFNETMASK request codes.
# Kept as local literals rather than importing the private constants, so
# these fakes don't reach across the module boundary they're replacing.
_ADDR = 0x8915
_MASK = 0x891B


def _fake_interface_ipv4(
    by_interface: dict[str, dict[int, IPv4Address]],
) -> Callable[[str, int], IPv4Address | None]:
    def lookup(ifname: str, request: int) -> IPv4Address | None:
        return by_interface.get(ifname, {}).get(request)

    return lookup


def test_no_warnings_when_everything_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network_drift, "_default_route", lambda: ("eth0", IPv4Address("192.168.1.1")))
    monkeypatch.setattr(
        network_drift,
        "_interface_ipv4",
        _fake_interface_ipv4(
            {"eth1": {_ADDR: IPv4Address("192.168.1.2"), _MASK: IPv4Address("255.255.255.0")}}
        ),
    )
    monkeypatch.setattr(network_drift, "_local_ipv4_networks", lambda: [IPv4Network("192.168.1.0/24")])

    config = make_config(admin={"admin_pc_ip": "192.168.1.50"})
    assert network_drift.check_network_drift(config) == []


def test_stale_upstream_gateway_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network_drift, "_default_route", lambda: ("eth0", IPv4Address("10.0.0.1")))
    monkeypatch.setattr(
        network_drift,
        "_interface_ipv4",
        _fake_interface_ipv4(
            {"eth1": {_ADDR: IPv4Address("192.168.1.2"), _MASK: IPv4Address("255.255.255.0")}}
        ),
    )
    monkeypatch.setattr(network_drift, "_local_ipv4_networks", lambda: [IPv4Network("192.168.1.0/24")])

    config = make_config()
    warnings = network_drift.check_network_drift(config)

    fields = {warning.field for warning in warnings}
    assert "network.upstream_gateway" in fields
    assert "network.wan_interface" not in fields  # interface still matches, only the gateway drifted


def test_wan_interface_mismatch_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network_drift, "_default_route", lambda: ("wlan1", IPv4Address("192.168.1.1")))
    monkeypatch.setattr(network_drift, "_interface_ipv4", _fake_interface_ipv4({}))
    monkeypatch.setattr(network_drift, "_local_ipv4_networks", list)

    config = make_config()  # wan_interface="eth0" in tests/helpers/config.py
    warnings = network_drift.check_network_drift(config)

    assert any(w.field == "network.wan_interface" for w in warnings)


def test_stale_lan_ip_and_protected_network_are_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network_drift, "_default_route", lambda: ("eth0", IPv4Address("192.168.1.1")))
    monkeypatch.setattr(
        network_drift,
        "_interface_ipv4",
        _fake_interface_ipv4(
            {"eth1": {_ADDR: IPv4Address("10.0.5.2"), _MASK: IPv4Address("255.255.255.0")}}
        ),
    )
    monkeypatch.setattr(network_drift, "_local_ipv4_networks", lambda: [IPv4Network("10.0.5.0/24")])

    config = make_config()  # pirewall_lan_ip=192.168.1.2, protected_network=192.168.1.0/24
    warnings = network_drift.check_network_drift(config)

    fields = {w.field for w in warnings}
    assert "network.pirewall_lan_ip" in fields
    assert "network.protected_network" in fields


def test_stale_admin_pc_ip_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network_drift, "_default_route", lambda: ("eth0", IPv4Address("192.168.1.1")))
    monkeypatch.setattr(
        network_drift,
        "_interface_ipv4",
        _fake_interface_ipv4(
            {"eth1": {_ADDR: IPv4Address("192.168.1.2"), _MASK: IPv4Address("255.255.255.0")}}
        ),
    )
    monkeypatch.setattr(network_drift, "_local_ipv4_networks", lambda: [IPv4Network("192.168.1.0/24")])

    config = make_config(admin={"admin_pc_ip": "10.9.9.9"})  # not on any live subnet
    warnings = network_drift.check_network_drift(config)

    assert any(w.field == "admin.admin_pc_ip" for w in warnings)


def test_disabled_integration_hosts_are_not_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network_drift, "_default_route", lambda: ("eth0", IPv4Address("192.168.1.1")))
    monkeypatch.setattr(
        network_drift,
        "_interface_ipv4",
        _fake_interface_ipv4(
            {"eth1": {_ADDR: IPv4Address("192.168.1.2"), _MASK: IPv4Address("255.255.255.0")}}
        ),
    )
    monkeypatch.setattr(network_drift, "_local_ipv4_networks", lambda: [IPv4Network("192.168.1.0/24")])

    config = make_config(
        integration={"wazuh_enabled": False, "wazuh_host": "10.9.9.9", "netdata_enabled": False}
    )
    warnings = network_drift.check_network_drift(config)

    assert not any(w.field.startswith("integration.") for w in warnings)


def test_hostname_integration_values_are_skipped_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hostname (not a literal IPv4) has no subnet to compare against — must not false-positive."""
    monkeypatch.setattr(network_drift, "_default_route", lambda: ("eth0", IPv4Address("192.168.1.1")))
    monkeypatch.setattr(
        network_drift,
        "_interface_ipv4",
        _fake_interface_ipv4(
            {"eth1": {_ADDR: IPv4Address("192.168.1.2"), _MASK: IPv4Address("255.255.255.0")}}
        ),
    )
    monkeypatch.setattr(network_drift, "_local_ipv4_networks", lambda: [IPv4Network("192.168.1.0/24")])

    config = make_config(integration={"wazuh_enabled": True, "wazuh_host": "siem.internal.example"})
    warnings = network_drift.check_network_drift(config)

    assert not any(w.field == "integration.wazuh_host" for w in warnings)


def test_missing_default_route_is_reported_without_crashing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network_drift, "_default_route", lambda: None)
    monkeypatch.setattr(
        network_drift,
        "_interface_ipv4",
        _fake_interface_ipv4(
            {"eth1": {_ADDR: IPv4Address("192.168.1.2"), _MASK: IPv4Address("255.255.255.0")}}
        ),
    )
    monkeypatch.setattr(network_drift, "_local_ipv4_networks", list)

    config = make_config()
    warnings = network_drift.check_network_drift(config)

    assert any(w.field == "network.upstream_gateway" for w in warnings)
