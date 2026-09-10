"""Startup cross-check between configured network addresses and the kernel's live view.

`KNOWN_ISSUES.md` #16: moving the Pi to a new uplink (or a new Admin PC
segment) leaves `config/local_config.toml`'s addresses pointing at a
network the Pi is no longer on, and nothing notices — `--check-config`
accepts any syntactically valid address, and the values it gets wrong
(`network.upstream_gateway`, `network.pirewall_lan_ip`,
`network.protected_network`, `admin.admin_pc_ip`,
`integration.wazuh_host`/`netdata_host`) are exactly the ones
`pirewall.firewall.validator._validate_safety` trusts to protect the Pi's
own uplink and management access (spec §24). A stale gateway is worse than
a missing one: it protects an address nobody uses any more while leaving
the real gateway unprotected.

This module only *observes* — like `scripts/deployment/discovery.py`, which
it deliberately does not import (that module is setup-time tooling outside
the `pirewall` package; this one runs on every `pirewall-core` startup).
Nothing here refuses to start on a mismatch, since the uplink can
legitimately be down at boot — `pirewall.runtime.core.CoreDaemon.start()`
calls `check_network_drift` and turns each `DriftWarning` into a
`SYSTEM_WARNING` `SecurityEvent` instead.

Stdlib-only and read-only: `/proc/net/route` for the live default route and
`SIOCGIFADDR`/`SIOCGIFNETMASK` ioctls for interface addresses, no
`subprocess`. `scripts/deployment/discovery.py`'s docstring notes "no
subprocess usage outside NftablesBackend" as a property of the runtime;
using ioctls and `/proc` here instead of shelling out to `ip` keeps that
property true for this check too.
"""

from __future__ import annotations

import fcntl
import socket
import struct
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from pirewall.config.models import PirewallConfig

_SIOCGIFADDR = 0x8915
_SIOCGIFNETMASK = 0x891B
_PROC_NET_ROUTE = Path("/proc/net/route")
_SYS_CLASS_NET = Path("/sys/class/net")


@dataclass(frozen=True, slots=True)
class DriftWarning:
    """One configured value that no longer matches the kernel's live view."""

    field: str
    detail: str


def _interface_ipv4(ifname: str, request: int) -> IPv4Address | None:
    """One `SIOCGIFADDR`/`SIOCGIFNETMASK` ioctl result, or `None` if the interface has no IPv4 address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            packed = fcntl.ioctl(
                sock.fileno(),
                request,
                struct.pack("256s", ifname[:15].encode("utf-8")),
            )
        return IPv4Address(socket.inet_ntoa(packed[20:24]))
    except OSError:
        return None


def _default_route() -> tuple[str, IPv4Address] | None:
    """`(interface, gateway)` for the live IPv4 default route, parsed from `/proc/net/route`.

    Addresses there are hex, in host byte order (little-endian on the
    arm64/x86 hosts this runs on) — `struct.pack("<L", ...)` undoes that
    before handing the bytes to `inet_ntoa`, which expects network byte
    order.
    """
    try:
        lines = _PROC_NET_ROUTE.read_text(encoding="ascii").splitlines()
    except OSError:
        return None
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 3:
            continue
        iface, destination, gateway = fields[0], fields[1], fields[2]
        if destination != "00000000":
            continue
        try:
            gateway_ip = IPv4Address(socket.inet_ntoa(struct.pack("<L", int(gateway, 16))))
        except ValueError:
            continue
        return iface, gateway_ip
    return None


def _local_ipv4_networks() -> list[IPv4Network]:
    """Every subnet this host has an address on, across all interfaces (not just WAN/LAN)."""
    networks: list[IPv4Network] = []
    try:
        interfaces = [entry.name for entry in _SYS_CLASS_NET.iterdir()]
    except OSError:
        return networks
    for ifname in interfaces:
        if ifname == "lo":
            continue
        address = _interface_ipv4(ifname, _SIOCGIFADDR)
        netmask = _interface_ipv4(ifname, _SIOCGIFNETMASK)
        if address is None or netmask is None:
            continue
        networks.append(IPv4Network(f"{address}/{netmask}", strict=False))
    return networks


def _address_is_stale(address: IPv4Address, local_networks: list[IPv4Network]) -> bool:
    """`True` if `address` sits on none of this host's live subnets — likely stale after a network move."""
    return not any(address in network for network in local_networks)


def check_network_drift(config: PirewallConfig) -> list[DriftWarning]:
    """Compare `config`'s network addresses against the kernel's live view.

    Never raises, never blocks startup.
    """
    warnings: list[DriftWarning] = []

    route = _default_route()
    if route is None:
        warnings.append(
            DriftWarning(
                "network.upstream_gateway",
                "no IPv4 default route found; cannot verify against the live uplink",
            )
        )
    else:
        live_interface, live_gateway = route
        if live_interface != config.network.wan_interface:
            warnings.append(
                DriftWarning(
                    "network.wan_interface",
                    f"configured as {config.network.wan_interface!r} but the kernel's "
                    f"default route is via {live_interface!r}",
                )
            )
        if live_gateway != config.network.upstream_gateway:
            warnings.append(
                DriftWarning(
                    "network.upstream_gateway",
                    f"configured as {config.network.upstream_gateway} but the kernel's "
                    f"live default gateway is {live_gateway}",
                )
            )

    lan_address = _interface_ipv4(config.network.lan_interface, _SIOCGIFADDR)
    lan_netmask = _interface_ipv4(config.network.lan_interface, _SIOCGIFNETMASK)
    if lan_address is None:
        warnings.append(
            DriftWarning(
                "network.lan_interface",
                f"{config.network.lan_interface!r} has no IPv4 address; is it up?",
            )
        )
    else:
        if lan_address != config.network.pirewall_lan_ip:
            warnings.append(
                DriftWarning(
                    "network.pirewall_lan_ip",
                    f"configured as {config.network.pirewall_lan_ip} but "
                    f"{config.network.lan_interface} is actually {lan_address}",
                )
            )
        if lan_netmask is not None:
            live_network = IPv4Network(f"{lan_address}/{lan_netmask}", strict=False)
            if live_network != config.network.protected_network:
                warnings.append(
                    DriftWarning(
                        "network.protected_network",
                        f"configured as {config.network.protected_network} but "
                        f"{config.network.lan_interface}'s live network is {live_network}",
                    )
                )

    local_networks = _local_ipv4_networks()
    stale_candidates: list[tuple[str, IPv4Address | None]] = [
        ("admin.admin_pc_ip", config.admin.admin_pc_ip),
    ]
    if config.integration.wazuh_enabled and config.integration.wazuh_host is not None:
        stale_candidates.append(
            ("integration.wazuh_host", _parse_ipv4_or_none(config.integration.wazuh_host))
        )
    if config.integration.netdata_enabled and config.integration.netdata_host is not None:
        stale_candidates.append(
            ("integration.netdata_host", _parse_ipv4_or_none(config.integration.netdata_host))
        )

    for field_name, address in stale_candidates:
        if address is None:
            continue  # a hostname, not a literal IPv4 address — nothing to compare against a subnet
        if local_networks and _address_is_stale(address, local_networks):
            warnings.append(
                DriftWarning(
                    field_name,
                    f"{address} is not on any subnet this host currently has an address on; "
                    "likely stale after a network move",
                )
            )

    return warnings


def _parse_ipv4_or_none(value: str) -> IPv4Address | None:
    try:
        return IPv4Address(value)
    except ValueError:
        return None
