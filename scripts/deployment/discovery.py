"""Read the Pi's live network layout from `ip`, so setup doesn't depend on guesswork.

Most of what `config/local_config.toml` needs is already true of the
running machine and can simply be *observed*: which interface carries the
default route (the WAN), which one faces the protected LAN, that LAN's
CIDR, the Pi's own address on it, and the upstream gateway. Asking an
operator to retype all of that invites exactly the class of error that
matters most here — `network.pirewall_lan_ip` and
`network.upstream_gateway` are the two addresses safety validation refuses
to ever block (spec §24), so a typo in either silently removes the
protection that stops pirewall locking you out of your own network.

**What is deliberately never auto-detected: `admin.admin_pc_ip`.** It is a
policy decision, not an observation — "which machine on this LAN is
allowed to administer the firewall". The neighbour table can only say which
hosts have recently talked to the Pi, which is a different question, and
picking the wrong one either locks the operator out or grants the wrong
host administrative access. So `admin_pc_candidates` gathers *candidates*
for a human to choose between, and nothing here ever chooses.

Scope discipline, two ways:

* **Read-only.** Every command is `ip ... show`. Nothing here configures an
  interface, adds an address, or touches `/etc` — spec §21 and `CLAUDE.md`
  ("never auto-modify network configuration"). The output is a set of
  suggested config *values*; a human confirms them and a separate step
  writes the file.
* **Outside the `pirewall` package.** The audit records "no `subprocess`
  usage outside `NftablesBackend`" as a security property of the runtime.
  This is operator tooling that runs at setup time, not runtime code, so it
  lives in `scripts/` and that property stays exactly true.

Every command is a fixed argument list with `shell=False`; the only
variable ever passed is an interface name that came from `ip` itself, never
from user input.

`ip -j` (JSON output) is required — it has been in iproute2 since 4.x and
is present on Raspberry Pi OS Bookworm. Parsing the human-readable output
instead would be fragile, so an `ip` without `-j` is reported as an error
telling the operator to fill the values in by hand.
"""

import ipaddress
import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, cast

_IP_BINARY = "ip"
_COMMAND_TIMEOUT_SECONDS = 10.0

# Neighbour states worth offering as an Admin PC candidate. FAILED and
# INCOMPLETE mean the Pi could not reach the host at all; NOARP/PERMANENT
# entries are usually infrastructure rather than a workstation.
_USABLE_NEIGHBOUR_STATES = frozenset({"REACHABLE", "STALE", "DELAY", "PROBE"})


class DiscoveryError(Exception):
    """Raised when the live network layout cannot be read.

    Not a `PirewallError` subclass: this is setup-time operator tooling
    outside the `pirewall` package, and nothing in the runtime ever catches
    it. The message is always actionable — it tells the operator which
    value to fill in by hand.
    """


@dataclass(frozen=True, slots=True)
class InterfaceAddress:
    """One IPv4 address on one interface, with the prefix length it was configured with."""

    interface: str
    address: ipaddress.IPv4Address
    prefix_length: int

    @property
    def network(self) -> ipaddress.IPv4Network:
        """The CIDR this address sits in — `config.network.protected_network` for the LAN side."""
        # IPv4Network, not ip_network: `address` is already an IPv4Address,
        # so the family is fixed (ADDENDUM.md A5 keeps v1 IPv4-only).
        return ipaddress.IPv4Network(f"{self.address}/{self.prefix_length}", strict=False)


@dataclass(frozen=True, slots=True)
class DiscoveredNetwork:
    """Everything about the live layout that setup can fill in without asking.

    `admin_pc_candidates` is explicitly *not* an answer — see the module
    docstring. `warnings` carries anything ambiguous that a human should
    look at before accepting the result (e.g. several plausible LAN
    interfaces).
    """

    wan_interface: str
    lan_interface: str
    upstream_gateway: ipaddress.IPv4Address
    pirewall_lan_ip: ipaddress.IPv4Address
    protected_network: ipaddress.IPv4Network
    admin_pc_candidates: tuple[ipaddress.IPv4Address, ...] = ()
    warnings: tuple[str, ...] = ()


def _run_ip(*arguments: str) -> Any:
    """Run `ip -j <arguments>` and parse its JSON output.

    `Any`: this is the boundary where untyped external JSON enters. Every
    caller immediately narrows it through the `_parse_*` functions below,
    which are what the tests exercise.
    """
    if shutil.which(_IP_BINARY) is None:
        raise DiscoveryError(
            "the `ip` command was not found. Network auto-detection needs iproute2; "
            "install it, or fill the [network] and [capture] sections of your config in by hand."
        )
    command = [_IP_BINARY, "-j", *arguments]
    try:
        # Fixed argv, `shell=False` (the default). The only variable that
        # ever reaches this list is an interface name that came from `ip`
        # itself — never operator input (spec §20, CLAUDE.md).
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=_COMMAND_TIMEOUT_SECONDS,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise DiscoveryError(
            f"`{' '.join(command)}` failed ({exc.returncode}): {exc.stderr.strip()}"
        ) from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DiscoveryError(f"could not run `{' '.join(command)}`: {exc}") from exc

    try:
        return json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise DiscoveryError(
            f"`{' '.join(command)}` did not return JSON, so this iproute2 is too old for `ip -j`. "
            "Fill the [network] and [capture] sections of your config in by hand."
        ) from exc


def _as_object(value: object) -> dict[str, Any] | None:
    """Narrow one JSON-decoded value to a string-keyed object, or `None`.

    Mirrors `pirewall.firewall.backend.nftables._as_dict`: a bare
    `isinstance(value, dict)` still leaves pyright unable to infer key and
    value types, so the one explicit cast every JSON parser here needs is
    centralized. Every JSON object's keys are strings by construction.
    """
    return cast("dict[str, Any]", value) if isinstance(value, dict) else None


def _as_array(value: object) -> list[Any] | None:
    """Narrow one JSON-decoded value to an array, or `None`."""
    return cast("list[Any]", value) if isinstance(value, list) else None


def _string_set(value: object) -> set[str]:
    """The string members of a JSON array (`flags`, `state`), ignoring anything else."""
    items = _as_array(value)
    return {item for item in items if isinstance(item, str)} if items is not None else set()


def parse_default_route(payload: Any) -> tuple[str, ipaddress.IPv4Address]:
    """Extract `(interface, gateway)` from `ip -j route show default` output.

    Raises `DiscoveryError` if there is no usable default route — which
    means the Pi has no upstream, and `network.wan_interface` /
    `network.upstream_gateway` cannot be inferred.
    """
    routes = _as_array(payload)
    if routes is None:
        raise DiscoveryError("unexpected `ip -j route` output: expected a list of routes")
    for entry in routes:
        route = _as_object(entry)
        if route is None:
            continue
        device = route.get("dev")
        gateway = route.get("gateway")
        if not isinstance(device, str) or not isinstance(gateway, str):
            continue
        try:
            return device, ipaddress.IPv4Address(gateway)
        except ValueError:
            continue  # an IPv6 default route: pirewall is IPv4-only in v1 (ADDENDUM.md A5)
    raise DiscoveryError(
        "no IPv4 default route found, so the WAN interface and upstream gateway cannot be "
        "detected. Connect the Pi's uplink first, or set network.wan_interface and "
        "network.upstream_gateway by hand."
    )


def parse_addresses(payload: Any) -> list[InterfaceAddress]:
    """Extract every usable IPv4 interface address from `ip -j addr show` output.

    Skips loopback and any interface that is not up: an interface with no
    carrier cannot be the LAN pirewall is protecting.
    """
    links = _as_array(payload)
    if links is None:
        raise DiscoveryError("unexpected `ip -j addr` output: expected a list of interfaces")
    found: list[InterfaceAddress] = []
    for entry in links:
        link = _as_object(entry)
        if link is None:
            continue
        name = link.get("ifname")
        if not isinstance(name, str) or name == "lo":
            continue
        flags = _string_set(link.get("flags"))
        if "LOOPBACK" in flags or "UP" not in flags:
            continue
        for address_entry in _as_array(link.get("addr_info")) or []:
            info = _as_object(address_entry)
            if info is None or info.get("family") != "inet":
                continue  # ADDENDUM.md A5: IPv4 only
            local = info.get("local")
            prefix = info.get("prefixlen")
            if not isinstance(local, str) or not isinstance(prefix, int):
                continue
            try:
                found.append(InterfaceAddress(name, ipaddress.IPv4Address(local), prefix))
            except ValueError:
                continue
    return found


def parse_neighbours(payload: Any) -> list[ipaddress.IPv4Address]:
    """Extract reachable IPv4 neighbours from `ip -j neigh show dev <iface>` output.

    These are Admin PC *candidates* only — hosts that have recently talked
    to the Pi. Being in this list says nothing about whether a host should
    be allowed to administer the firewall.
    """
    entries = _as_array(payload)
    if entries is None:
        return []
    neighbours: list[ipaddress.IPv4Address] = []
    for entry in entries:
        neighbour = _as_object(entry)
        if neighbour is None:
            continue
        destination = neighbour.get("dst")
        if not isinstance(destination, str):
            continue
        if not _string_set(neighbour.get("state")) & _USABLE_NEIGHBOUR_STATES:
            continue
        try:
            neighbours.append(ipaddress.IPv4Address(destination))
        except ValueError:
            continue  # IPv6 neighbour
    return sorted(set(neighbours))


def choose_lan_interface(
    addresses: list[InterfaceAddress], wan_interface: str
) -> tuple[InterfaceAddress, tuple[str, ...]]:
    """Pick the LAN-facing interface: the one that is up, addressed, and isn't the WAN.

    Returns the chosen address plus any warnings. With more than one
    candidate this picks the first by interface name for determinism and
    *warns* — it does not silently decide, because getting this wrong means
    capturing on the wrong side of the firewall.
    """
    candidates = sorted(
        (address for address in addresses if address.interface != wan_interface),
        key=lambda address: address.interface,
    )
    if not candidates:
        raise DiscoveryError(
            f"no LAN-facing interface found: the only interface with an IPv4 address is the WAN "
            f"({wan_interface}). pirewall needs a second, LAN-side interface — bring up the "
            "hotspot or second NIC first, or set network.lan_interface by hand."
        )
    warnings: list[str] = []
    if len(candidates) > 1:
        names = ", ".join(sorted({address.interface for address in candidates}))
        warnings.append(
            f"more than one possible LAN interface ({names}); chose {candidates[0].interface}. "
            "Confirm this is the interface facing the network you want protected."
        )
    return candidates[0], tuple(warnings)


def discover() -> DiscoveredNetwork:
    """Read the live network layout. Raises `DiscoveryError` with an actionable message on failure."""
    wan_interface, upstream_gateway = parse_default_route(_run_ip("route", "show", "default"))
    addresses = parse_addresses(_run_ip("addr", "show"))
    lan, warnings = choose_lan_interface(addresses, wan_interface)

    candidates = [
        neighbour
        for neighbour in parse_neighbours(_run_ip("neigh", "show", "dev", lan.interface))
        if neighbour != lan.address and neighbour in lan.network
    ]
    return DiscoveredNetwork(
        wan_interface=wan_interface,
        lan_interface=lan.interface,
        upstream_gateway=upstream_gateway,
        pirewall_lan_ip=lan.address,
        protected_network=lan.network,
        admin_pc_candidates=tuple(candidates),
        warnings=warnings,
    )
