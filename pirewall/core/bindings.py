"""IP<->MAC bindings: the dnsmasq lease parser and the in-memory `BindingTable` (ADDENDUM_4.md D3).

`LeaseBindingTable` implements the frozen `pirewall.core.binding_table.BindingTable`
Protocol. It merges two sources, and a static entry always wins:

* **`[[antispoof.static]]`**, fixed for the life of the process: devices
  with a configured address and no DHCP lease.
* **The NetworkManager dnsmasq lease file**, re-read by the lease-sync
  thread (`pirewall.runtime.lease_sync`). `parse_leases` reads it.

**The lease file is client-controlled input.** Its hostname and client-id
fields are whatever a DHCP client chose to send. `parse_leases` therefore:

* matches each line against one strict pattern (`expiry MAC IPv4 field
  field`, five single-space-separated fields, nothing else), so a line is
  either a well-formed IPv4 lease or ignored;
* never looks inside the hostname or client-id fields, and never puts any
  part of a line into a log message or an exception, only counts;
* caps the file size and the line length, so a hostile file cannot cost
  more than a bounded read.

A line that is not a usable lease (malformed, IPv6, an infinite lease, an
address outside the protected network, a group MAC, a duplicate) is
counted in `LeaseParse.ignored` by reason and otherwise dropped.

Pure data and a lock. This module holds no nft handle: turning a
`BindingChange` into kernel elements is `FirewallManager.sync_bindings`,
the only writer of the binding sets (D1).
"""

import re
import threading
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network, IPv6Address
from typing import Final

from pydantic import TypeAdapter, ValidationError

from pirewall.config.models import StaticBindingEntry
from pirewall.core.enums import BindingSource
from pirewall.core.models.common import MacAddress, UnicastMacAddress
from pirewall.core.models.identity import Binding, BindingChange

MAX_LEASE_FILE_BYTES: Final = 1024 * 1024
"""A lease file larger than this is refused outright (about 10,000 leases; a Pi serves dozens)."""

_MAX_LINE_CHARS: Final = 512
# Five fields separated by single spaces, exactly as dnsmasq writes them
# (`lease_update_file`): expiry, MAC, IPv4, hostname or `*`, client-id or
# `*`. The last two are matched only as "one or more non-space characters",
# never captured. Expiry is at most 11 digits, which keeps it a datetime
# (`datetime.fromtimestamp` refuses absurd values).
_LEASE_LINE: Final = re.compile(
    r"(?P<expiry>[0-9]{1,11}) "
    r"(?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}) "
    r"(?P<ip>[0-9]{1,3}(?:\.[0-9]{1,3}){3}) "
    r"[^ ]+ [^ ]+"
)
_UNICAST_MAC: Final[TypeAdapter[str]] = TypeAdapter(UnicastMacAddress)


class IgnoredLease(StrEnum):
    """Why one lease-file line did not become a binding."""

    MALFORMED = "malformed"
    TOO_LONG = "too_long"
    IPV6 = "ipv6"
    INFINITE = "infinite"
    OUTSIDE_NETWORK = "outside_network"
    NOT_UNICAST = "not_unicast"
    DUPLICATE = "duplicate"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class LeaseParse:
    """What `parse_leases` made of a lease file: the usable bindings, and counts of the rest."""

    bindings: tuple[Binding, ...]
    ignored: Mapping[IgnoredLease, int] = field(default_factory=dict[IgnoredLease, int])

    @property
    def ignored_total(self) -> int:
        """How many lines were dropped, for any reason."""
        return sum(self.ignored.values())


def parse_leases(text: str, protected_network: IPv4Network) -> LeaseParse:
    """Parse a dnsmasq lease file into lease `Binding`s. Never raises on content; see the module docstring.

    * An IPv6 lease (the `duid` line and every line whose address is not
      IPv4) is ignored: v1/v2 enforcement is IPv4-only (ADDENDUM.md A5).
    * Expiry `0` is dnsmasq's infinite lease. It is ignored, not bound
      forever: a binding needs an expiry to become a kernel timeout, and a
      device with a permanent address belongs in `[[antispoof.static]]`.
    * The same `(IP, MAC)` pair twice keeps the later expiry.
    * One IP leased to two different MACs is ambiguous, so neither binds:
      an unbound device is metered, while a wrong binding would drop the
      real owner (critique_safety_eval.md A6). One MAC with two IPs is
      allowed (two client-ids on one interface); both bind.
    """
    ignored: Counter[IgnoredLease] = Counter()
    by_pair: dict[tuple[IPv4Address, str], Binding] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        if len(line) > _MAX_LINE_CHARS:
            ignored[IgnoredLease.TOO_LONG] += 1
            continue
        binding, reason = _parse_line(line, protected_network)
        if binding is None:
            assert reason is not None
            ignored[reason] += 1
            continue
        pair = (binding.ip, binding.mac)
        previous = by_pair.get(pair)
        if previous is not None:
            ignored[IgnoredLease.DUPLICATE] += 1
            if _expiry(previous) >= _expiry(binding):
                continue
        by_pair[pair] = binding
    macs_by_ip: dict[IPv4Address, set[str]] = {}
    for ip, mac in by_pair:
        macs_by_ip.setdefault(ip, set()).add(mac)
    bindings: list[Binding] = []
    for (ip, _), binding in sorted(by_pair.items()):
        if len(macs_by_ip[ip]) > 1:
            ignored[IgnoredLease.CONFLICT] += 1
            continue
        bindings.append(binding)
    return LeaseParse(bindings=tuple(bindings), ignored=dict(ignored))


def _parse_line(line: str, protected_network: IPv4Network) -> tuple[Binding | None, IgnoredLease | None]:
    match = _LEASE_LINE.fullmatch(line)
    if match is None:
        # The IPv6 section never matches: its `duid` line, and lease lines
        # with an IAID where the MAC would be and an IPv6 address after it.
        fields = line.split(" ")
        is_ipv6 = fields[0] == "duid" or (len(fields) == 5 and _is_ipv6(fields[2]))
        return None, IgnoredLease.IPV6 if is_ipv6 else IgnoredLease.MALFORMED
    try:
        ip = IPv4Address(match["ip"])
    except ValueError:
        return None, IgnoredLease.MALFORMED
    expiry = int(match["expiry"])
    if expiry == 0:
        return None, IgnoredLease.INFINITE
    if ip not in protected_network:
        return None, IgnoredLease.OUTSIDE_NETWORK
    try:
        mac = _UNICAST_MAC.validate_python(match["mac"])
    except ValidationError:
        return None, IgnoredLease.NOT_UNICAST
    try:
        expires_at = datetime.fromtimestamp(expiry, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None, IgnoredLease.MALFORMED
    return Binding(ip=ip, mac=mac, source=BindingSource.LEASE, expires_at=expires_at), None


def _is_ipv6(field: str) -> bool:
    try:
        IPv6Address(field)
    except ValueError:
        return False
    return True


def _expiry(binding: Binding) -> datetime:
    assert binding.expires_at is not None  # lease bindings always carry one
    return binding.expires_at


def static_bindings(entries: Iterable[StaticBindingEntry]) -> tuple[Binding, ...]:
    """`[[antispoof.static]]` entries as STATIC `Binding`s (no expiry)."""
    return tuple(
        Binding(ip=entry.ip, mac=entry.mac, source=BindingSource.STATIC) for entry in entries
    )


class LeaseBindingTable:
    """The `BindingTable` implementation: static entries plus the current lease set. Thread-safe.

    The lease-sync thread writes (`apply_leases`); the generator, the
    validator path, the portal and RPC read. Every method takes one short
    internal lock and never calls out while holding it, so a reader is
    never stuck behind nft I/O or core's RPC lock.
    """

    def __init__(self, static: Iterable[Binding] = ()) -> None:
        """`static` must be STATIC bindings with distinct IPs and MACs (config validation guarantees it)."""
        self._lock = threading.Lock()
        self._static: dict[IPv4Address, Binding] = {}
        self._static_macs: set[str] = set()
        for binding in static:
            if binding.source is not BindingSource.STATIC:
                raise ValueError("LeaseBindingTable(static=...) takes STATIC bindings only")
            self._static[binding.ip] = binding
            self._static_macs.add(binding.mac)
        self._leases: dict[IPv4Address, Binding] = {}

    def resolve_mac(self, ip: IPv4Address) -> MacAddress | None:
        """The MAC bound to `ip` (static first), or None."""
        with self._lock:
            binding = self._static.get(ip) or self._leases.get(ip)
        return None if binding is None else binding.mac

    def resolve_ip(self, mac: MacAddress) -> IPv4Address | None:
        """The IPv4 address bound to `mac`: its static entry, else its latest-expiring lease, or None."""
        with self._lock:
            for binding in self._static.values():
                if binding.mac == mac:
                    return binding.ip
            leases = [binding for binding in self._leases.values() if binding.mac == mac]
        if not leases:
            return None
        return max(leases, key=_expiry).ip

    def snapshot(self) -> tuple[Binding, ...]:
        """Every live binding, static first, each group in IP order. An immutable copy."""
        with self._lock:
            static = sorted(self._static.values(), key=lambda binding: binding.ip)
            leases = sorted(self._leases.values(), key=lambda binding: binding.ip)
        return (*static, *leases)

    def apply_leases(self, leases: Sequence[Binding], now: datetime) -> BindingChange:
        """Replace the lease bindings with `leases` (the full current set) and return what changed.

        Follows the Protocol: an entry not expiring after `now` is absent;
        a lease naming a static IP or MAC is ignored; a moved or renewed pair
        is the old binding in `removed` plus the new one in `added`. A
        renewal counts as a change because the kernel element's timeout has
        to move with it, and nft only sets a timeout when an element is added.
        If `leases` holds two bindings for one IP, the later expiry wins.
        """
        wanted: dict[IPv4Address, Binding] = {}
        for binding in leases:
            if binding.source is not BindingSource.LEASE:
                raise ValueError("apply_leases takes LEASE bindings only")
            if _expiry(binding) <= now:
                continue
            if binding.ip in self._static or binding.mac in self._static_macs:
                continue
            current = wanted.get(binding.ip)
            if current is None or _expiry(binding) > _expiry(current):
                wanted[binding.ip] = binding
        with self._lock:
            previous = self._leases
            self._leases = wanted
        removed = [binding for ip, binding in previous.items() if wanted.get(ip) != binding]
        added = [binding for ip, binding in wanted.items() if previous.get(ip) != binding]
        return BindingChange(
            removed=tuple(sorted(removed, key=lambda binding: binding.ip)),
            added=tuple(sorted(added, key=lambda binding: binding.ip)),
        )
