"""The addresses this machine itself holds, read from the kernel's own routing table.

Why this exists: the safety stage of `pirewall.firewall.validator` must
guarantee that no adaptive rule can ever lock out pirewall itself (spec
§24). Until now it could only check the addresses named in configuration —
`network.pirewall_lan_ip`, `network.upstream_gateway`, `admin.admin_pc_ip`.
That is strictly less than the truth: a Pi routing between a LAN AP, a
WAN uplink and a wired admin link holds three or more addresses, and the
WAN one is a DHCP lease that changes without anybody editing a TOML file.
A candidate naming *that* address passed every safety check, and in the
field six `BLOCK` rules targeting the Pi's own WAN address were queued for
approval — a self-lockout the validator was supposed to make impossible.

**Source.** `/proc/net/fib_trie`, the kernel's forwarding-information-base
dump, which lists every address the host has claimed, each tagged with its
scope and type. An address entry looks like:

    |-- 192.168.100.1
       /32 host LOCAL

so an address line followed by a `host LOCAL` line is one of ours, and one
followed by `link BROADCAST` is a subnet broadcast address — also never a
legitimate rule target.

**Read, never written; a file, never a command.** No `subprocess`, no
`nft`, no netlink library, and nothing derived from ML output or user input
(spec §20) — this only opens a read-only procfs file and parses integers
and dotted quads out of it.

**Degrades to nothing, never raises.** `/proc/net/fib_trie` is Linux-only
and may be absent (a non-Linux dev machine, a hardened container). Every
failure returns an empty set, which leaves the validator exactly as strict
as it was before this module existed — the configured checks still run. It
can only ever *add* protection.
"""

import logging
import time
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path

_logger = logging.getLogger(__name__)

_FIB_TRIE_PATH = Path("/proc/net/fib_trie")
_ADDRESS_PREFIX = "|--"
_LOCAL_MARKERS = ("host LOCAL",)
_BROADCAST_MARKERS = ("link BROADCAST",)

# The validator runs on every candidate rule, which on a busy link can be
# many per second; re-reading and re-parsing procfs that often is pure
# waste. Interface addresses change on the order of a DHCP lease, so a few
# seconds of staleness is immaterial — and staleness can only ever make the
# check match the *previous* address set, never invent a wrong one.
_CACHE_TTL_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class LocalAddresses:
    """Every IPv4 address this host answers to, plus the broadcast addresses of its subnets."""

    host: frozenset[IPv4Address]
    broadcast: frozenset[IPv4Address]

    def contains(self, address: IPv4Address) -> bool:
        """True if `address` is one of this host's own addresses or a local broadcast address."""
        return address in self.host or address in self.broadcast


_EMPTY = LocalAddresses(host=frozenset(), broadcast=frozenset())

_cached: LocalAddresses = _EMPTY
_cached_at: float = 0.0


def read_local_addresses(path: Path = _FIB_TRIE_PATH) -> LocalAddresses:
    """Parse `path` (a `/proc/net/fib_trie` dump) into this host's own addresses.

    Returns empty sets — never raises — if the file is missing, unreadable,
    or in an unexpected format.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        _logger.debug("cannot read %s, local-address safety check degrades to config only: %s", path, exc)
        return _EMPTY
    try:
        return _parse_fib_trie(text)
    except Exception as exc:  # a procfs format change must not break rule validation
        _logger.warning("unparseable %s, local-address safety check degrades to config only: %s", path, exc)
        return _EMPTY


def cached_local_addresses(now: float | None = None) -> LocalAddresses:
    """`read_local_addresses` behind a short TTL cache (see `_CACHE_TTL_SECONDS`)."""
    global _cached, _cached_at
    moment = time.monotonic() if now is None else now
    if _cached is _EMPTY or moment - _cached_at >= _CACHE_TTL_SECONDS:
        _cached = read_local_addresses()
        _cached_at = moment
    return _cached


def reset_cache() -> None:
    """Drop the TTL cache. For tests, and for a caller that knows addressing just changed."""
    global _cached, _cached_at
    _cached = _EMPTY
    _cached_at = 0.0


def _parse_fib_trie(text: str) -> LocalAddresses:
    host: set[IPv4Address] = set()
    broadcast: set[IPv4Address] = set()
    pending: IPv4Address | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith(_ADDRESS_PREFIX):
            pending = _parse_address(line[len(_ADDRESS_PREFIX) :].strip())
            continue
        if pending is None:
            continue
        if any(marker in line for marker in _LOCAL_MARKERS):
            host.add(pending)
        elif any(marker in line for marker in _BROADCAST_MARKERS):
            broadcast.add(pending)
        pending = None

    return LocalAddresses(host=frozenset(host), broadcast=frozenset(broadcast))


def _parse_address(token: str) -> IPv4Address | None:
    try:
        return IPv4Address(token)
    except ValueError:
        return None
