"""The v2 set backend contract and rule -> set-element translation (ADDENDUM_4.md D1, D4, D5).

v2 enforcement is not per-rule chains. It is elements in reviewed, pre-loaded
kernel sets (`deploy/firewall/pirewall_adaptive.nft.template`), each with a
timeout, plus the three guard verdict chains in `pirewall_static`. This
module holds:

* `SetBackend`: what a backend must offer the manager (Protocol). Real:
  `pirewall.firewall.backend.nftables_sets.NftablesSetBackend`; fake:
  `pirewall.firewall.backend.fake_sets.FakeSetBackend`. Only
  `pirewall.firewall.manager` may hold one (CLAUDE.md single deploy path).
* `SetOp`, `ElementState`, `SetFill`, `RulesetSnapshot`: the data that crosses
  that boundary. Structured values only; a backend turns them into nft JSON,
  never into nft syntax strings (spec §20).
* `MANAGER_WRITABLE_SETS` and `validate_element`: the single-writer table
  (D1) and the key/timeout checks every backend applies before writing, so
  a bug upstream cannot put an element in a kernel-owned set, an element
  without a timeout in an enforcement set, or a broadcast MAC anywhere.
* `device_target`, `enforcement_set_for`, `element_timeout_seconds`: how a
  validated `FirewallRule` becomes one element.

No I/O here.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network
from typing import Final, Protocol, runtime_checkable

from pydantic import TypeAdapter, ValidationError

from pirewall.core import nft_names
from pirewall.core.enums import FirewallAction, GuardMode, GuardName, NftTransportKind
from pirewall.core.exceptions import FirewallError
from pirewall.core.models.common import UnicastMacAddress
from pirewall.core.models.identity import RuleTarget
from pirewall.core.models.rule import CandidateRule, FirewallRule

ElementKey = str | tuple[str, str]
"""A set element's key: one normalised value, or a two-part concatenation (`ip . mac`)."""

_HOST_PREFIX = 32
_UNICAST_MAC: Final[TypeAdapter[str]] = TypeAdapter(UnicastMacAddress)


class KeyType(StrEnum):
    """An element key's nft type."""

    IPV4 = "ipv4_addr"
    MAC = "ether_addr"
    IPV4_MAC = "ipv4_addr . ether_addr"
    MAC_IPV4 = "ether_addr . ipv4_addr"


@dataclass(frozen=True, slots=True)
class WritableSet:
    """A set the manager may write: its key type, and whether elements must carry a timeout."""

    key_type: KeyType
    timeout_required: bool


MANAGER_WRITABLE_SETS: Final[Mapping[tuple[str, str, str], WritableSet]] = {
    # (family, table, set) -> shape. D1: every other set has another writer
    # (the kernel, or pirewall-start for infra4), and a backend refuses it.
    (nft_names.INET_FAMILY, nft_names.ADAPTIVE_TABLE, nft_names.SET_BLOCK_MAC): WritableSet(
        KeyType.MAC, True
    ),
    (nft_names.INET_FAMILY, nft_names.ADAPTIVE_TABLE, nft_names.SET_BLOCK4): WritableSet(KeyType.IPV4, True),
    (nft_names.INET_FAMILY, nft_names.ADAPTIVE_TABLE, nft_names.SET_RATELIMIT_MAC): WritableSet(
        KeyType.MAC, True
    ),
    (nft_names.INET_FAMILY, nft_names.ADAPTIVE_TABLE, nft_names.SET_RATELIMIT4): WritableSet(
        KeyType.IPV4, True
    ),
    (nft_names.INET_FAMILY, nft_names.ADAPTIVE_TABLE, nft_names.SET_ALLOW_BOUND): WritableSet(
        KeyType.MAC_IPV4, False
    ),
    (nft_names.INET_FAMILY, nft_names.STATIC_TABLE, nft_names.SET_ALLOW_BOUND): WritableSet(
        KeyType.MAC_IPV4, False
    ),
    (nft_names.INET_FAMILY, nft_names.STATIC_TABLE, nft_names.SET_BOUND4): WritableSet(KeyType.IPV4, False),
    (nft_names.INET_FAMILY, nft_names.STATIC_TABLE, nft_names.SET_MACBIND): WritableSet(
        KeyType.IPV4_MAC, False
    ),
    (nft_names.ARP_FAMILY, nft_names.STATIC_ARP_TABLE, nft_names.SET_BOUND4): WritableSet(
        KeyType.IPV4, False
    ),
    (nft_names.ARP_FAMILY, nft_names.STATIC_ARP_TABLE, nft_names.SET_MACBIND): WritableSet(
        KeyType.IPV4_MAC, False
    ),
}
"""The single-writer table (ADDENDUM_4.md D1): the only sets core may put elements into.

Binding sets (`bound4`, `macbind`) are listed for phase 14's `sync_bindings`;
their timeout is optional because static bindings never expire.
"""

MAX_ELEMENT_TIMEOUT_SECONDS: Final = 3600
"""Every adaptive element expires within an hour (D1), so a block orphaned by a crash ends on its own."""


class SetOpKind(StrEnum):
    """One element operation inside an atomic batch."""

    ADD = "add"
    DELETE = "delete"


@dataclass(frozen=True, slots=True)
class SetOp:
    """Add or delete one element. Several ops in one `SetBackend.apply` call commit atomically.

    `timeout_seconds` is for ADD only, and is required for enforcement sets.
    DELETE is idempotent: deleting an element that is not there (already
    expired) is not an error, so an atomic upgrade cannot fail because the
    old element lapsed a moment earlier.
    """

    kind: SetOpKind
    set_name: str
    key: ElementKey
    timeout_seconds: int | None = None
    table: str = nft_names.ADAPTIVE_TABLE
    family: str = nft_names.INET_FAMILY


@dataclass(frozen=True, slots=True)
class ElementState:
    """One element as the kernel reports it. `expires_in_seconds` is None without a timeout."""

    key: ElementKey
    expires_in_seconds: int | None


@dataclass(frozen=True, slots=True)
class SetFill:
    """How full a set is. A full set refuses adds (and a full meter fails open, critique_redteam V2)."""

    count: int
    size: int | None

    @property
    def ratio(self) -> float | None:
        """`count / size`, or None for an unbounded set."""
        return None if not self.size else self.count / self.size


@dataclass(frozen=True, slots=True)
class TransportMetrics:
    """Counters for the transport a backend uses (phase 13 deliverable 2)."""

    kind: NftTransportKind
    calls: int
    failures: int
    total_seconds: float


@dataclass(frozen=True, slots=True)
class TableSnapshot:
    """What one table holds: each chain's rules (normalised) and each set's element keys."""

    chains: Mapping[str, tuple[str, ...]] = field(default_factory=dict[str, tuple[str, ...]])
    sets: Mapping[str, frozenset[ElementKey]] = field(default_factory=dict[str, frozenset[ElementKey]])


RulesetSnapshot = Mapping[tuple[str, str], TableSnapshot]
"""(family, table) -> its contents. The ruleset-diff invariant helper compares two of these."""


@runtime_checkable
class SetBackend(Protocol):
    """What `FirewallManager` needs from the v2 kernel data plane.

    Contract:

    * Only elements of `MANAGER_WRITABLE_SETS` are ever written, and only
      after `validate_element` passes. Rules and chains are never edited,
      except the three guard verdict chains through `set_guard_modes`.
    * `delete table` happens only in `panic`, and only for
      `nft_names.PANIC_TABLES`. `pirewall_base` and `pirewall_portal` are
      never touched.
    * Every method that writes is one atomic batch: all of it or none.
    * Raises `pirewall.core.exceptions.FirewallError` on failure.
    """

    @property
    def transport(self) -> NftTransportKind:
        """How this backend reaches the kernel."""
        ...

    def metrics(self) -> TransportMetrics:
        """Transport call/failure/latency counters."""
        ...

    def apply(self, ops: Sequence[SetOp]) -> None:
        """Apply element adds/deletes as one atomic batch (an upgrade is a delete + add here)."""
        ...

    def add_element(self, set_name: str, key: ElementKey, timeout_seconds: int | None) -> None:
        """Add one element to an adaptive set. Re-adding keeps the old timeout; delete first to change it."""
        ...

    def delete_element(self, set_name: str, key: ElementKey) -> None:
        """Delete one element from an adaptive set. Idempotent."""
        ...

    def flush_sets(self, set_names: Iterable[str]) -> None:
        """Empty these adaptive sets in one atomic batch."""
        ...

    def flush_set(self, set_name: str) -> None:
        """Empty one adaptive set."""
        ...

    def list_set(
        self, set_name: str, *, table: str = nft_names.ADAPTIVE_TABLE, family: str = nft_names.INET_FAMILY
    ) -> list[ElementState]:
        """The elements the kernel holds now. A separate call from any write (read-after-write)."""
        ...

    def set_fill(
        self, set_name: str, *, table: str = nft_names.ADAPTIVE_TABLE, family: str = nft_names.INET_FAMILY
    ) -> SetFill:
        """Element count and declared size."""
        ...

    def set_guard_modes(self, modes: Mapping[GuardName, GuardMode]) -> None:
        """Replace these guards' verdict chains (`counter` + `drop`, or `counter` alone) in ONE batch."""
        ...

    def set_guard_mode(self, guard: GuardName, mode: GuardMode) -> None:
        """One guard's flip, as one atomic batch."""
        ...

    def guard_mode(self, guard: GuardName) -> GuardMode | None:
        """The mode the kernel's verdict chain encodes now, or None if the chain is missing."""
        ...

    def table_exists(self, family: str, table: str) -> bool:
        """Whether `family table` is loaded."""
        ...

    def panic(self) -> tuple[tuple[str, str], ...]:
        """Delete every table in `nft_names.PANIC_TABLES`, atomically and idempotently. Returns them."""
        ...

    def snapshot(self) -> RulesetSnapshot:
        """The whole ruleset, normalised, for the ruleset-diff invariant (tests and diagnostics)."""
        ...

    def health_check(self) -> bool:
        """True if the kernel is reachable."""
        ...


def validate_element(op: SetOp) -> None:
    """Refuse an op a backend must never send: wrong set, malformed key, or a missing/over-long timeout.

    Shared by every backend so the real one and the fake refuse the same
    things. Keys must already be normalised (`normalise_key`).
    """
    shape = MANAGER_WRITABLE_SETS.get((op.family, op.table, op.set_name))
    if shape is None:
        raise FirewallError(
            f"refusing to write {op.family} {op.table} {op.set_name}: core is not this set's writer (D1)"
        )
    if normalise_key(shape.key_type, op.key) != op.key:
        raise FirewallError(f"key {op.key!r} is not a normalised {shape.key_type.value}")
    if op.kind is not SetOpKind.ADD:
        return
    if op.timeout_seconds is None:
        if shape.timeout_required:
            raise FirewallError(f"refusing an element without a timeout in {op.set_name} (D1)")
        return
    if op.timeout_seconds <= 0:
        raise FirewallError(f"element timeout {op.timeout_seconds}s must be positive")
    # D1's one-hour ceiling is for *enforcement* elements, so an orphaned block
    # ends on its own. A binding's timeout is its DHCP lease (plus grace,
    # phase 14), which is routinely longer; capping it would unbind every
    # device before its lease ran out.
    if shape.timeout_required and op.timeout_seconds > MAX_ELEMENT_TIMEOUT_SECONDS:
        raise FirewallError(
            f"element timeout {op.timeout_seconds}s outside 1..{MAX_ELEMENT_TIMEOUT_SECONDS}s"
        )


def writable_set(family: str, table: str, set_name: str) -> WritableSet:
    """The shape of a manager-writable set. Raises `FirewallError` for any other set."""
    shape = MANAGER_WRITABLE_SETS.get((family, table, set_name))
    if shape is None:
        raise FirewallError(f"{family} {table} {set_name} is not a manager-writable set")
    return shape


def normalise_key(key_type: KeyType, key: ElementKey) -> ElementKey:
    """The canonical form of `key` for `key_type`. Raises `FirewallError` if it cannot be one.

    MACs must be unicast and non-zero: a multicast or broadcast MAC names
    every listener at once (D3).
    """
    if key_type is KeyType.IPV4:
        return _ipv4(key)
    if key_type is KeyType.MAC:
        return _mac(key)
    if not isinstance(key, tuple):
        raise FirewallError(f"{key_type.value} needs a two-part key, got {key!r}")
    first, second = key
    if key_type is KeyType.IPV4_MAC:
        return (_ipv4(first), _mac(second))
    return (_mac(first), _ipv4(second))


def _ipv4(value: ElementKey) -> str:
    if not isinstance(value, str):
        raise FirewallError(f"expected an IPv4 address, got {value!r}")
    try:
        return str(IPv4Address(value))
    except ValueError as exc:
        raise FirewallError(f"expected an IPv4 address, got {value!r}") from exc


def _mac(value: ElementKey) -> str:
    if not isinstance(value, str):
        raise FirewallError(f"expected a MAC address, got {value!r}")
    try:
        return str(_UNICAST_MAC.validate_python(value))
    except ValidationError as exc:
        raise FirewallError(f"expected a unicast MAC address, got {value!r}") from exc


# ---------------------------------------------------------------- rule -> element


def device_target(
    rule: CandidateRule | FirewallRule, protected_network: IPv4Network, mac: str | None = None
) -> RuleTarget | None:
    """The LAN device a rule's enforcement keys on, or None when there is none.

    v2 enforces per device, at LAN ingress (D1): the target is the rule's
    *source*, and only when it is a single address inside the protected
    network. A v1 rule against a WAN source, or one whose source is a range,
    has no device the adaptive sets can key on; the v2 validator rejects it
    as UNENFORCEABLE rather than deploying something narrower or broader
    than the evidence (spec §24). `mac` comes from the binding table once
    phase 14 wires one in.
    """
    source = rule.source
    if source.prefixlen != _HOST_PREFIX or not source.subnet_of(protected_network):
        return None
    return RuleTarget(
        ip=source.network_address, mac=None if mac is None else _UNICAST_MAC.validate_python(mac)
    )


def enforcement_set_for(action: FirewallAction, target: RuleTarget) -> str | None:
    """Which adaptive set enforces `action` on `target`, or None for actions with no kernel effect.

    A MAC, when known, wins over the IP (D3): it survives a change of
    address, and a spoofed source IP cannot frame a neighbour with it.
    """
    if action is FirewallAction.BLOCK:
        return nft_names.SET_BLOCK_MAC if target.mac is not None else nft_names.SET_BLOCK4
    if action is FirewallAction.RATE_LIMIT:
        return nft_names.SET_RATELIMIT_MAC if target.mac is not None else nft_names.SET_RATELIMIT4
    return None


def element_key(set_name: str, target: RuleTarget) -> str:
    """The key `target` has in `set_name`: its MAC for a MAC set, its IP otherwise."""
    shape = writable_set(nft_names.INET_FAMILY, nft_names.ADAPTIVE_TABLE, set_name)
    if shape.key_type is KeyType.MAC:
        if target.mac is None:
            raise FirewallError(f"{set_name} needs a MAC, and the target has none")
        return str(target.mac)
    return str(target.ip)


def element_timeout_seconds(expires_at: datetime, now: datetime, max_ttl_seconds: int) -> int:
    """The element timeout for a rule expiring at `expires_at`: whole seconds, at least 1, capped."""
    remaining = int((expires_at - now).total_seconds())
    return max(1, min(remaining, max_ttl_seconds, MAX_ELEMENT_TIMEOUT_SECONDS))
