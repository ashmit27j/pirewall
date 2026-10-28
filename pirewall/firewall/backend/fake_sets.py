"""`FakeSetBackend`: an in-memory v2 `SetBackend` for tests (spec §39, phase 13).

Models the kernel semantics `FirewallManager`'s set path depends on:

* Tables are pre-loaded, as `pirewall-start` would have done: the two v2
  tables and the arp companion, plus empty `pirewall_base` and
  `pirewall_portal` so a test can prove panic leaves them alone.
* Element timeouts run on an injectable clock (`now_fn`), and expired
  elements disappear unannounced, like the kernel's.
* Every set has its declared size, and an add to a full set fails.
* Writes are atomic: a batch either applies completely or not at all.
* The same `validate_element` checks as the real backend, so the fake
  refuses whatever the kernel path would refuse.

`ops` records every successful write for assertions. `fail_next` makes the
next write raise, to exercise failure paths.
"""

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Final

from pirewall.core import nft_names
from pirewall.core.enums import GuardMode, GuardName, NftTransportKind
from pirewall.core.exceptions import FirewallError
from pirewall.firewall.guards import verdict_expressions
from pirewall.firewall.sets import (
    ElementKey,
    ElementState,
    RulesetSnapshot,
    SetFill,
    SetOp,
    SetOpKind,
    TableSnapshot,
    TransportMetrics,
    validate_element,
    writable_set,
)

DEFAULT_GUARD_MODES: Final[Mapping[GuardName, GuardMode]] = MappingProxyType(
    {
        GuardName.RAW: GuardMode.ENFORCE,
        GuardName.INPUT: GuardMode.ENFORCE,
        GuardName.FORWARD: GuardMode.OBSERVE,
    }
)
"""D2's defaults, which is what a freshly rendered template loads with."""

_Location = tuple[str, str]


class _FakeSet:
    """One fake kernel set: its declared size and its elements (key -> expiry, or None)."""

    def __init__(self, size: int | None) -> None:
        self.size = size
        self.elements: dict[ElementKey, datetime | None] = {}


class FakeSetBackend:
    """In-memory `SetBackend`. See the module docstring for the semantics it models."""

    def __init__(
        self,
        now_fn: Callable[[], datetime],
        *,
        adaptive_size: int = 4096,
        binding_size: int = 1024,
        guard_modes: Mapping[GuardName, GuardMode] | None = None,
    ) -> None:
        self._now_fn = now_fn
        self._adaptive_size = adaptive_size
        self._binding_size = binding_size
        self._tables: dict[_Location, dict[str, _FakeSet]] = {}
        self._guards: dict[GuardName, GuardMode] = {}
        self.ops: list[tuple[str, tuple[object, ...]]] = []
        self.fail_next = False
        self.calls = 0
        self.failures = 0
        self.load_tables(guard_modes)

    def load_tables(self, guard_modes: Mapping[GuardName, GuardMode] | None = None) -> None:
        """(Re)load the reviewed tables keeping existing elements: `pirewall-start`'s idempotent reload.

        Guard modes are re-rendered from `guard_modes` when given; otherwise a
        guard keeps its current mode (or takes D2's default on first load).
        """
        inet = nft_names.INET_FAMILY
        self._tables.setdefault((inet, nft_names.BASE_TABLE), {})
        self._tables.setdefault((inet, nft_names.PORTAL_TABLE), {})
        adaptive = self._tables.setdefault((inet, nft_names.ADAPTIVE_TABLE), {})
        for name in nft_names.ADAPTIVE_ENFORCEMENT_SETS:
            adaptive.setdefault(name, _FakeSet(self._adaptive_size))
        adaptive.setdefault(nft_names.SET_ALLOW_BOUND, _FakeSet(self._binding_size))
        static = self._tables.setdefault((inet, nft_names.STATIC_TABLE), {})
        for name in (nft_names.SET_BOUND4, nft_names.SET_MACBIND, nft_names.SET_ALLOW_BOUND):
            static.setdefault(name, _FakeSet(self._binding_size))
        arp = self._tables.setdefault((nft_names.ARP_FAMILY, nft_names.STATIC_ARP_TABLE), {})
        for name in (nft_names.SET_BOUND4, nft_names.SET_MACBIND):
            arp.setdefault(name, _FakeSet(self._binding_size))
        for guard in GuardName:
            if guard_modes is not None and guard in guard_modes:
                self._guards[guard] = guard_modes[guard]
            else:
                self._guards.setdefault(guard, DEFAULT_GUARD_MODES[guard])

    # ------------------------------------------------------------ properties

    @property
    def transport(self) -> NftTransportKind:
        return NftTransportKind.FAKE

    def metrics(self) -> TransportMetrics:
        return TransportMetrics(NftTransportKind.FAKE, self.calls, self.failures, 0.0)

    # ---------------------------------------------------------------- writes

    def apply(self, ops: Sequence[SetOp]) -> None:
        if not ops:
            return
        self._begin()
        for op in ops:
            validate_element(op)
        now = self._now_fn()
        staged: dict[tuple[str, str, str], dict[ElementKey, datetime | None]] = {}
        for op in ops:
            fake = self._set(op.family, op.table, op.set_name)
            address = (op.family, op.table, op.set_name)
            elements = staged.setdefault(address, _live(fake.elements, now))
            if op.kind is SetOpKind.DELETE:
                elements.pop(op.key, None)
                continue
            if op.key in elements:
                continue
            if fake.size is not None and len(elements) >= fake.size:
                self.failures += 1
                raise FirewallError(f"set is full: {op.set_name} holds {fake.size} element(s)")
            elements[op.key] = (
                None if op.timeout_seconds is None else now + timedelta(seconds=op.timeout_seconds)
            )
        for (family, table, set_name), elements in staged.items():
            self._tables[(family, table)][set_name].elements = elements
        self.ops.append(("apply", tuple(ops)))

    def add_element(self, set_name: str, key: ElementKey, timeout_seconds: int | None) -> None:
        self.apply([SetOp(SetOpKind.ADD, set_name, key, timeout_seconds)])

    def delete_element(self, set_name: str, key: ElementKey) -> None:
        self.apply([SetOp(SetOpKind.DELETE, set_name, key)])

    def flush_sets(self, set_names: Iterable[str]) -> None:
        names = sorted(set(set_names))
        self._begin()
        targets = [self._adaptive_writable(name) for name in names]
        for fake in targets:
            fake.elements = {}
        self.ops.append(("flush", tuple(names)))

    def flush_set(self, set_name: str) -> None:
        self.flush_sets((set_name,))

    def set_guard_modes(self, modes: Mapping[GuardName, GuardMode]) -> None:
        self._begin()
        self._require_table(nft_names.INET_FAMILY, nft_names.STATIC_TABLE)
        self._guards.update(modes)
        self.ops.append(("guards", tuple(sorted(modes.items()))))

    def set_guard_mode(self, guard: GuardName, mode: GuardMode) -> None:
        self.set_guard_modes({guard: mode})

    def panic(self) -> tuple[tuple[str, str], ...]:
        self._begin()
        for location in nft_names.PANIC_TABLES:
            self._tables.pop(location, None)
        self.ops.append(("panic", nft_names.PANIC_TABLES))
        return nft_names.PANIC_TABLES

    # ----------------------------------------------------------------- reads

    def list_set(
        self, set_name: str, *, table: str = nft_names.ADAPTIVE_TABLE, family: str = nft_names.INET_FAMILY
    ) -> list[ElementState]:
        fake = self._set(family, table, set_name)
        now = self._now_fn()
        fake.elements = _live(fake.elements, now)
        return [
            ElementState(key, None if expires is None else max(0, int((expires - now).total_seconds())))
            for key, expires in sorted(fake.elements.items(), key=lambda item: str(item[0]))
        ]

    def set_fill(
        self, set_name: str, *, table: str = nft_names.ADAPTIVE_TABLE, family: str = nft_names.INET_FAMILY
    ) -> SetFill:
        fake = self._set(family, table, set_name)
        fake.elements = _live(fake.elements, self._now_fn())
        return SetFill(len(fake.elements), fake.size)

    def guard_mode(self, guard: GuardName) -> GuardMode | None:
        if (nft_names.INET_FAMILY, nft_names.STATIC_TABLE) not in self._tables:
            return None
        return self._guards[guard]

    def table_exists(self, family: str, table: str) -> bool:
        return (family, table) in self._tables

    def snapshot(self) -> RulesetSnapshot:
        now = self._now_fn()
        result: dict[_Location, TableSnapshot] = {}
        for location, sets in self._tables.items():
            chains: dict[str, tuple[str, ...]] = {}
            if location == (nft_names.INET_FAMILY, nft_names.STATIC_TABLE):
                chains = {
                    nft_names.GUARD_VERDICT_CHAINS[guard]: (
                        json.dumps(verdict_expressions(guard, mode), sort_keys=True),
                    )
                    for guard, mode in self._guards.items()
                }
            result[location] = TableSnapshot(
                chains=chains,
                sets={name: frozenset(_live(fake.elements, now)) for name, fake in sets.items()},
            )
        return result

    def health_check(self) -> bool:
        return True

    # --------------------------------------------------------------- helpers

    def _begin(self) -> None:
        self.calls += 1
        if self.fail_next:
            self.fail_next = False
            self.failures += 1
            raise FirewallError("simulated set backend failure")

    def _require_table(self, family: str, table: str) -> dict[str, _FakeSet]:
        sets = self._tables.get((family, table))
        if sets is None:
            self.failures += 1
            raise FirewallError(f"No such file or directory: table {family} {table}")
        return sets

    def _set(self, family: str, table: str, set_name: str) -> _FakeSet:
        fake = self._require_table(family, table).get(set_name)
        if fake is None:
            raise FirewallError(f"No such file or directory: set {family} {table} {set_name}")
        return fake

    def _adaptive_writable(self, set_name: str) -> _FakeSet:
        writable_set(nft_names.INET_FAMILY, nft_names.ADAPTIVE_TABLE, set_name)
        return self._set(nft_names.INET_FAMILY, nft_names.ADAPTIVE_TABLE, set_name)


def _live(elements: Mapping[ElementKey, datetime | None], now: datetime) -> dict[ElementKey, datetime | None]:
    """The elements that have not expired by `now`."""
    return {key: expires for key, expires in elements.items() if expires is None or expires > now}
