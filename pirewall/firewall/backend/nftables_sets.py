"""`NftablesSetBackend`: the v2 `SetBackend` over real nftables (ADDENDUM_4.md D1, D5; phase 13).

Writes only set elements of `pirewall.firewall.sets.MANAGER_WRITABLE_SETS`
and the contents of the three guard verdict chains, never any other rule or
chain. Deletes tables only in `panic`, and only `nft_names.PANIC_TABLES`. The
reviewed tables themselves are loaded by `pirewall-start` (phase 16) from
`deploy/firewall/`; this backend never creates one.

Every write is one nft transaction (one JSON document), so an upgrade
(delete RATE_LIMIT element + add BLOCK element) or a kill switch (flush four
sets) is all-or-nothing. Two idioms make writes idempotent on nft 1.0.6
(which has no `destroy`), both verified in the netns probe on nft 1.1.6:

* **Delete an element** = `add` it (with a 1 s timeout where the set has
  timeouts), then `delete` it, in the same transaction. An element that
  already expired is therefore not an error.
* **Panic** = `add table` then `delete table` for each panic table, in one
  transaction. A table that is already gone is not an error.

One known edge: deleting an element that is absent from a set that is also
*full* fails, because the placeholder add hits the size limit. The kill
switch flushes instead of deleting, so it is unaffected.

The old `NftablesBackend` (per-rule chain on `forward`) stays in
`backend/nftables.py` until phase 16 moves core onto this class.

Linux-only, needs CAP_NET_ADMIN. Exercised for real only by the netns tier
(`tests/netns/`, env=sandbox); on the Pi it is Environment-dependent.
"""

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import cast

from pirewall.core import nft_names
from pirewall.core.enums import GuardMode, GuardName, NftTransportKind
from pirewall.core.exceptions import FirewallError
from pirewall.firewall.backend.nft_transport import MeteredTransport, NftTransport, select_transport
from pirewall.firewall.guards import guard_mode_commands, mode_from_rules
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

# The kernel returns ENFILE ("Too many open files in system") for an add to a
# full set. Mapped to a message that says what actually happened.
_SET_FULL_MARKER = "Too many open files"


class NftablesSetBackend:
    """`SetBackend` over libnftables or `nft -j -f -` (see `nft_transport.select_transport`)."""

    def __init__(self, transport: NftTransport | None = None) -> None:
        self._transport = MeteredTransport(transport or select_transport())

    # ------------------------------------------------------------ properties

    @property
    def transport(self) -> NftTransportKind:
        return self._transport.kind

    def metrics(self) -> TransportMetrics:
        return TransportMetrics(
            kind=self._transport.kind,
            calls=self._transport.calls,
            failures=self._transport.failures,
            total_seconds=self._transport.total_seconds,
        )

    # ---------------------------------------------------------------- writes

    def apply(self, ops: Sequence[SetOp]) -> None:
        if not ops:
            return
        commands: list[dict[str, object]] = []
        for op in ops:
            validate_element(op)
            commands.extend(_element_commands(op))
        self._run(commands)

    def add_element(self, set_name: str, key: ElementKey, timeout_seconds: int | None) -> None:
        self.apply([SetOp(SetOpKind.ADD, set_name, key, timeout_seconds)])

    def delete_element(self, set_name: str, key: ElementKey) -> None:
        self.apply([SetOp(SetOpKind.DELETE, set_name, key)])

    def flush_sets(self, set_names: Iterable[str]) -> None:
        commands: list[dict[str, object]] = []
        for name in sorted(set(set_names)):
            writable_set(nft_names.INET_FAMILY, nft_names.ADAPTIVE_TABLE, name)
            commands.append(
                {
                    "flush": {
                        "set": {
                            "family": nft_names.INET_FAMILY,
                            "table": nft_names.ADAPTIVE_TABLE,
                            "name": name,
                        }
                    }
                }
            )
        if commands:
            self._run(commands)

    def flush_set(self, set_name: str) -> None:
        self.flush_sets((set_name,))

    def set_guard_modes(self, modes: Mapping[GuardName, GuardMode]) -> None:
        commands = guard_mode_commands(modes)
        if commands:
            self._run(commands)

    def set_guard_mode(self, guard: GuardName, mode: GuardMode) -> None:
        self.set_guard_modes({guard: mode})

    def panic(self) -> tuple[tuple[str, str], ...]:
        commands: list[dict[str, object]] = []
        for family, table in nft_names.PANIC_TABLES:
            commands.append({"add": {"table": {"family": family, "name": table}}})
            commands.append({"delete": {"table": {"family": family, "name": table}}})
        self._run(commands)
        return nft_names.PANIC_TABLES

    # ----------------------------------------------------------------- reads

    def list_set(
        self, set_name: str, *, table: str = nft_names.ADAPTIVE_TABLE, family: str = nft_names.INET_FAMILY
    ) -> list[ElementState]:
        listed = self._list_set_object(set_name, table, family)
        return [state for element in _as_list(listed.get("elem")) if (state := _element_state(element))]

    def set_fill(
        self, set_name: str, *, table: str = nft_names.ADAPTIVE_TABLE, family: str = nft_names.INET_FAMILY
    ) -> SetFill:
        listed = self._list_set_object(set_name, table, family)
        size = listed.get("size")
        return SetFill(count=len(_as_list(listed.get("elem"))), size=size if isinstance(size, int) else None)

    def guard_mode(self, guard: GuardName) -> GuardMode | None:
        chain = nft_names.GUARD_VERDICT_CHAINS[guard]
        try:
            output = self._run(
                [
                    {
                        "list": {
                            "chain": {
                                "family": nft_names.INET_FAMILY,
                                "table": nft_names.STATIC_TABLE,
                                "name": chain,
                            }
                        }
                    }
                ]
            )
        except FirewallError:
            return None
        rules = [_as_list(item.get("expr")) for item in _objects(output, "rule")]
        return mode_from_rules(rules)

    def table_exists(self, family: str, table: str) -> bool:
        output = self._run([{"list": {"tables": None}}])
        return any(
            item.get("family") == family and item.get("name") == table for item in _objects(output, "table")
        )

    def snapshot(self) -> RulesetSnapshot:
        output = self._run([{"list": {"ruleset": None}}])
        chains: dict[tuple[str, str], dict[str, list[str]]] = {}
        sets: dict[tuple[str, str], dict[str, frozenset[ElementKey]]] = {}
        tables: set[tuple[str, str]] = set()
        for item in _objects(output, "table"):
            tables.add((str(item.get("family")), str(item.get("name"))))
        for item in _objects(output, "chain"):
            location = (str(item.get("family")), str(item.get("table")))
            chains.setdefault(location, {}).setdefault(str(item.get("name")), [])
        for item in _objects(output, "rule"):
            location = (str(item.get("family")), str(item.get("table")))
            chain = chains.setdefault(location, {}).setdefault(str(item.get("chain")), [])
            chain.append(_normalise_rule(item.get("expr")))
        for item in _objects(output, "set"):
            location = (str(item.get("family")), str(item.get("table")))
            keys = frozenset(
                state.key for element in _as_list(item.get("elem")) if (state := _element_state(element))
            )
            sets.setdefault(location, {})[str(item.get("name"))] = keys
        return {
            location: TableSnapshot(
                chains={name: tuple(rules) for name, rules in chains.get(location, {}).items()},
                sets=dict(sets.get(location, {})),
            )
            for location in tables
        }

    def health_check(self) -> bool:
        try:
            self._run([{"list": {"tables": None}}])
        except FirewallError:
            return False
        return True

    # --------------------------------------------------------------- helpers

    def _list_set_object(self, set_name: str, table: str, family: str) -> dict[str, object]:
        output = self._run([{"list": {"set": {"family": family, "table": table, "name": set_name}}}])
        listed = _objects(output, "set")
        if not listed:
            raise FirewallError(f"{family} {table} {set_name}: no such set")
        return listed[0]

    def _run(self, commands: list[dict[str, object]]) -> dict[str, object]:
        try:
            return self._transport.run({"nftables": commands})
        except FirewallError as exc:
            if _SET_FULL_MARKER in str(exc):
                raise FirewallError(f"set is full: {exc}") from exc
            raise


def _element_commands(op: SetOp) -> list[dict[str, object]]:
    location = {"family": op.family, "table": op.table, "name": op.set_name}
    value = _key_json(op.key)
    if op.kind is SetOpKind.ADD:
        element: object = (
            value if op.timeout_seconds is None else {"elem": {"val": value, "timeout": op.timeout_seconds}}
        )
        return [{"add": {"element": {**location, "elem": [element]}}}]
    # Idempotent delete (module docstring): make sure it exists, then remove it.
    shape = writable_set(op.family, op.table, op.set_name)
    placeholder: object = {"elem": {"val": value, "timeout": 1}} if shape.timeout_required else value
    return [
        {"add": {"element": {**location, "elem": [placeholder]}}},
        {"delete": {"element": {**location, "elem": [value]}}},
    ]


def _key_json(key: ElementKey) -> object:
    if isinstance(key, tuple):
        return {"concat": [key[0], key[1]]}
    return key


def _element_state(element: object) -> ElementState | None:
    """One listed element, in any of the shapes nft emits: bare, concat, or `{"elem": {...}}`."""
    expires: int | None = None
    value: object = element
    element_dict = _as_dict(element)
    if element_dict is not None and "elem" in element_dict:
        inner = _as_dict(element_dict["elem"]) or {}
        value = inner.get("val")
        raw_expires = inner.get("expires")
        expires = raw_expires if isinstance(raw_expires, int) else None
    key = _key_from_json(value)
    return None if key is None else ElementState(key=key, expires_in_seconds=expires)


def _key_from_json(value: object) -> ElementKey | None:
    if isinstance(value, str):
        return value
    value_dict = _as_dict(value)
    if value_dict is None:
        return None
    parts = _as_list(value_dict.get("concat"))
    if len(parts) == 2 and all(isinstance(part, str) for part in parts):
        return (str(parts[0]), str(parts[1]))
    return None


def _normalise_rule(expressions: object) -> str:
    """A rule's expressions as canonical JSON: stable across listings, for the ruleset diff."""
    return json.dumps(expressions, sort_keys=True)


def _objects(output: Mapping[str, object], kind: str) -> list[dict[str, object]]:
    """Every `{kind: {...}}` object in an nft JSON listing."""
    found: list[dict[str, object]] = []
    for item in _as_list(output.get("nftables")):
        item_dict = _as_dict(item)
        if item_dict is None:
            continue
        inner = _as_dict(item_dict.get(kind))
        if inner is not None:
            found.append(inner)
    return found


def _as_dict(value: object) -> dict[str, object] | None:
    if isinstance(value, dict):
        return cast("dict[str, object]", value)
    return None


def _as_list(value: object) -> list[object]:
    return cast("list[object]", value) if isinstance(value, list) else []
