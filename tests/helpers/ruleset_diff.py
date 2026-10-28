"""The ruleset-diff invariant (ADDENDUM_4.md D1): what a core operation is allowed to change.

`changed_objects` compares two `RulesetSnapshot`s (from `SetBackend.snapshot()`,
fake or real `nft -j list ruleset`) and lists every object that differs.
`assert_only_allowed_changes` fails if anything outside D1's allowance moved:

* the contents of a `guard_verdict_*` chain in `pirewall_static`;
* the elements of a set core writes (`MANAGER_WRITABLE_SETS`);
* with `allow_panic=True`, the deletion of exactly `nft_names.PANIC_TABLES`.

Every other chain, every kernel-written set, and `pirewall_base` /
`pirewall_portal` must be identical before and after.
"""

from collections.abc import Mapping

from pirewall.core import nft_names
from pirewall.firewall.sets import MANAGER_WRITABLE_SETS, RulesetSnapshot

Change = tuple[str, str, str, str]
"""(family, table, kind, name): kind is "table", "chain" or "set"."""

_ALLOWED_CHAINS = frozenset(
    (nft_names.INET_FAMILY, nft_names.STATIC_TABLE, "chain", chain)
    for chain in nft_names.GUARD_VERDICT_CHAINS.values()
)
_ALLOWED_SETS = frozenset((family, table, "set", name) for family, table, name in MANAGER_WRITABLE_SETS)


def changed_objects(before: RulesetSnapshot, after: RulesetSnapshot) -> set[Change]:
    """Every table, chain or set whose presence or contents differ between the two snapshots."""
    changes: set[Change] = set()
    for location in set(before) | set(after):
        family, table = location
        if (location in before) != (location in after):
            changes.add((family, table, "table", table))
            continue
        old, new = before[location], after[location]
        changes |= _diff(family, table, "chain", old.chains, new.chains)
        changes |= _diff(family, table, "set", old.sets, new.sets)
    return changes


def assert_only_allowed_changes(
    before: RulesetSnapshot, after: RulesetSnapshot, *, allow_panic: bool = False
) -> None:
    """Fail with the offending objects if anything outside D1's allowance changed."""
    allowed = _ALLOWED_CHAINS | _ALLOWED_SETS
    if allow_panic:
        allowed |= {(family, table, "table", table) for family, table in nft_names.PANIC_TABLES}
    forbidden = changed_objects(before, after) - allowed
    assert not forbidden, f"objects changed outside D1's allowance: {sorted(forbidden)}"


def _diff(
    family: str, table: str, kind: str, old: Mapping[str, object], new: Mapping[str, object]
) -> set[Change]:
    return {(family, table, kind, name) for name in set(old) | set(new) if old.get(name) != new.get(name)}
