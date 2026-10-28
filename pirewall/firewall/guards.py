"""Static guard modes: the one runtime write core makes to `pirewall_static` (ADDENDUM_4.md D1, D2).

A guard's mode lives in its `guard_verdict_<guard>` chain: `counter name
c_verdict_<guard>` followed by `drop` (ENFORCE), or the counter alone
(OBSERVE). Every meter hit jumps there, so an observe-mode guard still
counts and still records `@offenders`. A flip replaces the chain's contents
in one batch: `flush chain` + `add rule`. This module builds that batch as
nft JSON and reads a listed chain back into a mode. It never builds any
other rule.

The counter is part of the chain's contents, so a flip re-adds it; dropping
it would silently stop the per-guard hit count the kernel poller reads
(`nft_names.GUARD_VERDICT_COUNTERS`). That matches the tested batch in
`docs/v2/v2/test_ruleset.py` (`set_mode`).
"""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from pirewall.core import nft_names
from pirewall.core.enums import GuardMode, GuardName

ALL_OBSERVE: Final[Mapping[GuardName, GuardMode]] = MappingProxyType(
    dict.fromkeys(GuardName, GuardMode.OBSERVE)
)
"""The kill switch's guard modes (D5): every guard, not only raw (RESULTS.md finding 4)."""


def verdict_expressions(guard: GuardName, mode: GuardMode) -> list[dict[str, object]]:
    """The expressions of the single rule a verdict chain holds in `mode`."""
    expressions: list[dict[str, object]] = [{"counter": nft_names.GUARD_VERDICT_COUNTERS[guard]}]
    if mode is GuardMode.ENFORCE:
        expressions.append({"drop": None})
    return expressions


def guard_mode_commands(modes: Mapping[GuardName, GuardMode]) -> list[dict[str, object]]:
    """nft JSON commands that set every guard in `modes`, for one atomic batch.

    Guards are emitted in `GuardName` order so the batch is deterministic.
    """
    commands: list[dict[str, object]] = []
    for guard in GuardName:
        mode = modes.get(guard)
        if mode is None:
            continue
        chain = nft_names.GUARD_VERDICT_CHAINS[guard]
        location = {"family": nft_names.INET_FAMILY, "table": nft_names.STATIC_TABLE}
        commands.append({"flush": {"chain": {**location, "name": chain}}})
        commands.append(
            {"add": {"rule": {**location, "chain": chain, "expr": verdict_expressions(guard, mode)}}}
        )
    return commands


def mode_from_rules(rule_expressions: list[list[object]]) -> GuardMode:
    """Read a verdict chain's listed rules back into a mode: any `drop` means ENFORCE."""
    for expressions in rule_expressions:
        for expression in expressions:
            if isinstance(expression, dict) and "drop" in expression:
                return GuardMode.ENFORCE
    return GuardMode.OBSERVE


def effective_raw_mode(configured: GuardMode, bindings_seeded: bool) -> GuardMode:
    """D2's "enforce if seeded": an unseeded raw guard is observe whatever the config says.

    Enforcing anti-spoof with an empty binding set would meter every client
    as unbound; phase 16 calls this at startup and raises the SYSTEM_WARNING.
    """
    if configured is GuardMode.ENFORCE and not bindings_seeded:
        return GuardMode.OBSERVE
    return configured
