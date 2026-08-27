"""`NftablesBackend`: the real Linux nftables implementation (spec §20).

Every operation builds a Python `dict` (nftables' documented JSON schema,
see `libnftables-json(5)`) and hands it to `nft -j -f -` over **stdin** as
serialized JSON — never a hand-built nft-syntax string, and the `subprocess`
call itself is always an argument list with `shell=False` (the default).
Every value that ends up in that JSON is already a validated,
type-constrained field from `pirewall.core.models.rule.FirewallRule`
(an `IPv4Network`, a bounded `int` port, a closed `Protocol`/`FirewallAction`
enum) — never a free-form string from evidence/reason/user input. This is
what CLAUDE.md's "no shell commands built from ML output or user input"
and this phase's "no string-interpolated shell commands... never shell=True
with interpolated rule data" mean concretely here.

Linux-only, requires root/`CAP_NET_ADMIN` and a real `nft` binary — cannot
be exercised outside a real Raspberry Pi / Linux host. See
`docs/PROGRESS.md` Phase 6 for the Environment-dependent label and what a
human needs to do to verify it.
"""

import json
import subprocess
from collections.abc import Mapping
from ipaddress import IPv4Network
from typing import cast

from pirewall.core.enums import FirewallAction, Protocol
from pirewall.core.exceptions import FirewallError
from pirewall.core.models.rule import FirewallRule

_NFT_BINARY = "nft"
_FAMILY = "inet"
_TABLE = "pirewall"
_CHAIN = "adaptive"
_COMMENT_PREFIX = "pirewall-rule:"

_PROTOCOL_PAYLOAD_NAME = {Protocol.TCP: "tcp", Protocol.UDP: "udp"}


class NftablesBackend:
    """`FirewallBackend` backed by a real `nft` binary via its JSON interface."""

    def __init__(self, rate_limit_per_second: int) -> None:
        self._rate_limit_per_second = rate_limit_per_second
        self._bootstrapped = False

    def _ensure_bootstrap(self) -> None:
        """Create the pirewall table/chain if they don't already exist. Idempotent."""
        if self._bootstrapped:
            return
        payload = {
            "nftables": [
                {"add": {"table": {"family": _FAMILY, "name": _TABLE}}},
                {
                    "add": {
                        "chain": {
                            "family": _FAMILY,
                            "table": _TABLE,
                            "name": _CHAIN,
                            "type": "filter",
                            "hook": "forward",
                            "prio": 0,
                            "policy": "accept",
                        }
                    }
                },
            ]
        }
        self._run_json(payload)
        self._bootstrapped = True

    def apply_rule(self, rule: FirewallRule) -> None:
        """Deploy `rule`. Raises `FirewallError` on failure."""
        self._ensure_bootstrap()
        comment = _rule_comment(rule.id)
        add_commands = _build_add_commands(rule, comment, self._rate_limit_per_second)
        try:
            self._run_json({"nftables": add_commands})
        except FirewallError:
            raise
        except Exception as exc:  # never let an unexpected error look like success
            raise FirewallError(f"failed to apply rule {rule.id}: {exc}") from exc

    def remove_rule(self, rule_id: str) -> None:
        """Remove every deployed nft rule tagged with `rule_id`'s comment. Idempotent."""
        self._ensure_bootstrap()
        comment = _rule_comment(rule_id)
        handles = self._find_handles_by_comment(comment)
        if not handles:
            return
        delete_commands = [
            {"delete": {"rule": {"family": _FAMILY, "table": _TABLE, "chain": _CHAIN, "handle": handle}}}
            for handle in handles
        ]
        try:
            self._run_json({"nftables": delete_commands})
        except Exception as exc:
            raise FirewallError(f"failed to remove rule {rule_id}: {exc}") from exc

    def list_active_rule_ids(self) -> frozenset[str]:
        """IDs of rules currently deployed, derived from nft rule comments."""
        self._ensure_bootstrap()
        ruleset = self._list_ruleset()
        ids: set[str] = set()
        for item in ruleset:
            rule = _as_dict(item.get("rule"))
            if rule is None:
                continue
            comment = rule.get("comment")
            if isinstance(comment, str) and comment.startswith(_COMMENT_PREFIX):
                ids.add(comment[len(_COMMENT_PREFIX) :])
        return frozenset(ids)

    def health_check(self) -> bool:
        try:
            self._run_command(["-j", "list", "tables"])
            return True
        except FirewallError:
            return False

    def _find_handles_by_comment(self, comment: str) -> list[int]:
        handles: list[int] = []
        for item in self._list_ruleset():
            rule = _as_dict(item.get("rule"))
            if rule is not None and rule.get("comment") == comment:
                handle = rule.get("handle")
                if isinstance(handle, int):
                    handles.append(handle)
        return handles

    def _list_ruleset(self) -> list[dict[str, object]]:
        result = self._run_command(["-j", "list", "chain", _FAMILY, _TABLE, _CHAIN])
        try:
            parsed: object = json.loads(result)
        except json.JSONDecodeError as exc:
            raise FirewallError(f"nft returned invalid JSON: {exc}") from exc
        parsed_dict = _as_dict(parsed)
        if parsed_dict is None:
            return []
        items = parsed_dict.get("nftables")
        if not isinstance(items, list):
            return []
        results: list[dict[str, object]] = []
        for entry in cast("list[object]", items):
            entry_dict = _as_dict(entry)
            if entry_dict is not None:
                results.append(entry_dict)
        return results

    def _run_json(self, payload: Mapping[str, object]) -> None:
        self._run_command(["-j", "-f", "-"], stdin_json=payload)

    def _run_command(self, args: list[str], stdin_json: Mapping[str, object] | None = None) -> str:
        stdin_data = json.dumps(stdin_json) if stdin_json is not None else None
        try:
            result = subprocess.run(
                [_NFT_BINARY, *args],
                input=stdin_data,
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
        except FileNotFoundError as exc:
            raise FirewallError(f"'{_NFT_BINARY}' binary not found: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise FirewallError(f"nft command timed out: {exc}") from exc
        except subprocess.CalledProcessError as exc:
            raise FirewallError(f"nft command failed: {exc.stderr}") from exc
        return result.stdout


def _as_dict(value: object) -> dict[str, object] | None:
    """Narrow a JSON-decoded value to `dict[str, object]`, or `None` if it isn't a dict.

    `json.loads` returns `object`/`Any`-typed structures; a bare
    `isinstance(value, dict)` check alone still leaves pyright unable to
    infer the key/value types, so this centralizes the one explicit,
    verified cast nftables JSON parsing needs (every JSON object's keys
    are strings by construction).
    """
    if isinstance(value, dict):
        return cast("dict[str, object]", value)
    return None


def _rule_comment(rule_id: str) -> str:
    return f"{_COMMENT_PREFIX}{rule_id}"


def _address_match(field: str, network: IPv4Network) -> dict[str, object]:
    return {
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": "ip", "field": field}},
            "right": {"prefix": {"addr": str(network.network_address), "len": network.prefixlen}},
        }
    }


def _port_match(protocol_name: str, field: str, port: int) -> dict[str, object]:
    return {
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": protocol_name, "field": field}},
            "right": port,
        }
    }


def _match_expressions(rule: FirewallRule) -> list[dict[str, object]]:
    expressions: list[dict[str, object]] = [
        _address_match("saddr", rule.source),
        _address_match("daddr", rule.destination),
    ]
    protocol_name = _PROTOCOL_PAYLOAD_NAME.get(rule.protocol)
    if protocol_name is not None and rule.destination_port is not None:
        expressions.append(_port_match(protocol_name, "dport", rule.destination_port))
    return expressions


def _verdict_expressions(rule: FirewallRule, rate_limit_per_second: int) -> list[dict[str, object]]:
    if rule.action is FirewallAction.BLOCK:
        return [{"drop": None}]
    if rule.action is FirewallAction.MONITOR:
        return [{"log": {"prefix": "pirewall-monitor: "}}, {"counter": None}]
    if rule.action is FirewallAction.RATE_LIMIT:
        return [{"limit": {"rate": rate_limit_per_second, "per": "second"}}, {"accept": None}]
    raise FirewallError(f"nftables backend has no translation for action {rule.action!r}")


def _build_add_commands(
    rule: FirewallRule, comment: str, rate_limit_per_second: int
) -> list[dict[str, object]]:
    """Build the `nft -j -f -` add-rule command(s) for `rule`.

    `RATE_LIMIT` needs two nft rules under the same comment: one that
    accepts traffic under the configured rate, and one unconditional
    `drop` right after it to catch everything the limit rejects (plain
    `limit` alone doesn't drop excess — it just stops matching, letting
    excess fall through to whatever rule/policy follows).
    """
    base_expr = _match_expressions(rule)
    commands: list[dict[str, object]] = [
        {
            "add": {
                "rule": {
                    "family": _FAMILY,
                    "table": _TABLE,
                    "chain": _CHAIN,
                    "comment": comment,
                    "expr": [*base_expr, *_verdict_expressions(rule, rate_limit_per_second)],
                }
            }
        }
    ]
    if rule.action is FirewallAction.RATE_LIMIT:
        commands.append(
            {
                "add": {
                    "rule": {
                        "family": _FAMILY,
                        "table": _TABLE,
                        "chain": _CHAIN,
                        "comment": comment,
                        "expr": [*base_expr, {"drop": None}],
                    }
                }
            }
        )
    return commands
