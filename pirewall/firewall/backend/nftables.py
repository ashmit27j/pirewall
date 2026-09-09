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
from ipaddress import IPv4Address, IPv4Network
from typing import cast

from pirewall.core.enums import FirewallAction, Protocol
from pirewall.core.exceptions import FirewallError
from pirewall.core.models.rule import FirewallRule

_NFT_BINARY = "nft"
_FAMILY = "inet"
_TABLE = "pirewall"
_CHAIN = "adaptive"
_COMMENT_PREFIX = "pirewall-rule:"

# The captive portal's authorized-client set (ADDENDUM_3.md C2). A separate
# table from `pirewall` (adaptive rules) and `pirewall_base` (static posture)
# so a portal bug cannot corrupt either, and so `nft delete table` on any one
# of the three leaves the others standing. The table and set are declared in
# `deploy/firewall/portal.nft.template`; this backend only adds and removes
# *elements*, never the chains that reference them.
_PORTAL_TABLE = "pirewall_portal"
_PORTAL_SET = "authed"

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

    def authorize_portal_client(self, client_ip: IPv4Address, timeout_seconds: int) -> None:
        """Add `client_ip` to `pirewall_portal`'s `authed` set with a kernel-side timeout.

        `timeout` is expressed in nft's own units ("1800s"); the kernel
        removes the element when it lapses, which is what makes portal
        auto-logout cost nothing at runtime. Re-adding an address that is
        already present refreshes its timeout, so a re-login extends a
        session rather than failing.
        """
        if timeout_seconds <= 0:
            raise FirewallError(f"portal session timeout must be positive, got {timeout_seconds}")
        element: dict[str, object] = {
            "elem": {"val": str(client_ip), "timeout": timeout_seconds},
        }
        payload = {
            "nftables": [
                {
                    "add": {
                        "element": {
                            "family": _FAMILY,
                            "table": _PORTAL_TABLE,
                            "name": _PORTAL_SET,
                            "elem": [element],
                        }
                    }
                }
            ]
        }
        try:
            self._run_json(payload)
        except FirewallError:
            raise
        except Exception as exc:  # never let an unexpected error look like success
            raise FirewallError(f"failed to authorize portal client {client_ip}: {exc}") from exc

    def deauthorize_portal_client(self, client_ip: IPv4Address) -> None:
        """Remove `client_ip` from the portal set. Idempotent: an absent element is not an error."""
        payload = {
            "nftables": [
                {
                    "delete": {
                        "element": {
                            "family": _FAMILY,
                            "table": _PORTAL_TABLE,
                            "name": _PORTAL_SET,
                            "elem": [str(client_ip)],
                        }
                    }
                }
            ]
        }
        try:
            self._run_json(payload)
        except FirewallError as exc:
            # nft exits non-zero deleting an element that is not there. The
            # contract is idempotent, and the element genuinely being gone
            # (expired by the kernel a moment ago) is the common case, not
            # an error worth propagating.
            if "No such file or directory" in str(exc) or "does not exist" in str(exc):
                return
            raise

    def list_portal_clients(self) -> frozenset[IPv4Address]:
        """Addresses currently in the portal set, as the kernel sees them."""
        result = self._run_command(["-j", "list", "set", _FAMILY, _PORTAL_TABLE, _PORTAL_SET])
        try:
            parsed: object = json.loads(result)
        except json.JSONDecodeError as exc:
            raise FirewallError(f"nft returned invalid JSON listing the portal set: {exc}") from exc
        parsed_dict = _as_dict(parsed)
        if parsed_dict is None:
            return frozenset()
        items = parsed_dict.get("nftables")
        if not isinstance(items, list):
            return frozenset()
        addresses: set[IPv4Address] = set()
        for entry in cast("list[object]", items):
            entry_dict = _as_dict(entry)
            if entry_dict is None:
                continue
            set_dict = _as_dict(entry_dict.get("set"))
            if set_dict is None:
                continue
            for element in _as_list(set_dict.get("elem")):
                address = _portal_element_address(element)
                if address is not None:
                    addresses.add(address)
        return frozenset(addresses)

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


def _as_list(value: object) -> list[object]:
    """Narrow a JSON-decoded value to `list[object]`, or an empty list if it isn't one."""
    return cast("list[object]", value) if isinstance(value, list) else []


def _portal_element_address(element: object) -> IPv4Address | None:
    """Pull the address out of one set element, in either shape nft emits.

    A timeout-less element is a bare string (`"192.168.100.50"`); one with a
    timeout is `{"elem": {"val": "192.168.100.50", "timeout": 1800, ...}}`.
    Portal elements always carry a timeout, but reading both shapes means a
    hand-added element does not make this return nonsense.
    """
    if isinstance(element, str):
        return _parse_address(element)
    element_dict = _as_dict(element)
    if element_dict is None:
        return None
    inner = _as_dict(element_dict.get("elem"))
    if inner is None:
        return None
    value = inner.get("val")
    return _parse_address(value) if isinstance(value, str) else None


def _parse_address(value: str) -> IPv4Address | None:
    try:
        return IPv4Address(value)
    except ValueError:
        return None
