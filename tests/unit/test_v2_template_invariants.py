"""Static invariants of the deployed v2 nft templates (ADDENDUM_4.md D1, D3; phase 13).

Parsed as text, never loaded: the netns tier (`tests/netns/`) loads them for
real. What is pinned here:

* no rule reads `@offenders` as a match: `@offenders` is evidence only, and
  is only ever written (`update @offenders`);
* every chain with a hook is guarded by `iifname` as its first rule, and
  every hookless chain is reachable only by a `jump` from a guarded one, so
  traffic on the WAN or admin interface is never touched;
* the adaptive table exempts DHCP, DNS and the portal toward the Pi before
  any block rule (C4), and accepts nothing because of an infra4 *source*;
* the base table pins admin access to interface + MAC + IP, and DNS to the
  LAN interface (`docs/v2/v2/base_and_portal.diff`);
* the renderer fills every token of every deployed template from config,
  and refuses when an admin value is unset.
"""

import re
from pathlib import Path

import pytest
from scripts.deployment.render_templates import render_template, substitution_mapping

from pirewall.core.exceptions import ConfigurationError
from tests.helpers.config import make_config

_FIREWALL = Path(__file__).resolve().parents[2] / "deploy" / "firewall"
_V2_TEMPLATES = ("pirewall_static.nft.template", "pirewall_adaptive.nft.template")
_CHAIN = re.compile(r"^\s*chain (\w+) \{\s*$")


def _text(name: str) -> str:
    return (_FIREWALL / name).read_text(encoding="utf-8")


def _rule_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


def _chain_bodies(text: str) -> dict[str, list[str]]:
    """Rule lines of every multi-line `chain NAME {` block, keyed by (table-local) chain name."""
    bodies: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        match = _CHAIN.match(line)
        if match is not None:
            name: str = match.group(1)
            current = name
            bodies[name] = []
            continue
        stripped = line.strip()
        if current is None or not stripped or stripped.startswith("#"):
            continue
        if stripped == "}":
            current = None
            continue
        bodies[current].append(stripped)
    return bodies


@pytest.mark.parametrize("name", _V2_TEMPLATES)
def test_offenders_is_only_ever_written_never_matched(name: str) -> None:
    for line in _rule_lines(_text(name)):
        for match in re.finditer(r"@offenders", line):
            assert line[: match.start()].endswith("update "), f"{name}: reads @offenders: {line}"


@pytest.mark.parametrize("name", _V2_TEMPLATES)
def test_every_hooked_chain_is_guarded_by_the_lan_interface(name: str) -> None:
    bodies = _chain_bodies(_text(name))
    hooked = {chain: rules for chain, rules in bodies.items() if rules and "hook" in rules[0]}
    assert hooked, f"{name}: no hooked chains parsed"
    for chain, rules in hooked.items():
        guard = rules[1]
        assert re.fullmatch(r'(meta )?iifname != "\$\{LAN_INTERFACE\}" return', guard), (
            f"{name}: chain {chain} does not start with the LAN iifname guard: {guard}"
        )


@pytest.mark.parametrize("name", _V2_TEMPLATES)
def test_hookless_chains_are_only_reached_by_jumps_from_guarded_chains(name: str) -> None:
    bodies = _chain_bodies(_text(name))
    hooked = {chain for chain, rules in bodies.items() if rules and "hook" in rules[0]}
    reached = set(hooked)
    changed = True
    while changed:
        changed = False
        for chain in list(reached):
            for line in bodies.get(chain, []):
                for target in re.findall(r"\b(?:jump|goto) (\w+)", line):
                    if target not in reached:
                        reached.add(target)
                        changed = True
    hookless = {chain for chain, rules in bodies.items() if not rules or "hook" not in rules[0]}
    assert hookless <= reached, f"{name}: chains reachable some other way: {sorted(hookless - reached)}"


def test_the_adaptive_table_exempts_dhcp_dns_and_the_portal_before_any_block() -> None:
    rules = _chain_bodies(_text("pirewall_adaptive.nft.template"))["prerouting_adaptive"]
    first_drop = next(index for index, line in enumerate(rules) if line.endswith("drop"))
    exemptions = rules[:first_drop]
    assert "ip daddr { 255.255.255.255, ${PIREWALL_LAN_IP} } udp sport 68 udp dport 67 return" in exemptions
    assert "ip daddr ${PIREWALL_LAN_IP} udp dport 53 return" in exemptions
    assert any("tcp dport { 53, 80, ${PORTAL_PORT} } return" in line for line in exemptions)
    # The exemptions are toward the Pi only: none may return on a destination-less match,
    # or a blocked device could reach any outside host on an exempt port.
    assert all("${PIREWALL_LAN_IP}" in line for line in exemptions if "dport" in line)


def test_no_rule_accepts_traffic_because_its_source_is_infrastructure() -> None:
    for name in _V2_TEMPLATES:
        for line in _rule_lines(_text(name)):
            assert "saddr @infra4" not in line, f"{name}: infra4 source bypass: {line}"


def test_base_pins_admin_access_and_lan_dns() -> None:
    text = _text("base.nft.template")
    admin = [line for line in _rule_lines(text) if "${API_PORT}" in line and "accept" in line]
    assert admin == [
        'iifname "${ADMIN_INTERFACE}" ether saddr ${ADMIN_PC_MAC} ip saddr ${ADMIN_PC_IP} '
        "tcp dport { 22, ${API_PORT} } accept"
    ]
    dns = [line for line in _rule_lines(text) if "dport 53 accept" in line]
    assert dns and all(line.startswith('iifname "${LAN_INTERFACE}"') for line in dns)


# ---------------------------------------------------------------- rendering


@pytest.mark.parametrize("name", [*_V2_TEMPLATES, "base.nft.template", "portal.nft.template"])
def test_every_deployed_firewall_template_renders_completely(name: str) -> None:
    config = make_config(
        network={"admin_interface": "eth0"},
        admin={"admin_pc_ip": "192.168.1.50", "admin_pc_mac": "02:00:00:00:00:02"},
    )
    rendered = render_template(_text(name), config)
    assert "${" not in rendered


def test_rendering_refuses_without_the_admin_identity() -> None:
    with pytest.raises(
        ConfigurationError, match=r"ADMIN_INTERFACE.*ADMIN_PC_MAC|ADMIN_PC_MAC.*ADMIN_INTERFACE"
    ):
        render_template(_text("base.nft.template"), make_config())


def test_guard_modes_render_into_verdicts_and_infra_is_deduplicated() -> None:
    config = make_config(
        guards={"raw_mode": "enforce", "input_mode": "observe", "forward_mode": "enforce"},
        network={"upstream_gateway": "192.168.1.1"},
    )
    mapping = substitution_mapping(config)
    assert (mapping["RAW_VERDICT"], mapping["INPUT_VERDICT"], mapping["FORWARD_VERDICT"]) == (
        "drop",
        "",
        "drop",
    )
    assert mapping["INFRA4_ELEMENTS"] == "192.168.1.1, 192.168.1.2, 192.168.1.50"
    assert mapping["LAN_BROADCAST"] == "192.168.1.255"
    assert mapping["UDP_FWD_PPS"] == "20000" and mapping["UDP_FWD_BURST"] == "40000"
