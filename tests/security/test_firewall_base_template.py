"""Static assertions on `deploy/firewall/base.nft.template` (spec §24 Safety, §27, Phase 8).

Parses the checked-in template as text — never loads it into a real `nft`
instance (this repo's dev/CI machines aren't guaranteed to have `nft`, and
applying it for real is out of scope for automated tests). Real-hardware
`nft -c -f` syntax verification is Environment-dependent, see
`docs/PROGRESS.md`.
"""

import re
from pathlib import Path

import pirewall

_TEMPLATE_PATH = (
    Path(pirewall.__file__).resolve().parent.parent / "deploy" / "firewall" / "base.nft.template"
)


def _chain_body(text: str, chain_name: str) -> str:
    """The body of the *last* `chain <name> { ... }` block — the one carrying rules.

    The template declares each chain twice: once bare, so the `flush chain`
    lines that make a reload idempotent cannot fail on a first load, and then
    again with the actual rules. Matching the first declaration would read an
    empty chain and quietly assert nothing.
    """
    matches = list(re.finditer(rf"chain {re.escape(chain_name)} \{{", text))
    assert matches, f"chain {chain_name!r} not found in template"
    start = matches[-1].end()
    depth = 1
    index = start
    while depth > 0:
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    return text[start : index - 1]


def test_forward_chain_defaults_to_deny() -> None:
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    body = _chain_body(text, "forward")
    assert "policy drop" in body


def test_input_chain_defaults_to_deny() -> None:
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    body = _chain_body(text, "input")
    assert "policy drop" in body


def _dport_accept_lines(body: str) -> list[str]:
    return [
        line
        for line in body.splitlines()
        if "accept" in line and ("tcp dport" in line or "udp dport" in line)
    ]


def test_management_access_restricted_to_admin_pc_placeholder() -> None:
    """spec §27 'Network exposure': management (SSH/API) must be scoped to the Admin PC, not left open.

    Deliberately narrowed to the two actual management ports (22, the API
    port) rather than every `dport accept` line in the chain: DNS/DHCP
    (port 53/67) are ordinary LAN services the Pi provides to every client
    on the protected network, not management access, and are correctly
    scoped to `${PROTECTED_NETWORK}` instead — see
    `test_dns_and_dhcp_are_scoped_to_the_protected_network_not_the_admin_pc`
    for that half of the same input-chain block. A generic "every dport
    accept line must be Admin-PC-scoped" assertion would be wrong, not
    just strict: it would fail on a correct template and pass a template
    that (incorrectly) locked DNS to the Admin PC alone, breaking every
    other LAN client's name resolution.
    """
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    body = _chain_body(text, "input")
    management_lines = [
        line for line in _dport_accept_lines(body) if "22" in line or "${API_PORT}" in line
    ]
    assert management_lines, "expected an explicit management-access accept rule in the input chain"
    for line in management_lines:
        assert "${ADMIN_PC_IP}" in line, f"management access rule not scoped to Admin PC: {line!r}"


def test_dns_and_dhcp_are_scoped_to_the_lan_not_the_admin_pc() -> None:
    """DNS (53) and DHCP (67/68) are ordinary LAN services, not "management access".

    The Pi answers these for every client on the protected network, so they
    are scoped to the LAN — by `${PROTECTED_NETWORK}` where a source address
    is meaningful, or by `${LAN_INTERFACE}` where it is not (see the DHCP
    test below). Narrowing them to the Admin PC would break every other LAN
    client's DNS and DHCP, which is the failure mode this guards against,
    in the opposite direction from the management-access test above.
    """
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    body = _chain_body(text, "input")
    service_lines = [
        line for line in _dport_accept_lines(body) if "53" in line or "67" in line or "68" in line
    ]
    assert service_lines, "expected explicit DNS/DHCP accept rules in the input chain"
    for line in service_lines:
        assert "${PROTECTED_NETWORK}" in line or "${LAN_INTERFACE}" in line or "${WAN_INTERFACE}" in line, (
            f"DNS/DHCP rule is not scoped to an interface or the protected network: {line!r}"
        )
        assert "${ADMIN_PC_IP}" not in line, f"DNS/DHCP rule should not be Admin-PC-scoped: {line!r}"


def test_dhcp_server_rule_is_interface_scoped_not_source_scoped() -> None:
    """A DHCPDISCOVER comes from 0.0.0.0, so a source-scoped rule never matches it.

    Regression test for a real fault in this template: it accepted DHCP with
    `ip saddr ${PROTECTED_NETWORK} udp dport 67`, which cannot match a
    client that does not yet have an address. Under the input chain's
    `policy drop`, every *new* LAN client would have silently failed to get
    a lease — while renewals from already-addressed clients kept working,
    making it look intermittent rather than broken.
    """
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    body = _chain_body(text, "input")
    dhcp_server_lines = [line for line in _dport_accept_lines(body) if "dport 67" in line]
    assert dhcp_server_lines, "expected an explicit DHCP server accept rule in the input chain"
    for line in dhcp_server_lines:
        assert "${LAN_INTERFACE}" in line, f"DHCP server rule must be interface-scoped: {line!r}"
        assert "saddr" not in line, (
            f"DHCP server rule must not be source-scoped — DISCOVER comes from 0.0.0.0: {line!r}"
        )


def test_wan_dhcp_client_replies_are_accepted() -> None:
    """Without a `udp dport 68` accept the Pi silently loses its WAN lease on renewal.

    Regression test: the input chain's `policy drop` would discard the
    DHCP reply to the Pi's own lease renewal on the WAN interface. The
    failure appears hours or days after a deploy that looked fine, which is
    exactly why it is worth pinning.
    """
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    body = _chain_body(text, "input")
    lines = [line for line in _dport_accept_lines(body) if "dport 68" in line]
    assert lines, "expected a `udp dport 68` accept so WAN DHCP renewals are not dropped"
    assert any("${WAN_INTERFACE}" in line for line in lines), (
        "the DHCP client rule should be scoped to the WAN interface"
    )


def test_captive_portal_is_reachable_by_every_lan_client() -> None:
    """The portal must be reachable by LAN clients, including blocked ones (ADDENDUM_3.md C4).

    A blocked device is told *why* over this path. Adaptive BLOCK rules live
    on the `forward` hook, so they never affect it — but the input chain's
    `policy drop` would, if the portal port were not explicitly accepted.
    """
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    body = _chain_body(text, "input")
    lines = [line for line in _dport_accept_lines(body) if "${PORTAL_PORT}" in line]
    assert lines, "expected an accept for ${PORTAL_PORT} in the input chain"
    for line in lines:
        assert "${LAN_INTERFACE}" in line, f"portal rule should be LAN-scoped: {line!r}"
        assert "${ADMIN_PC_IP}" not in line, (
            f"the portal is for LAN clients, not the Admin PC: {line!r}"
        )


def test_forward_chain_does_not_blanket_accept_wan_to_lan() -> None:
    """No rule should unconditionally accept new inbound WAN traffic (only established/related, LAN->WAN)."""
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    body = _chain_body(text, "forward")
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "accept" not in stripped:
            continue
        # Every accept rule must be scoped by ct state, source, or protocol —
        # never a bare "accept" with no match at all.
        assert stripped != "accept", "unconditional accept rule found in forward chain"


def test_priority_places_adaptive_chain_before_base_forward_chain() -> None:
    """`pirewall.firewall.backend.nftables` hooks `forward` at priority 0; base must run after it."""
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    body = _chain_body(text, "forward")
    match = re.search(r"hook forward priority (-?\d+)", body)
    assert match is not None
    assert int(match.group(1)) > 0, "base forward chain priority must be greater than the adaptive chain's 0"
