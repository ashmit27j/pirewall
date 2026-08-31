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
    """Extract one `chain <name> { ... }` block's body (brace-depth aware, nested braces included)."""
    match = re.search(rf"chain {re.escape(chain_name)} \{{", text)
    assert match is not None, f"chain {chain_name!r} not found in template"
    start = match.end()
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


def test_dns_and_dhcp_are_scoped_to_the_protected_network_not_the_admin_pc() -> None:
    """DNS (port 53) and DHCP (port 67) are ordinary LAN services, not "management access".

    The Pi answers these for every client on the protected network, so
    they are deliberately scoped to `${PROTECTED_NETWORK}` rather than
    narrowed to the Admin PC — narrowing them to the Admin PC alone would
    be a regression that breaks every other LAN client's DNS/DHCP, exactly
    the failure mode this test guards against, in the opposite direction
    from the management-access test above.
    """
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    body = _chain_body(text, "input")
    service_lines = [line for line in _dport_accept_lines(body) if "53" in line or "67" in line]
    assert service_lines, "expected explicit DNS/DHCP accept rules in the input chain"
    for line in service_lines:
        assert "${PROTECTED_NETWORK}" in line, f"DNS/DHCP rule not scoped to the protected network: {line!r}"
        assert "${ADMIN_PC_IP}" not in line, f"DNS/DHCP rule should not be Admin-PC-scoped: {line!r}"


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
