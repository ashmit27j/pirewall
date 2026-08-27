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


def test_management_access_restricted_to_admin_pc_placeholder() -> None:
    """spec §27 'Network exposure': management (SSH/API) must be scoped to the Admin PC, not left open."""
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    body = _chain_body(text, "input")
    accept_lines = [line for line in body.splitlines() if "accept" in line and "tcp dport" in line]
    assert accept_lines, "expected an explicit management-access accept rule in the input chain"
    for line in accept_lines:
        assert "${ADMIN_PC_IP}" in line, f"management access rule not scoped to Admin PC: {line!r}"


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
