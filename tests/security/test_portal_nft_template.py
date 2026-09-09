"""`deploy/firewall/portal.nft.template` — the captive-portal gate (ADDENDUM_3.md C2).

Parsed as text; loading it for real needs root and a real `nft`, which stays
Environment-dependent (`docs/PROGRESS.md`).

Two of these are regressions for faults found by running the thing on real
hardware rather than by reading it. Both were invisible to every existing
test because they are properties of *rule order* and *reload behaviour*, not
of the rules themselves.
"""

import re
from pathlib import Path

import pirewall

_REPO_ROOT = Path(pirewall.__file__).resolve().parent.parent
_TEMPLATE = _REPO_ROOT / "deploy" / "firewall" / "portal.nft.template"
_BASE_TEMPLATE = _REPO_ROOT / "deploy" / "firewall" / "base.nft.template"


def _text() -> str:
    return _TEMPLATE.read_text(encoding="utf-8")


def _chain_rules(text: str, chain: str) -> list[str]:
    """The rule lines of the *last* declaration of `chain` — the one carrying rules.

    The template declares each chain twice: once bare, to guarantee it exists
    so the flushes cannot fail on a first load, then again with the rules.
    """
    blocks = re.findall(rf"chain {chain} \{{(.*?)\n\t\}}", text, re.S)
    assert blocks, f"no chain {chain} in the template"
    return [
        line.strip()
        for line in blocks[-1].splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def test_port_80_to_the_pi_itself_is_redirected_to_the_portal() -> None:
    """Regression: DHCP option 114 advertises `http://<pi>/portal`, so port 80 must work.

    A blanket `ip daddr ${PIREWALL_LAN_IP} return` placed before the redirect
    exempts port 80 along with DNS and DHCP. Nothing listens on port 80, so
    that URL reached no DNAT, fell through to the base ruleset's `policy
    drop`, and hung — killing the primary discovery path for every modern
    client while the port-80 redirect appeared, from the ruleset, to be fine.
    """
    rules = _chain_rules(_text(), "prerouting")
    redirect_index = next(
        index for index, rule in enumerate(rules) if "dport 80 redirect" in rule
    )
    for index, rule in enumerate(rules[:redirect_index]):
        if "${PIREWALL_LAN_IP}" in rule and "return" in rule:
            assert "dport" in rule, (
                f"rule {index} exempts the Pi's whole address before the port-80 redirect, "
                f"so DHCP option 114's URL is never redirected: {rule!r}"
            )


def test_the_pi_s_own_services_stay_reachable_before_sign_in() -> None:
    """An unauthenticated client still needs DNS, DHCP, and the portal itself."""
    rules = " ".join(_chain_rules(_text(), "prerouting"))
    assert "udp dport { 53, 67 } return" in rules, "DNS/DHCP to the Pi must not be intercepted"
    assert "tcp dport ${PORTAL_PORT} return" in rules, "the portal itself must not be intercepted"


def test_https_is_not_intercepted() -> None:
    """Redirecting 443 presents a certificate for the wrong name — a warning, not a portal."""
    rules = " ".join(_chain_rules(_text(), "prerouting"))
    assert "dport 443" not in rules


def test_unauthenticated_forwarding_is_rejected_not_dropped() -> None:
    """Reject makes captive-portal detection fail fast; drop leaves clients retransmitting."""
    rules = _chain_rules(_text(), "forward")
    assert any("reject" in rule for rule in rules)
    assert not any(rule == "drop" for rule in rules)


def test_authenticated_clients_fall_through_to_the_adaptive_chain() -> None:
    """Portal gating is a precondition, not a verdict (ADDENDUM_3.md C2).

    `return` rather than `accept`: an authenticated device is not a trusted
    device, and the adaptive chain at priority 0 still gets its say.
    """
    rules = _chain_rules(_text(), "forward")
    assert "ip saddr @authed return" in rules
    assert "ip saddr @authed accept" not in rules


def test_the_gate_runs_before_the_adaptive_and_base_chains() -> None:
    """Priority -10, ahead of adaptive (0) and base (10)."""
    assert "priority -10" in _text()


def test_established_flows_are_not_re_gated() -> None:
    """A session expiring mid-download should stop the next connection, not sever this one."""
    assert "ct state established,related return" in _chain_rules(_text(), "forward")


def test_reloading_the_template_does_not_duplicate_rules() -> None:
    """Regression: `nft -f` appends to an existing chain rather than replacing it.

    Without an explicit flush, every re-run of `pirewall-start` stacked
    another copy of every rule. Observed on hardware at four copies after
    four runs — the chain grows without bound and each packet is matched
    against the same rules repeatedly.
    """
    text = _text()
    for chain in ("forward", "prerouting"):
        assert f"flush chain inet pirewall_portal {chain}" in text, (
            f"portal.nft must flush its {chain} chain, or reloading duplicates every rule"
        )


def test_reloading_does_not_sign_every_client_out() -> None:
    """Flush the chains, never delete the table — the table owns the `authed` set.

    Deleting it would take every signed-in client's authorization with it on
    every reload, which `pirewall-start` performs routinely.
    """
    text = _text()
    assert "delete table" not in text
    assert "flush set" not in text, "flushing the set would sign every client out on reload"


def test_the_base_ruleset_is_also_idempotent() -> None:
    """Same fault, same fix — it was duplicated four times over on hardware too."""
    text = _BASE_TEMPLATE.read_text(encoding="utf-8")
    for chain in ("forward", "input", "output"):
        assert f"flush chain inet pirewall_base {chain}" in text
