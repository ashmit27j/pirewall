"""Phase 14's MAC identity path on real nft: lease file → bindings → `FirewallManager` (env=sandbox).

`test_kernel_data_plane.py` seeds its bindings with raw `SetOp`s and gives
the manager a dict as its MAC resolver. This module drives the real chain
instead: a dnsmasq lease file plus `[[antispoof.static]]`, parsed by
`LeaseSync`, written by `FirewallManager.replace_bindings` /
`sync_bindings`, with `LeaseBindingTable.resolve_mac` as the manager's
resolver. It covers the prompt's netns cases: spoofing a bound neighbour is
dropped and the neighbour is never accused; a MAC-keyed BLOCK resolved from
a lease still reaches DHCP, DNS and the portal notice. It also covers the
`ip . mac` portal gate and the MAC-pinned allowlist on the kernel.

Sandbox regression evidence only. None of these numbers are Pi numbers.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

import pytest
from scripts.deployment.render_templates import render_template

from pirewall.config.models import AntispoofConfig, StaticBindingEntry
from pirewall.core import nft_names
from pirewall.core.bindings import LeaseBindingTable, static_bindings
from pirewall.core.enums import FirewallAction, GuardMode, GuardName, ThreatLevel
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.event import SecurityEvent
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.nftables import NftablesBackend
from pirewall.firewall.backend.nftables_sets import NftablesSetBackend
from pirewall.firewall.manager import FirewallManager, SubmissionResult
from pirewall.runtime.lease_sync import LeaseSync
from tests.helpers.rules import make_candidate
from tests.netns.testbed import (
    AD,
    IP,
    MAC,
    REPO,
    ST,
    Testbed,
    accusatory_sets_holding,
    counter,
    curl_ok,
    elems,
    hping,
    sh,
)

ARP = "arp pirewall_static_arp"
MOVED_MAC = "02:00:00:00:00:99"
LEGIT_HITS: list[tuple[str, list[str]]] = []
DNS_TO_PI = (
    'python3 -c "import socket;s=socket.socket(2,2);s.settimeout(2);'
    "s.sendto(b'q',('192.168.100.1',53));print(s.recv(64))\""
)


@dataclass
class Identity:
    """One test's view: a lease file, the binding table, lease sync and a manager resolving through it."""

    bed: Testbed
    lease_file: Path
    table: LeaseBindingTable
    sync: LeaseSync
    backend: NftablesSetBackend
    manager: FirewallManager
    events: list[SecurityEvent]
    decisions: int = 0

    def write_leases(self, pairs: dict[str, str]) -> None:
        expiry = int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
        # Hostname and client-id fields are present, as dnsmasq writes them, and must be ignored.
        self.lease_file.write_text(
            "".join(f"{expiry} {mac} {ip} host-{i} 01:{mac}\n" for i, (ip, mac) in enumerate(pairs.items())),
            encoding="utf-8",
        )

    def submit(self, action: FirewallAction, source: str) -> SubmissionResult:
        self.decisions += 1
        now = datetime.now(UTC)
        candidate = make_candidate(
            decision_id=f"netns14-{self.decisions}",
            action=action,
            source=f"{source}/32",
            destination=f"{IP['v']}/32",
            created_at=now,
            expires_at=now + timedelta(seconds=600),
            evidence=(f"netns14-{self.decisions}",),
        )
        self.manager.register_decision(
            FirewallDecision.model_validate(
                {
                    "id": candidate.decision_id,
                    "threat_assessment_id": "netns14",
                    "action": action,
                    "threat_score": candidate.threat_score,
                    "threat_level": ThreatLevel.CRITICAL,
                    "reason": "netns14",
                    "decided_at": now,
                }
            )
        )
        return self.manager.submit_candidate(candidate, now)


@pytest.fixture
def identity(testbed: Testbed, request: pytest.FixtureRequest) -> Iterator[Identity]:
    testbed.reset()
    lease_file = testbed.state / "dnsmasq-lan0.leases"
    antispoof = AntispoofConfig(
        lease_file=str(lease_file),
        static=(StaticBindingEntry(ip=IPv4Address(IP["w"]), mac=MAC["w"], reason="netns static device"),),
    )
    config = testbed.config.model_copy(update={"antispoof": antispoof})
    backend = NftablesSetBackend()
    backend.set_guard_modes(dict.fromkeys(GuardName, GuardMode.ENFORCE))
    table = LeaseBindingTable(static_bindings(config.antispoof.static))
    manager = FirewallManager(
        config, FakeFirewallBackend(), set_backend=backend, mac_resolver=table.resolve_mac
    )
    events: list[SecurityEvent] = []
    sync = LeaseSync(config, table, manager, events.append)
    view = Identity(testbed, lease_file, table, sync, backend, manager, events)
    view.write_leases({IP["a"]: MAC["a"], IP["l"]: MAC["l"]})
    assert view.sync.seed(), [event.reason for event in events]
    yield view
    hits = accusatory_sets_holding(MAC["l"])
    if hits:
        test_name: str = getattr(request, "node").name  # noqa: B009 (pytest leaves `node` untyped)
        LEGIT_HITS.append((test_name, hits))


def test_14a_the_seed_writes_leases_and_static_entries_to_both_binding_tables(identity: Identity) -> None:
    pairs = {(IP["a"], MAC["a"]), (IP["l"], MAC["l"]), (IP["w"], MAC["w"])}
    for table in (ST, ARP):
        assert set(elems(table, nft_names.SET_MACBIND)) == pairs, table
        assert set(elems(table, nft_names.SET_BOUND4)) == {IP["a"], IP["l"], IP["w"]}, table
    assert identity.backend.guard_mode(GuardName.RAW) is GuardMode.ENFORCE
    assert identity.table.resolve_mac(IPv4Address(IP["l"])) == MAC["l"]


def test_14b_spoofing_a_lease_bound_neighbour_is_dropped_and_never_accuses_it(identity: Identity) -> None:
    hping("pw_a", f"-S -a {IP['l']} -p 8080 -c 2000 -i u500 -q {IP['r']}")
    assert counter(ST, "c_spoof") >= 1980
    assert counter("inet obs", "syn8080") == 0
    assert accusatory_sets_holding(MAC["l"]) == []
    assert curl_ok("pw_l", f"http://{IP['v']}/"), "the real neighbour is unaffected"


def test_14c_a_lease_moving_to_a_new_mac_rebinds_on_the_kernel(identity: Identity) -> None:
    identity.write_leases({IP["a"]: MAC["a"], IP["l"]: MOVED_MAC})
    assert identity.sync.poll() > 0
    for table in (ST, ARP):
        macbind = set(elems(table, nft_names.SET_MACBIND))
        assert (IP["l"], MOVED_MAC) in macbind, table
        assert (IP["l"], MAC["l"]) not in macbind, f"{table}: the old pair is gone"
        assert IP["l"] in elems(table, nft_names.SET_BOUND4), f"{table}: the IP stays bound"
    # Put it back, so the neighbour is itself again for the rest of the module.
    identity.write_leases({IP["a"]: MAC["a"], IP["l"]: MAC["l"]})
    assert identity.sync.poll() > 0
    assert (IP["l"], MAC["l"]) in elems(ST, nft_names.SET_MACBIND)


def test_14d_a_block_resolved_through_the_lease_is_mac_keyed_and_spares_dhcp_dns_portal(
    identity: Identity,
) -> None:
    result = identity.submit(FirewallAction.BLOCK, IP["a"])
    assert result.rule is not None
    assert result.rule.target is not None and result.rule.target.mac == MAC["a"]
    assert elems(AD, nft_names.SET_BLOCK_MAC) == [MAC["a"]]
    assert elems(AD, nft_names.SET_BLOCK4) == []
    assert not curl_ok("pw_a", f"http://{IP['v']}/"), "the block holds for everything else"
    assert curl_ok("pw_a", f"http://{IP['r']}:8080/"), "the portal (block notice) is reachable"
    assert "b'" in sh("pw_a", DNS_TO_PI).stdout, "the resolver on the Pi answers"
    assert identity.manager.blocking_rules_matching(IPv4Address(IP["a"])), "C4 finds the block by IP→MAC"
    assert curl_ok("pw_l", f"http://{IP['v']}/"), "the neighbour is not caught by the block"


def test_14e_a_mac_pinned_allowlist_entry_reaches_both_allow_bound_sets(identity: Identity) -> None:
    for table in (ST, AD):
        assert elems(table, nft_names.SET_ALLOW_BOUND) == [], "a fresh testbed holds no allowlist pairs"
    entry = AllowlistEntry(
        target=IPv4Network(f"{IP['w']}/32"),
        mac=MAC["w"],
        reason="netns allowlist",
        created_at=datetime.now(UTC),
        created_by="netns",
    )
    identity.manager.add_allowlist_entry(entry)
    try:
        for table in (ST, AD):
            assert elems(table, nft_names.SET_ALLOW_BOUND) == [(MAC["w"], IP["w"])], table
        hping("pw_w", f"-S -p 8080 -c 20000 -i u100 -q {IP['r']}")
        assert counter("inet obs", "syn8080") > 19000, "the allowlisted pair is unmetered"
        refused = identity.submit(FirewallAction.BLOCK, IP["w"])
        assert refused.rule is None, "the validator refuses an allowlisted target"
    finally:
        identity.manager.remove_allowlist_entry(entry.id)
    for table in (ST, AD):
        assert elems(table, nft_names.SET_ALLOW_BOUND) == [], table


def test_14f_the_portal_gate_matches_the_session_mac_not_just_the_ip(identity: Identity) -> None:
    template = (REPO / "deploy" / "firewall" / "portal.nft.template").read_text(encoding="utf-8")
    rendered = identity.bed.state / "portal.nft"
    rendered.write_text(render_template(template, identity.bed.config), encoding="utf-8")
    sh("pw_r", f"nft -f {rendered}", check=True)
    # Portal grants go through the manager's v1 backend; here it must be the real one.
    portal = NftablesBackend(rate_limit_per_second=10)
    manager = FirewallManager(
        identity.bed.config, portal, set_backend=identity.backend, mac_resolver=identity.table.resolve_mac
    )
    client = IPv4Address(IP["l"])

    # Forwarded ICMP probes the forward gate. HTTP would not: an unsigned
    # client's port 80 is redirected to the portal, which answers.
    def forwards() -> bool:
        return sh("pw_l", f"ping -c2 -W1 -q {IP['v']}").returncode == 0

    try:
        assert not forwards(), "not signed in: gated"
        manager.authorize_portal_client(client, 120, MOVED_MAC)
        assert portal.list_portal_grants() == frozenset({(client, MOVED_MAC)})
        assert not forwards(), "a grant for another MAC does not open the gate"
        manager.deauthorize_portal_client(client)
        assert portal.list_portal_grants() == frozenset()
        manager.authorize_portal_client(client, 120, MAC["l"])
        assert forwards(), "the signed-in device passes"
        assert curl_ok("pw_l", f"http://{IP['v']}/")
    finally:
        sh("pw_r", "nft delete table inet pirewall_portal")


def test_14g_the_legit_mac_never_entered_an_accusatory_set() -> None:
    assert LEGIT_HITS == []
