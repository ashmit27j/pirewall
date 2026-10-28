"""The v2 kernel data plane on real nft, through `NftablesSetBackend` + `FirewallManager` (env=sandbox).

Ports docs/v2/v2/test_ruleset.py assertions 1-13 (same traffic, same pass
criteria) and adds the phase-13 cases: a MAC block that still reaches DHCP,
DNS and the portal (C4); kill switch then panic through the manager; reload
idempotency with live elements; fail-open shutdown leaving the guards
active; reconcile against live sets; and both transports.

Sandbox regression evidence only. None of these numbers are Pi numbers.
"""

import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from pirewall.core import nft_names
from pirewall.core.enums import FirewallAction, GuardMode, GuardName, NftTransportKind, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.nft_transport import SubprocessTransport
from pirewall.firewall.backend.nftables_sets import NftablesSetBackend
from pirewall.firewall.manager import FirewallManager, SubmissionResult
from pirewall.firewall.sets import SetOp, SetOpKind
from tests.helpers.rules import make_candidate
from tests.helpers.ruleset_diff import assert_only_allowed_changes, changed_objects
from tests.netns.testbed import (
    AD,
    IP,
    MAC,
    ROUTER_LAN_MAC,
    ST,
    Testbed,
    accusatory_sets_holding,
    counter,
    curl_ok,
    elems,
    hping,
    nft,
    offender_codes,
    scapy,
    sh,
)

MAC_BY_IP = {IPv4Address(IP[client]): MAC[client] for client in ("a", "l", "w")}
LEGIT_HITS: list[tuple[str, list[str]]] = []
# A resolver query to the Pi from inside a client namespace; prints the reply.
DNS_TO_PI = (
    "python3 -c \"import socket;s=socket.socket(2,2);s.settimeout(2);"
    "s.sendto(b'q',('192.168.100.1',53));print(s.recv(64))\""
)
RENDERED_GUARDS = {
    GuardName.RAW: GuardMode.ENFORCE,
    GuardName.INPUT: GuardMode.ENFORCE,
    GuardName.FORWARD: GuardMode.ENFORCE,
}


@dataclass
class Plane:
    """One test's view: the testbed, a fresh manager on the real kernel, and its backend."""

    bed: Testbed
    backend: NftablesSetBackend
    manager: FirewallManager
    decisions: int = 0

    def submit(
        self, action: FirewallAction, source: str, evidence: str = "netns", **fields: object
    ) -> SubmissionResult:
        self.decisions += 1
        now = datetime.now(UTC)
        candidate = make_candidate(
            decision_id=f"netns-{self.decisions}",
            action=action,
            source=f"{source}/32",
            destination=f"{IP['v']}/32",
            created_at=now,
            expires_at=now + timedelta(seconds=600),
            evidence=(f"{evidence}-{self.decisions}",),
            **fields,
        )
        self.manager.register_decision(
            FirewallDecision.model_validate(
                {
                    "id": candidate.decision_id,
                    "threat_assessment_id": "netns",
                    "action": action,
                    "threat_score": candidate.threat_score,
                    "threat_level": ThreatLevel.CRITICAL,
                    "reason": "netns",
                    "decided_at": now,
                }
            )
        )
        return self.manager.submit_candidate(candidate, now)


def seed(backend: NftablesSetBackend) -> None:
    """The bindings and allowlist the sandbox seeded, written through the backend (phase 14's path)."""
    ops: list[SetOp] = []
    for client in ("a", "l", "w"):
        for family, table in (
            (nft_names.INET_FAMILY, nft_names.STATIC_TABLE),
            (nft_names.ARP_FAMILY, nft_names.STATIC_ARP_TABLE),
        ):
            ops.append(
                SetOp(SetOpKind.ADD, nft_names.SET_BOUND4, IP[client], 3600, table=table, family=family)
            )
            ops.append(
                SetOp(
                    SetOpKind.ADD,
                    nft_names.SET_MACBIND,
                    (IP[client], MAC[client]),
                    3600,
                    table=table,
                    family=family,
                )
            )
    for table in (nft_names.STATIC_TABLE, nft_names.ADAPTIVE_TABLE):
        ops.append(SetOp(SetOpKind.ADD, nft_names.SET_ALLOW_BOUND, (MAC["w"], IP["w"]), table=table))
    backend.apply(ops)


@pytest.fixture(scope="module")
def seeded(testbed: Testbed) -> Testbed:
    seed(NftablesSetBackend())
    return testbed


@pytest.fixture
def plane(seeded: Testbed, request: pytest.FixtureRequest) -> Iterator[Plane]:
    seeded.reset()
    backend = NftablesSetBackend()
    backend.set_guard_modes(RENDERED_GUARDS)
    manager = FirewallManager(
        seeded.config, FakeFirewallBackend(), set_backend=backend, mac_resolver=MAC_BY_IP.get
    )
    yield Plane(seeded, backend, manager)
    if "uses_legit_mac" not in request.keywords:
        hits = accusatory_sets_holding(MAC["l"])
        if hits:
            test_name: str = getattr(request, "node").name  # noqa: B009 (pytest leaves `node` untyped)
            LEGIT_HITS.append((test_name, hits))


def during(flood: Callable[[], object], checks: list[Callable[[], bool]]) -> list[bool]:
    thread = threading.Thread(target=flood)
    thread.start()
    time.sleep(0.7)
    results = [check() for check in checks]
    thread.join()
    return results


# ------------------------------------------------------------------- 1: floods


def test_1a_syn_flood_to_the_pi(plane: Plane) -> None:
    legit = during(
        lambda: hping("pw_a", f"-S -p 8080 -c 30000 -i u100 -q {IP['r']}"),
        [lambda: curl_ok("pw_l", f"http://{IP['r']}:8080/"), lambda: curl_ok("pw_l", f"http://{IP['v']}/")],
    )
    reached = counter("inet obs", "syn8080")
    assert 1 in offender_codes(MAC["a"])
    assert reached < 3000, reached
    assert all(legit)


def test_1b_syn_flood_through_the_pi(plane: Plane) -> None:
    legit = during(
        lambda: hping("pw_a", f"-S -p 80 -c 30000 -i u100 -q {IP['v']}"),
        [lambda: curl_ok("pw_l", f"http://{IP['v']}/")],
    )
    assert 1 in offender_codes(MAC["a"])
    assert counter("inet obs", "syn_victim") < 3000
    assert all(legit)


def test_1c_udp_flood_through_the_pi(plane: Plane) -> None:
    before = plane.bed.readcount("v_udp9999")
    legit = during(
        lambda: hping("pw_a", f"--udp -p 9999 -s 40000 -k -d 32 -c 30000 -i u100 -q {IP['v']}"),
        [lambda: curl_ok("pw_l", f"http://{IP['v']}/")],
    )
    time.sleep(0.5)
    assert 8 in offender_codes(MAC["a"])
    assert plane.bed.readcount("v_udp9999") - before < 15000
    assert all(legit)


def test_1d_icmp_flood(plane: Plane) -> None:
    hping("pw_a", f"--icmp -c 15000 -i u100 -q {IP['r']}")
    hping("pw_a", f"--icmp -c 15000 -i u100 -q {IP['v']}")
    assert 3 in offender_codes(MAC["a"])
    assert counter(ST, "c_verdict_raw") > 20000
    assert sh("pw_l", f"ping -c2 -W1 -q {IP['v']}").returncode == 0


# ------------------------------------------------------------ 2-5: anti-spoof


def test_2_random_source_flood(plane: Plane) -> None:
    sent = 20000
    hping("pw_a", f"-S --rand-source -p 8080 -c {sent} -i u100 -q {IP['r']}")
    dropped = counter(ST, "c_bogon") + counter(ST, "c_rpf") + counter(ST, "c_spoof")
    assert dropped > sent * 0.95
    assert counter("inet obs", "syn8080") < 200
    assert len(elems(ST, "syn_meter")) <= 1


def test_3a_spoofing_a_bound_neighbour(plane: Plane) -> None:
    hping("pw_a", f"-S -a {IP['l']} -p 8080 -c 2000 -i u500 -q {IP['r']}")
    assert counter(ST, "c_spoof") >= 1980
    assert counter("inet obs", "syn8080") == 0
    assert accusatory_sets_holding(MAC["l"]) == []


def test_3b_arp_poisoning_of_a_bound_ip(plane: Plane) -> None:
    sh("pw_r", f"ping -c1 -W1 {IP['l']} >/dev/null")
    scapy(
        "pw_a",
        f"sendp(Ether(src='{MAC['a']}',dst='02:00:00:00:01:01')/ARP(op=2,hwsrc='{MAC['a']}',psrc='{IP['l']}',"
        f"hwdst='02:00:00:00:01:01',pdst='{IP['r']}'),iface='eth0',count=20,verbose=0)",
    )
    assert counter("arp pirewall_static_arp", "c_arp_spoof") >= 20
    assert MAC["l"] in sh("pw_r", f"ip neigh show {IP['l']}").stdout


def test_4_allowlisted_device_is_unmetered_and_unspoofable(plane: Plane) -> None:
    hping("pw_w", f"-S -p 8080 -c 20000 -i u100 -q {IP['r']}")
    assert counter("inet obs", "syn8080") > 19000
    assert accusatory_sets_holding(MAC["w"]) == []
    hping("pw_a", f"-S -a {IP['w']} -p 8080 -c 2000 -i u500 -q {IP['r']}")
    assert counter(ST, "c_spoof") >= 1980


def test_5_admin_survives_a_flood_and_cannot_be_spoofed(plane: Plane) -> None:
    admin = during(
        lambda: hping("pw_a", f"-S -p 8443 -c 30000 -i u100 -q {IP['adm_r']}"),
        [lambda: curl_ok("pw_ad", f"http://{IP['adm_r']}:8443/")] * 2,
    )
    assert all(admin)
    plane.bed.reset()
    hping("pw_a", f"-S -a {IP['ad']} -p 8443 -c 1000 -i u500 -q {IP['adm_r']}")
    assert counter(ST, "c_bogon") >= 990
    assert counter("inet obs", "api8443_in") == 0
    assert not curl_ok("pw_a", f"http://{IP['adm_r']}:8443/")


# -------------------------------------------------- 6: guard flips (manager)


def test_6_observe_enforce_flip_through_the_manager(plane: Plane) -> None:
    now = datetime.now(UTC)
    for guard in (GuardName.RAW, GuardName.INPUT):
        plane.manager.set_guard_mode(guard, GuardMode.OBSERVE, "netns", now)
    hping("pw_a", f"-S -p 8080 -c 10000 -i u100 -q {IP['r']}")
    observe_reached, observe_codes = counter("inet obs", "syn8080"), offender_codes(MAC["a"])
    plane.bed.reset()
    for guard in (GuardName.RAW, GuardName.INPUT):
        plane.manager.set_guard_mode(guard, GuardMode.ENFORCE, "netns", now)
    hping("pw_a", f"-S -p 8080 -c 10000 -i u100 -q {IP['r']}")
    enforce_reached = counter("inet obs", "syn8080")
    modes = plane.manager.guard_modes(now)
    assert observe_reached > 9500 and 1 in observe_codes, "observe still records offenders"
    assert enforce_reached < 2000
    assert (modes.raw, modes.input) == (GuardMode.ENFORCE, GuardMode.ENFORCE)
    rules = [line for line in nft(f"list chain {ST} guard_verdict_raw").splitlines() if "counter" in line]
    assert len(rules) == 1, "one rule per verdict chain in either mode"


# -------------------------------------- 7: block, rate limit, kill switch, panic


@pytest.mark.uses_legit_mac
def test_7_block_rate_limit_kill_switch_and_panic(plane: Plane) -> None:
    blocked = plane.submit(FirewallAction.BLOCK, IP["a"])
    assert blocked.rule is not None, blocked.event.reason
    assert elems(AD, "block_mac") == [MAC["a"]]
    assert not curl_ok("pw_a", f"http://{IP['v']}/")
    assert counter(AD, "c_block_mac") > 0

    limited = plane.submit(FirewallAction.RATE_LIMIT, IP["l"])
    assert limited.rule is not None, limited.event.reason
    flood_ping = sh("pw_l", f"ping -f -c 500 -W1 -q {IP['v']}").stdout
    assert "packet loss" in flood_ping and " 0% packet loss" not in flood_ping

    plane.manager.revert_to_base(datetime.now(UTC))
    assert curl_ok("pw_a", f"http://{IP['v']}/")
    tables = nft("list tables")
    assert "pirewall_static" in tables and "pirewall_adaptive" in tables and "pirewall_base" in tables
    assert all(plane.backend.guard_mode(guard) is GuardMode.OBSERVE for guard in GuardName)

    result, _event = plane.manager.panic("netns", datetime.now(UTC))
    after = nft("list tables")
    assert (
        "pirewall_static" not in after
        and "pirewall_adaptive" not in after
        and "pirewall_static_arp" not in after
    )
    assert "pirewall_base" in after
    assert result.restore_command
    assert curl_ok("pw_l", f"http://{IP['v']}/")
    assert not curl_ok("pw_a", f"http://{IP['adm_r']}:8443/"), "base still refuses LAN -> API"

    plane.bed.load()
    seed(plane.backend)


# --------------------------------------------- 8: reload with live elements


def test_8_reload_twice_is_idempotent_with_live_elements(plane: Plane) -> None:
    hping("pw_a", f"-S -p 8080 -c 3000 -i u100 -q {IP['r']}")
    assert plane.submit(FirewallAction.BLOCK, IP["a"]).rule is not None

    def census() -> dict[str, int]:
        return {
            "bound4": len(elems(ST, "bound4")),
            "macbind": len(elems(ST, "macbind")),
            "allow_bound": len(elems(ST, "allow_bound")),
            "offenders": len(elems(ST, "offenders")),
            "block_mac": len(elems(AD, "block_mac")),
            "infra4": len(elems(AD, "infra4")),
        }

    before = census()
    rules_before = nft(f"-j list table {ST}").count('"rule"')
    plane.bed.load()
    plane.bed.load()
    assert census() == before
    assert nft(f"-j list table {ST}").count('"rule"') == rules_before
    assert before["offenders"] > 0 and before["block_mac"] == 1


# ----------------------------------------- D1 ruleset diff on the real kernel


@pytest.mark.uses_legit_mac
def test_d1_every_manager_operation_changes_only_what_d1_allows(plane: Plane) -> None:
    """`nft -j list ruleset` before and after each core operation (D1 invariant), on real nft."""
    pristine = plane.backend.snapshot()
    now = datetime.now(UTC)
    assert plane.submit(FirewallAction.RATE_LIMIT, IP["a"]).rule is not None
    assert plane.submit(FirewallAction.BLOCK, IP["a"]).rule is not None  # atomic upgrade
    assert plane.submit(FirewallAction.BLOCK, IP["l"]).rule is not None
    plane.manager.set_guard_mode(GuardName.FORWARD, GuardMode.OBSERVE, "netns", now)
    after_writes = plane.backend.snapshot()
    assert_only_allowed_changes(pristine, after_writes)
    block_mac = (nft_names.INET_FAMILY, nft_names.ADAPTIVE_TABLE, "set", nft_names.SET_BLOCK_MAC)
    assert block_mac in changed_objects(pristine, after_writes), "the diff does see real writes"
    plane.manager.revert_to_base(now)
    assert_only_allowed_changes(after_writes, plane.backend.snapshot())
    before_panic = plane.backend.snapshot()
    plane.manager.panic("netns", now)
    after_panic = plane.backend.snapshot()
    assert_only_allowed_changes(before_panic, after_panic, allow_panic=True)
    assert (nft_names.INET_FAMILY, nft_names.BASE_TABLE) in after_panic
    plane.bed.load()
    seed(plane.backend)


# ------------------------------------------------------- 9-13: remaining guards


def test_9_established_flow_udp_flood_to_responding_dns(plane: Plane) -> None:
    sh(
        "pw_a",
        "python3 -c \"import socket;s=socket.socket(2,2);s.bind(('192.168.100.20',40053));s.settimeout(1);"
        "s.sendto(b'q',('192.168.100.1',53));print(s.recv(64))\"",
    )
    before = plane.bed.readcount("r_udp53")
    hping("pw_a", f"--udp -s 40053 -k -p 53 -d 32 -c 30000 -i u100 -q {IP['r']}")
    time.sleep(0.5)
    codes = offender_codes(MAC["a"])
    assert 2 in codes or 4 in codes
    assert plane.bed.readcount("r_udp53") - before < 3000
    legit = sh(
        "pw_l",
        DNS_TO_PI,
    ).stdout
    assert "b'" in legit


def test_10a_fragments_are_dropped_before_defrag(plane: Plane) -> None:
    assert sh("pw_a", f"ping -c3 -W1 -s 4000 {IP['r']}").returncode != 0
    assert counter(ST, "c_frag") >= 6
    assert sh("pw_a", f"ping -c1 -W1 {IP['r']}").returncode == 0


def test_10b_ipv6_from_the_lan_is_dropped(plane: Plane) -> None:
    if not Path("/proc/sys/net/ipv6").exists():
        pytest.skip("this kernel has no IPv6 stack; the rule loads, verify on the Pi")
    scapy(
        "pw_a",
        f"e=Ether(src='{MAC['a']}',dst='02:00:00:00:01:01')\n"
        "sendp([e/IPv6(src='fe80::20',dst='fe80::1')/ICMPv6EchoRequest(), "
        "e/IPv6(src='2001:db8::20',dst='2001:db8::1')/UDP(dport=53)]*5,iface='eth0',verbose=0)",
    )
    assert counter(ST, "c_ipv6") >= 10


def test_11_meter_fill_engages_the_global_backstop(plane: Plane) -> None:
    scapy(
        "pw_a",
        "import random\n"
        "def m(): return '02:%02x:%02x:%02x:%02x:%02x'%tuple(random.randint(0,255) for _ in range(5))\n"
        "pk=[Ether(src=m(),dst='02:00:00:00:01:01')/IP(src='192.168.100.%d'%random.randint(100,250),dst='192.168.100.1')"
        "/TCP(sport=random.randint(1024,65535),dport=8080,flags='S') for _ in range(6000)]\n"
        "sendp(pk,iface='eth0',verbose=0)",
    )
    size = plane.bed.config.guards.meter_set_size
    assert all(len(elems(ST, name)) <= size for name in ("unbound_meter", "syn_meter", "pps_meter"))
    assert counter(ST, "c_bk_unbound") > 0 or counter(ST, "c_bk_syn") > 0


def test_12_dns_and_dot_bypassing_the_pi_are_blocked(plane: Plane) -> None:
    before53, before853 = plane.bed.readcount("v_udp53"), plane.bed.readcount("v_tcp853")
    sh(
        "pw_l",
        "python3 -c \"import socket;s=socket.socket(2,2);"
        "[s.sendto(b'q',('10.99.0.2',53)) for _ in range(20)]\"",
    )
    dot = sh("pw_l", "timeout 3 bash -c 'echo > /dev/tcp/10.99.0.2/853'").returncode
    time.sleep(0.5)
    assert plane.bed.readcount("v_udp53") == before53
    assert plane.bed.readcount("v_tcp853") == before853
    assert dot != 0
    assert counter(ST, "c_dns_bypass") >= 20


def test_13_dhcp_from_unconfigured_clients_passes_with_a_per_mac_brake(plane: Plane) -> None:
    discover = (
        "p=Ether(src='{mac}',dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0',dst='255.255.255.255')/UDP(sport=68,dport=67)"
        "/BOOTP(xid=1)/DHCP(options=[('message-type','discover'),'end'])\n"
        "sendp(p,iface='eth0',count={count},verbose=0)"
    )
    scapy("pw_a", discover.format(mac="02:aa:bb:cc:dd:01", count=3))
    first = counter("inet obs", "dhcp67_in")
    scapy("pw_a", discover.format(mac="02:aa:bb:cc:dd:02", count=40))
    burst = counter("inet obs", "dhcp67_in") - first
    assert first == 3
    assert burst <= 10
    assert 67 in offender_codes("02:aa:bb:cc:dd:02")


# ------------------------------------------------------ phase 13 additions


def test_c4_a_blocked_mac_still_reaches_dhcp_dns_and_the_portal(plane: Plane) -> None:
    assert plane.submit(FirewallAction.BLOCK, IP["a"]).rule is not None
    assert not curl_ok("pw_a", f"http://{IP['v']}/"), "the block holds for everything else"
    assert curl_ok("pw_a", f"http://{IP['r']}:8080/"), "the portal (block notice) is reachable"
    dns = sh(
        "pw_a",
        DNS_TO_PI,
    ).stdout
    assert "b'" in dns, "the resolver on the Pi answers"
    before = counter("inet obs", "dhcp67_in")
    scapy(
        "pw_a",
        f"p=Ether(src='{MAC['a']}',dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0',dst='255.255.255.255')/UDP(sport=68,dport=67)"
        "/BOOTP(xid=7)/DHCP(options=[('message-type','discover'),'end'])\nsendp(p,iface='eth0',count=2,verbose=0)",
    )
    assert counter("inet obs", "dhcp67_in") - before == 2, "a blocked device can still renew its lease"
    dropped = counter(AD, "c_block_mac")
    scapy(
        "pw_a",
        f"sendp(Ether(src='{MAC['a']}',dst='{ROUTER_LAN_MAC}')/IP(src='{IP['a']}',dst='{IP['v']}')"
        "/UDP(sport=68,dport=67)/Raw(b'x'*8),iface='eth0',count=3,verbose=0)",
    )
    assert counter(AD, "c_block_mac") - dropped == 3, "the DHCP exemption does not reach outside hosts"


def test_fail_open_shutdown_leaves_the_guards_enforcing(plane: Plane) -> None:
    assert plane.submit(FirewallAction.BLOCK, IP["a"]).rule is not None
    plane.manager.fail_open_shutdown(datetime.now(UTC))
    assert elems(AD, "block_mac") == []
    assert all(plane.backend.guard_mode(guard) is GuardMode.ENFORCE for guard in GuardName)
    hping("pw_a", f"-S -p 8080 -c 10000 -i u100 -q {IP['r']}")
    assert counter("inet obs", "syn8080") < 2000, "the static guard keeps dropping with core gone"


def test_reconcile_adopts_live_elements_from_a_previous_run(plane: Plane) -> None:
    first = FirewallManager(plane.bed.config, FakeFirewallBackend(), set_backend=plane.backend)
    stale = Plane(plane.bed, plane.backend, first)
    assert stale.submit(FirewallAction.RATE_LIMIT, IP["a"]).rule is not None
    assert elems(AD, "ratelimit4") == [IP["a"]]
    report = plane.manager.reconcile(datetime.now(UTC))
    assert report.adopted == [f"reconciled:{nft_names.SET_RATELIMIT4}:{IP['a']}"]
    assert report.missing_tables == []
    assert plane.manager.restrictive_rules_matching(IPv4Address(IP["a"]))


def test_both_transports_write_the_same_kernel_state(plane: Plane) -> None:
    subprocess_backend = NftablesSetBackend(SubprocessTransport())
    assert subprocess_backend.transport is NftTransportKind.SUBPROCESS
    subprocess_backend.add_element(nft_names.SET_BLOCK4, "192.168.100.77", 120)
    assert [state.key for state in plane.backend.list_set(nft_names.SET_BLOCK4)] == ["192.168.100.77"]
    plane.backend.delete_element(nft_names.SET_BLOCK4, "192.168.100.77")
    plane.backend.delete_element(nft_names.SET_BLOCK4, "192.168.100.77")  # idempotent
    assert subprocess_backend.list_set(nft_names.SET_BLOCK4) == []
    metrics = plane.backend.metrics()
    assert metrics.calls > 0 and metrics.failures == 0
    print(f"set backend transport in use: {plane.backend.transport.value}")


def test_3c_the_legit_mac_never_entered_an_accusatory_set() -> None:
    assert LEGIT_HITS == []
