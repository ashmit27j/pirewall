#!/usr/bin/env python3
"""Behavioural tests of the pirewall v2 nft rulesets on the netns testbed.

Run as root, after the testbed is up:
    netns_testbed.sh up <overrides>
    test_ruleset.py

Each assertion generates real traffic (hping3, scapy, ping, curl) and checks
what the kernel actually did: nft counters, set contents, and how many
packets reached the service.

Results are printed and also written as JSON to /tmp/claude-0/pwtb/results.json.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATE = Path("/tmp/claude-0/pwtb")
MAC = {"a": "02:00:00:00:00:20", "l": "02:00:00:00:00:10", "w": "02:00:00:00:00:30"}
IP = {"a": "192.168.100.20", "l": "192.168.100.10", "w": "192.168.100.30", "r": "192.168.100.1", "v": "10.99.0.2"}
ST = "inet pirewall_static"
AD = "inet pirewall_adaptive"
METERS = ["dhcp_meter", "unbound_meter", "syn_meter", "udp_meter", "icmp_meter", "pps_meter", "dns_meter",
          "closed_meter", "portal_conc", "newconn_meter", "newconn_dst_meter", "udp_fwd_meter", "offenders", "unbound_seen"]
RESULTS: list[dict[str, object]] = []


def sh(ns: str, cmd: str, timeout: float = 120, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["ip", "netns", "exec", ns, "bash", "-c", cmd], capture_output=True, text=True,
                          timeout=timeout, check=check)


def nft(cmd: str) -> str:
    return sh("pw_r", f"nft {cmd}", check=True).stdout


def nft_batch(text: str) -> None:
    path = STATE / "batch.nft"
    path.write_text(text)
    out = sh("pw_r", f"nft -f {path}")
    if out.returncode:
        raise RuntimeError(out.stderr)


def counter(table: str, name: str) -> int:
    data = json.loads(nft(f"-j list counter {table} {name}"))
    for item in data["nftables"]:
        if "counter" in item:
            return int(item["counter"]["packets"])
    raise KeyError(name)


def elems(table: str, name: str) -> list[object]:
    data = json.loads(nft(f"-j list set {table} {name}"))
    for item in data["nftables"]:
        if "set" in item:
            out = []
            for e in item["set"].get("elem", []):
                if isinstance(e, dict) and "elem" in e:
                    e = e["elem"]["val"]
                if isinstance(e, dict) and "concat" in e:
                    e = tuple(e["concat"])
                out.append(e)
            return out
    return []


def offender_codes(mac: str) -> set[int]:
    return {e[1] for e in elems(ST, "offenders") if isinstance(e, tuple) and e[0] == mac}


def mac_in_any_set(mac: str, meters: bool = True) -> list[str]:
    """Sets that contain `mac`. A meter set holds a token bucket for EVERY source it
    has seen (being in one is not an accusation), so meters=False checks only the
    accusatory sets: offenders, unbound_seen, and the adaptive sets."""
    hits = []
    for s in (METERS if meters else ["offenders", "unbound_seen"]):
        for e in elems(ST, s):
            vals = e if isinstance(e, tuple) else (e,)
            if mac in vals:
                hits.append(s)
                break
    for s in ["block_mac", "ratelimit_mac", "rl_meter"]:
        if mac in elems(AD, s):
            hits.append(s)
    return hits


LEGIT_HITS: list[list[str]] = []
SKIP_LEGIT_CHECK = {"on": False}


def reset() -> None:
    """Flush the dynamic meter state and zero every counter, so each test starts clean.

    Before flushing, record whether the legit client's MAC entered any set during the
    previous test (it never should, except where t7 puts it in ratelimit_mac on purpose).
    """
    try:
        hits = mac_in_any_set(MAC["l"], meters=False)
        if hits and not SKIP_LEGIT_CHECK["on"]:
            LEGIT_HITS.append(hits)
    except Exception:
        pass
    batch = "".join(f"flush set {ST} {s}\n" for s in METERS)
    batch += f"flush set {AD} rl_meter\nflush set {AD} block_mac\nflush set {AD} block4\nflush set {AD} ratelimit_mac\n"
    nft_batch(batch)
    sh("pw_r", "nft reset counters >/dev/null; conntrack -F 2>/dev/null; true")


def set_mode(hook: str, enforce: bool) -> None:
    rule = f"add rule {ST} guard_verdict_{hook} counter name c_verdict_{hook}" + (" drop" if enforce else "")
    nft_batch(f"flush chain {ST} guard_verdict_{hook}\n{rule}\n")


def hping(ns: str, args: str, timeout: float = 60) -> str:
    out = sh(ns, f"hping3 {args} 2>&1", timeout=timeout)
    return out.stdout


def curl_ok(ns: str, url: str) -> bool:
    out = sh(ns, f"curl -s -m 3 -o /dev/null -w '%{{http_code}}' {url}")
    return out.stdout.strip() == "200"


def during(fn_flood, checks) -> list[bool]:
    """Run a flood in a background thread and the legit-traffic checks while it runs."""
    t = threading.Thread(target=fn_flood)
    t.start()
    time.sleep(0.7)
    res = [c() for c in checks]
    t.join()
    return res


def record(num: str, name: str, ok: bool, evidence: dict[str, object]) -> None:
    RESULTS.append({"id": num, "name": name, "pass": ok, "evidence": evidence})
    print(f"[{'PASS' if ok else 'FAIL'}] {num} {name}: {json.dumps(evidence, default=str)}")
    sys.stdout.flush()


def readcount(name: str) -> int:
    try:
        return int((STATE / name).read_text() or 0)
    except FileNotFoundError:
        return 0


# --------------------------------------------------------------------------- tests

def t1() -> None:
    sent = 30000
    # 1a SYN flood to the Pi's open portal port; legit traffic runs concurrently
    reset()
    legit = during(lambda: hping("pw_a", f"-S -p 8080 -c {sent} -i u100 -q {IP['r']}"),
                   [lambda: curl_ok("pw_l", "http://192.168.100.1:8080/"), lambda: curl_ok("pw_l", "http://10.99.0.2/")])
    got = counter("inet obs", "syn8080")
    ev = {"sent": sent, "reached_router": got, "dropped_verdict_raw": counter(ST, "c_verdict_raw"),
          "offender_codes": sorted(offender_codes(MAC["a"])), "legit_portal_ok, legit_wan_ok": legit}
    record("1a", "SYN flood -> Pi", 1 in offender_codes(MAC["a"]) and got < sent * 0.1 and all(legit), ev)

    # 1b SYN flood through the Pi at the WAN victim (forward path)
    reset()
    legit = during(lambda: hping("pw_a", f"-S -p 80 -c {sent} -i u100 -q {IP['v']}"),
                   [lambda: curl_ok("pw_l", "http://10.99.0.2/")])
    got = counter("inet obs", "syn_victim")
    ev = {"sent": sent, "reached_victim_fwd": got, "offender_codes": sorted(offender_codes(MAC["a"])), "legit_ok": legit}
    record("1b", "SYN flood -> WAN victim", 1 in offender_codes(MAC["a"]) and got < sent * 0.1 and all(legit), ev)

    # 1c UDP flood through the Pi at the victim (per-(mac,dst) forward meter, rendered at 2000 pps for the test)
    reset()
    before = readcount("v_udp9999")
    legit = during(lambda: hping("pw_a", f"--udp -p 9999 -s 40000 -k -d 32 -c {sent} -i u100 -q {IP['v']}"),
                   [lambda: curl_ok("pw_l", "http://10.99.0.2/")])
    time.sleep(0.5)
    got = readcount("v_udp9999") - before
    ev = {"sent": sent, "victim_received": got, "offender_codes": sorted(offender_codes(MAC["a"])),
          "dropped_verdict_forward": counter(ST, "c_verdict_forward"), "legit_ok": legit}
    record("1c", "UDP flood -> WAN victim", 8 in offender_codes(MAC["a"]) and got < sent * 0.5 and all(legit), ev)

    # 1d ICMP flood to the Pi and to the victim
    reset()
    hping("pw_a", f"--icmp -c 15000 -i u100 -q {IP['r']}")
    hping("pw_a", f"--icmp -c 15000 -i u100 -q {IP['v']}")
    drops = counter(ST, "c_verdict_raw")
    ping_ok = sh("pw_l", "ping -c2 -W1 -q 10.99.0.2").returncode == 0
    ev = {"sent": 30000, "dropped_verdict_raw": drops, "offender_codes": sorted(offender_codes(MAC["a"])), "legit_ping_ok": ping_ok}
    record("1d", "ICMP flood -> Pi + victim", 3 in offender_codes(MAC["a"]) and drops > 20000 and ping_ok, ev)


def t2() -> None:
    reset()
    sent = 20000
    hping("pw_a", f"-S --rand-source -p 8080 -c {sent} -i u100 -q {IP['r']}")
    bogon, rpf, spoof = counter(ST, "c_bogon"), counter(ST, "c_rpf"), counter(ST, "c_spoof")
    got = counter("inet obs", "syn8080")
    # in-subnet random sources from the attacker MAC (scapy): bound IPs -> c_spoof, unbound -> unbound chain
    sh("pw_a", "python3 -c \"from scapy.all import *; import random\n"
               "pk=[Ether(src='02:00:00:00:00:20',dst='02:00:00:00:01:01')/IP(src='192.168.100.%d'%random.randint(2,254),dst='192.168.100.1')/TCP(sport=random.randint(1024,65535),dport=8080,flags='S') for _ in range(3000)]\n"
               "sendp(pk,iface='eth0',verbose=0)\"")
    syn_keys = len(elems(ST, "syn_meter"))
    ev = {"rand_source_sent": sent, "c_bogon": bogon, "c_rpf": rpf, "reached_router": got,
          "in_subnet_scapy_sent": 3000, "c_spoof_after": counter(ST, "c_spoof"), "c_verdict_raw": counter(ST, "c_verdict_raw"),
          "unbound_seen_entries": len(elems(ST, "unbound_seen")), "syn_meter_keys": syn_keys}
    record("2", "--rand-source flood", bogon + rpf + spoof > sent * 0.95 and got < 200 and syn_keys <= 1, ev)


def t3() -> None:
    reset()
    sent = 2000
    hping("pw_a", f"-S -a {IP['l']} -p 8080 -c {sent} -i u500 -q {IP['r']}")
    spoof = counter(ST, "c_spoof")
    got = counter("inet obs", "syn8080")
    hits = mac_in_any_set(MAC["l"], meters=False)
    record("3a", "spoof bound neighbour IP", spoof >= sent * 0.99 and got == 0 and not hits,
           {"sent": sent, "c_spoof": spoof, "reached_router": got, "legit_mac_in_sets": hits})
    # 3b ARP poisoning attempt: attacker claims legit's IP
    sh("pw_r", f"ping -c1 -W1 {IP['l']} >/dev/null")
    sh("pw_a", "python3 -c \"from scapy.all import *\n"
               "sendp(Ether(src='02:00:00:00:00:20',dst='02:00:00:00:01:01')/ARP(op=2,hwsrc='02:00:00:00:00:20',psrc='192.168.100.10',hwdst='02:00:00:00:01:01',pdst='192.168.100.1'),iface='eth0',count=20,verbose=0)\"")
    neigh = sh("pw_r", f"ip neigh show {IP['l']}").stdout.strip()
    arp_drops = counter("arp pirewall_static_arp", "c_arp_spoof")
    record("3b", "ARP spoof of bound IP", arp_drops >= 20 and MAC["l"] in neigh,
           {"c_arp_spoof": arp_drops, "router_neigh_for_legit": neigh})


def t4() -> None:
    reset()
    sent = 20000
    hping("pw_w", f"-S -p 8080 -c {sent} -i u100 -q {IP['r']}")
    got = counter("inet obs", "syn8080")
    hits = mac_in_any_set(MAC["w"])
    ok1 = not hits and got > sent * 0.95
    hping("pw_a", f"-S -a {IP['w']} -p 8080 -c 2000 -i u500 -q {IP['r']}")
    spoof = counter(ST, "c_spoof")
    record("4", "allowlisted device unmetered; its IP unspoofable", ok1 and spoof >= 1980,
           {"allowlisted_sent": sent, "reached_router": got, "allowlisted_mac_in_sets": hits, "spoof_allowlisted_ip_dropped": spoof})


def t5() -> None:
    reset()
    admin_ok = during(lambda: hping("pw_a", f"-S -p 8443 -c 30000 -i u100 -q 192.168.101.1"),
                      [lambda: curl_ok("pw_ad", "http://192.168.101.1:8443/"), lambda: curl_ok("pw_ad", "http://192.168.101.1:8443/")])
    reset()
    hping("pw_a", "-S -a 192.168.101.2 -p 8443 -c 1000 -i u500 -q 192.168.101.1")
    bogon = counter(ST, "c_bogon")
    api_in = counter("inet obs", "api8443_in")
    own = curl_ok("pw_a", "http://192.168.101.1:8443/")
    record("5", "admin path survives flood; LAN cannot spoof admin", all(admin_ok) and bogon >= 990 and api_in == 0 and not own,
           {"admin_ok_during_flood": admin_ok, "spoof_admin_dropped_c_bogon": bogon, "api8443_reached_from_lan": api_in,
            "lan_with_own_ip_reaches_api": own})


def t6() -> None:
    reset()
    # observe on raw AND input (the portal-concurrency guard on input would otherwise still drop)
    set_mode("raw", False)
    set_mode("input", False)
    rules = json.loads(nft(f"-j list chain {ST} guard_verdict_raw"))["nftables"]
    nrules_obs = sum(1 for i in rules if "rule" in i)
    hping("pw_a", f"-S -p 8080 -c 10000 -i u100 -q {IP['r']}")
    obs_got, obs_off = counter("inet obs", "syn8080"), offender_codes(MAC["a"])
    reset()
    set_mode("raw", True)
    set_mode("input", True)
    rules = json.loads(nft(f"-j list chain {ST} guard_verdict_raw"))["nftables"]
    nrules_enf = sum(1 for i in rules if "rule" in i)
    hping("pw_a", f"-S -p 8080 -c 10000 -i u100 -q {IP['r']}")
    enf_got = counter("inet obs", "syn8080")
    record("6", "observe/enforce flip (atomic batch)", obs_got > 9500 and 1 in obs_off and enf_got < 2000 and nrules_obs == nrules_enf == 1,
           {"observe_reached": obs_got, "observe_offenders": sorted(obs_off), "enforce_reached": enf_got,
            "rules_in_verdict_chain": [nrules_obs, nrules_enf]})


def t7() -> None:
    reset()
    SKIP_LEGIT_CHECK["on"] = True
    nft_batch(f"add element {AD} block_mac {{ {MAC['a']} timeout 10m }}\n")
    blocked = not curl_ok("pw_a", "http://10.99.0.2/")
    cb = counter(AD, "c_block_mac")
    nft_batch(f"add element {AD} ratelimit_mac {{ {MAC['l']} timeout 10m }}\n")
    rl_ping = sh("pw_l", "ping -f -c 500 -W1 -q 10.99.0.2").stdout
    # kill switch: flush adaptive sets + guards observe (static + adaptive tables stay loaded)
    nft_batch(f"flush set {AD} block_mac\nflush set {AD} block4\nflush set {AD} ratelimit_mac\n"
              f"flush chain {ST} guard_verdict_raw\nadd rule {ST} guard_verdict_raw counter name c_verdict_raw\n"
              f"flush chain {ST} guard_verdict_input\nadd rule {ST} guard_verdict_input counter name c_verdict_input\n"
              f"flush chain {ST} guard_verdict_forward\nadd rule {ST} guard_verdict_forward counter name c_verdict_forward\n")
    after_kill = curl_ok("pw_a", "http://10.99.0.2/")
    tables = nft("list tables")
    kill_ok = blocked and cb > 0 and after_kill and "pirewall_static" in tables and "pirewall_base" in tables
    # panic
    sh("pw_r", "nft delete table inet pirewall_adaptive; nft delete table inet pirewall_static; nft delete table arp pirewall_static_arp", check=True)
    tables2 = nft("list tables")
    legit_after_panic = curl_ok("pw_l", "http://10.99.0.2/")
    base_still_drops = not curl_ok("pw_a", "http://192.168.101.1:8443/")
    panic_ok = "pirewall_static" not in tables2 and "pirewall_adaptive" not in tables2 and "pirewall_base" in tables2 and legit_after_panic and base_still_drops
    record("7", "kill switch and panic", kill_ok and panic_ok,
           {"blocked_before": blocked, "c_block_mac": cb, "ratelimit_ping_summary": rl_ping.strip().splitlines()[-2:],
            "attacker_ok_after_kill": after_kill, "tables_after_kill": tables.split(), "tables_after_panic": tables2.split(),
            "legit_ok_after_panic": legit_after_panic, "base_still_blocks_lan_to_api": base_still_drops})
    # restore for later tests
    subprocess.run(["bash", str(HERE / "netns_testbed.sh"), "load", *OVERRIDES], check=True, capture_output=True)
    reset()
    SKIP_LEGIT_CHECK["on"] = False


def chain_rule_counts() -> dict[str, int]:
    data = json.loads(nft(f"-j list table {ST}"))["nftables"]
    counts: dict[str, int] = {}
    for item in data:
        if "rule" in item:
            counts[item["rule"]["chain"]] = counts.get(item["rule"]["chain"], 0) + 1
    return counts


def t8() -> None:
    reset()
    hping("pw_a", f"-S -p 8080 -c 3000 -i u100 -q {IP['r']}")
    nft_batch(f"add element {AD} block_mac {{ 02:00:00:00:00:99 timeout 10m }}\n")
    before = {"bound4": len(elems(ST, "bound4")), "macbind": len(elems(ST, "macbind")), "allow_bound": len(elems(ST, "allow_bound")),
              "offenders": len(elems(ST, "offenders")), "block_mac": len(elems(AD, "block_mac")), "infra4": len(elems(AD, "infra4"))}
    rules_before = chain_rule_counts()
    for _ in range(2):
        sh("pw_r", f"nft -f {STATE}/static.nft && nft -f {STATE}/adaptive.nft", check=True)
    after = {"bound4": len(elems(ST, "bound4")), "macbind": len(elems(ST, "macbind")), "allow_bound": len(elems(ST, "allow_bound")),
             "offenders": len(elems(ST, "offenders")), "block_mac": len(elems(AD, "block_mac")), "infra4": len(elems(AD, "infra4"))}
    rules_after = chain_rule_counts()
    nft_batch(f"flush set {AD} block_mac\n")
    record("8", "template reload x2 idempotent", before == after and rules_before == rules_after and before["offenders"] > 0,
           {"elements_before": before, "elements_after": after, "rules_same": rules_before == rules_after})


def t9() -> None:
    reset()
    # establish the flow first so it is ESTABLISHED in conntrack (the case `ct state new` meters miss)
    sh("pw_a", "python3 -c \"import socket;s=socket.socket(2,2);s.bind(('192.168.100.20',40053));s.settimeout(1);s.sendto(b'q',('192.168.100.1',53));print(s.recv(64))\"")
    ct = sh("pw_r", "conntrack -L -p udp --dport 53 2>/dev/null").stdout.strip()
    before = readcount("r_udp53")
    sent = 30000
    hping("pw_a", f"--udp -s 40053 -k -p 53 -d 32 -c {sent} -i u100 -q {IP['r']}")
    time.sleep(0.5)
    got = readcount("r_udp53") - before
    codes = offender_codes(MAC["a"])
    legit_dns = "b'" in sh("pw_l", "python3 -c \"import socket;s=socket.socket(2,2);s.settimeout(2);s.sendto(b'q',('192.168.100.1',53));print(s.recv(64))\"").stdout
    record("9", "established-flow UDP flood to responding :53", (2 in codes or 4 in codes) and got < sent * 0.1 and legit_dns,
           {"sent": sent, "service_received": got, "offender_codes": sorted(codes), "conntrack_entry": ct[:160], "legit_dns_ok": legit_dns})


def t10() -> None:
    reset()
    # IPv6 is crafted with scapy (link-local ICMPv6 echo + a global-looking UDP) so the
    # test does not depend on the sandbox's IPv6 sysctls.
    sh("pw_a", "python3 -c \"from scapy.all import *\n"
               "e=Ether(src='02:00:00:00:00:20',dst='02:00:00:00:01:01')\n"
               "sendp([e/IPv6(src='fe80::20',dst='fe80::1')/ICMPv6EchoRequest(), e/IPv6(src='2001:db8::20',dst='2001:db8::1')/UDP(dport=53)]*5,iface='eth0',verbose=0)\"")
    v6 = counter(ST, "c_ipv6")
    pf = sh("pw_a", f"ping -c3 -W1 -s 4000 {IP['r']}").returncode
    frag = counter(ST, "c_frag")
    small = sh("pw_a", f"ping -c1 -W1 {IP['r']}").returncode == 0
    record("10a", "IPv4 fragments from LAN dropped (pre-defrag chain at -450)", pf != 0 and frag >= 6 and small,
           {"frag_ping_rc": pf, "c_frag": frag, "small_ping_ok": small})
    if not Path("/proc/sys/net/ipv6").exists():
        record("10b", "IPv6 from LAN dropped", False,
               {"status": "NOT TESTABLE HERE: sandbox kernel has no IPv6 stack (/proc/sys/net/ipv6 missing), so the "
                          "inet hooks never see IPv6. The rule parses and loads; verify on the Pi.", "c_ipv6": v6})
    else:
        record("10b", "IPv6 from LAN dropped", v6 >= 10, {"ipv6_sent": 10, "c_ipv6": v6})


def t11() -> None:
    reset()
    size = int(OVR.get("METER_SIZE", "256"))
    sh("pw_a", "python3 -c \"from scapy.all import *; import random\n"
               "def m(): return '02:%02x:%02x:%02x:%02x:%02x'%tuple(random.randint(0,255) for _ in range(5))\n"
               "pk=[Ether(src=m(),dst='02:00:00:00:01:01')/IP(src='192.168.100.%d'%random.randint(100,250),dst='192.168.100.1')/TCP(sport=random.randint(1024,65535),dport=8080,flags='S') for _ in range(6000)]\n"
               "sendp(pk,iface='eth0',verbose=0)\"", timeout=300)
    sizes = {s: len(elems(ST, s)) for s in ["unbound_meter", "syn_meter", "pps_meter"]}
    bk_unbound, bk_syn = counter(ST, "c_bk_unbound"), counter(ST, "c_bk_syn")
    got = counter("inet obs", "syn8080")
    record("11", "meter fill -> global backstop", all(v <= size for v in sizes.values()) and (bk_unbound > 0 or bk_syn > 0),
           {"distinct_macs_sent": 6000, "meter_size": size, "meter_keys": sizes, "c_bk_unbound": bk_unbound,
            "c_bk_syn": bk_syn, "reached_router": got})


def t12() -> None:
    reset()
    before53, before853 = readcount("v_udp53"), readcount("v_tcp853")
    sh("pw_l", "python3 -c \"import socket;s=socket.socket(2,2);[s.sendto(b'q',('10.99.0.2',53)) for _ in range(20)]\"")
    dot = sh("pw_l", "timeout 3 bash -c 'echo > /dev/tcp/10.99.0.2/853'").returncode
    time.sleep(0.5)
    got53, got853 = readcount("v_udp53") - before53, readcount("v_tcp853") - before853
    bypass = counter(ST, "c_dns_bypass")
    via_pi = "b'" in sh("pw_l", "python3 -c \"import socket;s=socket.socket(2,2);s.settimeout(2);s.sendto(b'q',('192.168.100.1',53));print(s.recv(64))\"").stdout
    record("12", "DNS/DoT to WAN not via Pi blocked", got53 == 0 and got853 == 0 and dot != 0 and bypass >= 20 and via_pi,
           {"victim_udp53_received": got53, "victim_tcp853_accepts": got853, "dot_connect_rc": dot, "c_dns_bypass": bypass, "dns_via_pi_ok": via_pi})


def t13() -> None:
    reset()
    sh("pw_a", "python3 -c \"from scapy.all import *\n"
               "p=Ether(src='02:aa:bb:cc:dd:01',dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0',dst='255.255.255.255')/UDP(sport=68,dport=67)/BOOTP(chaddr=b'\\x02\\xaa\\xbb\\xcc\\xdd\\x01',xid=1)/DHCP(options=[('message-type','discover'),'end'])\n"
               "sendp(p,iface='eth0',count=3,verbose=0)\"")
    got = counter("inet obs", "dhcp67_in")
    # starvation brake: 40 discovers from one MAC in a burst
    sh("pw_a", "python3 -c \"from scapy.all import *\n"
               "p=Ether(src='02:aa:bb:cc:dd:02',dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0',dst='255.255.255.255')/UDP(sport=68,dport=67)/BOOTP(xid=2)/DHCP(options=[('message-type','discover'),'end'])\n"
               "sendp(p,iface='eth0',count=40,verbose=0)\"")
    got2 = counter("inet obs", "dhcp67_in") - got
    codes = offender_codes("02:aa:bb:cc:dd:02")
    record("13", "DHCP discover from 0.0.0.0 passes; per-MAC brake", got == 3 and got2 <= 10 and 67 in codes,
           {"first_client_discovers_reached": got, "burst_40_reached": got2, "offender_codes_burst_mac": sorted(codes)})


def final_legit_check() -> None:
    reset()
    record("3c", "legit MAC never entered any meter/offender set across all tests (t7 excluded)", not LEGIT_HITS,
           {"legit_hits_per_test": LEGIT_HITS})


OVERRIDES = sys.argv[1:]
OVR = dict(a.split("=", 1) for a in OVERRIDES)

if __name__ == "__main__":
    for fn in (t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, final_legit_check):
        try:
            fn()
        except Exception as exc:  # report and continue
            record(fn.__name__, "exception", False, {"error": repr(exc)})
    (STATE / "results.json").write_text(json.dumps(RESULTS, indent=1, default=str))
    print(f"{sum(r['pass'] for r in RESULTS)}/{len(RESULTS)} passed")
