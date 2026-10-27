#!/usr/bin/env python3
"""Render the v2 nft templates. Usage: render.py TEMPLATE [KEY=VALUE ...] > out.nft

Defaults are the PLAN_v1 starting values (to be replaced by benign-capture-derived
thresholds); unknown/missing ${VARS} are a hard error so nothing renders half-filled.
"""
import re
import sys

DEFAULTS = {
    "LAN_INTERFACE": "wlan0",
    "WAN_INTERFACE": "wlan1",
    "ADMIN_INTERFACE": "eth0",
    "PROTECTED_NETWORK": "192.168.100.0/24",
    "LAN_BROADCAST": "192.168.100.255",
    "PIREWALL_LAN_IP": "192.168.100.1",
    "ADMIN_PC_IP": "192.168.101.2",
    "ADMIN_PC_MAC": "02:00:00:00:00:02",
    "API_PORT": "8443",
    "PORTAL_PORT": "8080",
    "INFRA4_ELEMENTS": "192.168.100.1, 192.168.101.1, 192.168.101.2",
    "BINDING_SIZE": "1024",
    "METER_SIZE": "256",
    "PAIR_METER_SIZE": "4096",
    "OFFENDER_SIZE": "4096",
    "ADAPTIVE_SIZE": "4096",
    "DHCP_PER_MINUTE": "10",
    "DHCP_BURST": "5",
    "UNBOUND_PPS": "50",
    "UNBOUND_BURST": "100",
    "GLOBAL_UNBOUND_PPS": "500",
    "GLOBAL_UNBOUND_BURST": "1000",
    "SYN_PPS": "200",
    "SYN_BURST": "400",
    "ICMP_PPS": "50",
    "ICMP_BURST": "100",
    "UDP_LOCAL_PPS": "500",
    "UDP_LOCAL_BURST": "1000",
    "LOCAL_PPS": "3000",
    "LOCAL_BURST": "6000",
    "GLOBAL_SYN_PPS": "2000",
    "GLOBAL_SYN_BURST": "4000",
    "GLOBAL_ICMP_PPS": "500",
    "GLOBAL_ICMP_BURST": "1000",
    "GLOBAL_UDP_LOCAL_PPS": "3000",
    "GLOBAL_UDP_LOCAL_BURST": "6000",
    "DNS_QPS": "100",
    "DNS_BURST": "300",
    "CLOSED_PPS": "20",
    "CLOSED_BURST": "40",
    "PORTAL_CONCURRENCY": "20",
    "NEWCONN_PPS": "100",
    "NEWCONN_BURST": "200",
    "NEWCONN_DST_PPS": "50",
    "NEWCONN_DST_BURST": "100",
    "UDP_FWD_PPS": "20000",
    "UDP_FWD_BURST": "40000",
    "GLOBAL_NEWCONN_PPS": "1000",
    "GLOBAL_NEWCONN_BURST": "2000",
    "RATELIMIT_PPS": "20",
    "RATELIMIT_BURST": "40",
    "RAW_VERDICT": "drop",
    "INPUT_VERDICT": "drop",
    "FORWARD_VERDICT": "",
}


def render(text: str, values: dict[str, str]) -> str:
    missing = sorted(set(re.findall(r"\$\{([A-Z0-9_]+)\}", text)) - values.keys())
    if missing:
        raise SystemExit(f"missing template values: {missing}")
    return re.sub(r"\$\{([A-Z0-9_]+)\}", lambda m: values[m.group(1)], text)


def main() -> None:
    values = dict(DEFAULTS)
    for arg in sys.argv[2:]:
        key, _, value = arg.partition("=")
        values[key] = value
    for key, value in values.items():
        if key.endswith("_VERDICT") and value not in ("drop", ""):
            raise SystemExit(f"{key} must be 'drop' or '' (got {value!r})")
    with open(sys.argv[1]) as handle:
        sys.stdout.write(render(handle.read(), values))


if __name__ == "__main__":
    main()
