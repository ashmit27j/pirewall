#!/usr/bin/env bash
# pirewall v2 netns testbed. Usage: netns_testbed.sh up|down|load [VAR=VALUE ...]
#
# Topology (all names prefixed pw_):
#
#   pw_a (attacker .20, 02:..:20) ─┐
#   pw_l (legit    .10, 02:..:10) ─┼─ br0 in pw_sw ── lan0 ┐
#   pw_w (allowed  .30, 02:..:30) ─┘   192.168.100.0/24     │
#                                                         pw_r (router: base + portal* +
#   pw_ad (admin 192.168.101.2, 02:..:02) ── adm0 ─────────┤        pirewall_static + adaptive,
#                                                          │        masquerade on wan0 like NM shared)
#   pw_v (victim 10.99.0.2, WAN side) ───────── wan0 ──────┘
#
# The router's kernel rp_filter is turned OFF on purpose, so the nft rules
# themselves must catch spoofing.
# The portal is loaded only by the portal-parse test (it would gate the
# forwarding tests).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE=/tmp/claude-0/pwtb
NS=(pw_r pw_sw pw_a pw_l pw_w pw_v pw_ad)
LAN_IF=lan0 WAN_IF=wan0 ADM_IF=adm0
x() { ip netns exec "$@"; }

down() {
	for n in "${NS[@]}"; do ip netns pids "$n" 2>/dev/null | xargs -r kill -9 2>/dev/null || true; ip netns del "$n" 2>/dev/null || true; done
	rm -rf "$STATE"
}

up() {
	down
	mkdir -p "$STATE"
	for n in "${NS[@]}"; do ip netns add "$n"; x "$n" ip link set lo up; done
	x pw_sw ip link add br0 type bridge
	x pw_sw ip link set br0 up
	# router <-> switch
	ip link add lan0 netns pw_r type veth peer name p_r netns pw_sw
	# clients <-> switch
	for c in a:20 l:10 w:30; do
		n=${c%%:*} o=${c##*:}
		ip link add eth0 netns pw_$n address 02:00:00:00:00:$o type veth peer name p_$n netns pw_sw
		x pw_$n ip addr add 192.168.100.$o/24 brd 192.168.100.255 dev eth0
		x pw_$n ip link set eth0 up
		x pw_$n ip route add default via 192.168.100.1
		x pw_sw ip link set p_$n master br0 up
	done
	x pw_sw ip link set p_r master br0 up
	x pw_r ip link set lan0 address 02:00:00:00:01:01
	x pw_r ip addr add 192.168.100.1/24 brd 192.168.100.255 dev lan0
	x pw_r ip link set lan0 up
	# WAN
	ip link add wan0 netns pw_r type veth peer name eth0 netns pw_v
	x pw_r ip addr add 10.99.0.1/24 dev wan0; x pw_r ip link set wan0 up
	x pw_v ip addr add 10.99.0.2/24 dev eth0; x pw_v ip link set eth0 up
	# admin
	ip link add adm0 netns pw_r type veth peer name eth0 netns pw_ad address 02:00:00:00:00:02
	x pw_r ip addr add 192.168.101.1/24 dev adm0; x pw_r ip link set adm0 up
	x pw_ad ip addr add 192.168.101.2/24 dev eth0; x pw_ad ip link set eth0 up
	x pw_ad ip route add default via 192.168.101.1
	# router sysctls: forward on, kernel anti-spoof OFF (nft must do it)
	x pw_r sysctl -qw net.ipv4.ip_forward=1
	for k in all default lan0 wan0 adm0; do x pw_r sysctl -qw net.ipv4.conf.$k.rp_filter=0; done
	# NM-shared-mode-like masquerade
	printf 'table ip nat_shared {\n chain post {\n  type nat hook postrouting priority 100; policy accept;\n  oifname "%s" masquerade\n }\n}\n' "$WAN_IF" > "$STATE/nat.nft"
	x pw_r nft -f "$STATE/nat.nft"
	# services
	x pw_r python3 "$HERE/svc.py" udp-echo 192.168.100.1 53 "$STATE/r_udp53" >/dev/null 2>&1 &
	x pw_r python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 &
	x pw_r python3 -m http.server 8443 --bind 192.168.101.1 >/dev/null 2>&1 &
	x pw_v python3 -m http.server 80 --bind 10.99.0.2 >/dev/null 2>&1 &
	x pw_v python3 "$HERE/svc.py" udp-echo 10.99.0.2 9999 "$STATE/v_udp9999" >/dev/null 2>&1 &
	x pw_v python3 "$HERE/svc.py" udp-echo 10.99.0.2 53 "$STATE/v_udp53" >/dev/null 2>&1 &
	x pw_v python3 "$HERE/svc.py" tcp-listen 10.99.0.2 853 "$STATE/v_tcp853" >/dev/null 2>&1 &
	x pw_v iperf3 -s -D -B 10.99.0.2 >/dev/null 2>&1
	sleep 1
	load "$@"
}

# Render and load base + static + adaptive into the router, plus an observation
# table (priority 100, counts what survives). Also seeds the bindings for a,
# l and w (what pirewall-leases would write) and the allowlist entry for w.
load() {
	local R="python3 $HERE/render.py"
	local common=(LAN_INTERFACE=$LAN_IF WAN_INTERFACE=$WAN_IF ADMIN_INTERFACE=$ADM_IF
		PROTECTED_NETWORK=192.168.100.0/24 LAN_BROADCAST=192.168.100.255 PIREWALL_LAN_IP=192.168.100.1
		ADMIN_PC_IP=192.168.101.2 ADMIN_PC_MAC=02:00:00:00:00:02 "INFRA4_ELEMENTS=192.168.100.1, 192.168.101.1, 192.168.101.2, 10.99.0.1")
	$R "$HERE/base.nft.template" "${common[@]}" "$@" > "$STATE/base.nft"
	$R "$HERE/pirewall_static.nft.template" "${common[@]}" "$@" > "$STATE/static.nft"
	$R "$HERE/pirewall_adaptive.nft.template" "${common[@]}" "$@" > "$STATE/adaptive.nft"
	$R "$HERE/portal.nft.template" "${common[@]}" "$@" > "$STATE/portal.nft"
	NFT="${NFT:-nft}"
	x pw_r $NFT -f "$STATE/base.nft"
	x pw_r $NFT -f "$STATE/static.nft"
	x pw_r $NFT -f "$STATE/adaptive.nft"
	x pw_r nft delete table inet obs 2>/dev/null || true
	x pw_r nft -f - <<-'EOF'
	table inet obs {
		chain in { type filter hook input priority 100; policy accept;
			tcp dport 8080 tcp flags & (syn|ack) == syn counter name syn8080
			udp dport 53 counter name udp53_in
			udp dport 67 counter name dhcp67_in
			tcp dport 8443 counter name api8443_in
		}
		chain forward_obs { type filter hook forward priority 100; policy accept;
			ip daddr 10.99.0.2 tcp dport 80 tcp flags & (syn|ack) == syn counter name syn_victim
		}
		counter syn8080 { }
		counter udp53_in { }
		counter dhcp67_in { }
		counter api8443_in { }
		counter syn_victim { }
	}
	EOF
	# The router's base forward chain only accepts LAN->WAN, and ICMP. That is all
	# the testbed needs.
	for c in 20 10 30; do
		x pw_r nft add element inet pirewall_static bound4 "{ 192.168.100.$c timeout 1h }"
		x pw_r nft add element inet pirewall_static macbind "{ 192.168.100.$c . 02:00:00:00:00:$c timeout 1h }"
		x pw_r nft add element arp pirewall_static_arp bound4 "{ 192.168.100.$c timeout 1h }"
		x pw_r nft add element arp pirewall_static_arp macbind "{ 192.168.100.$c . 02:00:00:00:00:$c timeout 1h }"
	done
	x pw_r nft add element inet pirewall_static allow_bound "{ 02:00:00:00:00:30 . 192.168.100.30 }"
	x pw_r nft add element inet pirewall_adaptive allow_bound "{ 02:00:00:00:00:30 . 192.168.100.30 }"
}

case "${1:-}" in
	up) shift; up "$@" ;;
	down) down ;;
	load) shift; load "$@" ;;
	*) echo "usage: $0 up|down|load [VAR=VALUE ...]"; exit 2 ;;
esac
