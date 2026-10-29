#!/usr/bin/env bash
# ICMP echo flood (hping3 --icmp), from a fixed source or --rand-source. Attacker host only.
#   bash lab/attacks/icmp_flood.sh --target <pi-or-victim-ip> --pi-ip IP --victim-net CIDR --protected-net CIDR \
#        [--rate 500] [--rand-source] [--duration 10] [--dry-run]
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
parse_common "$@"
hping_flood icmp
