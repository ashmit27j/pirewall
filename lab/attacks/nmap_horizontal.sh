#!/usr/bin/env bash
# Horizontal SYN scan (nmap -sS -p <port>) across a lab range (at most a /24). Attacker host only.
#   bash lab/attacks/nmap_horizontal.sh --scan-net <CIDR in the lab> --pi-ip IP --victim-net CIDR --protected-net CIDR \
#        [--port 22] [--timing T4] [--duration 60] [--dry-run]
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
parse_common "$@"
SCAN_NET=""
PORT=22
TIMING=T4
set -- "${REST[@]}"
while (($#)); do
  case "$1" in
    --scan-net) SCAN_NET="${2:?}"; shift ;;
    --port) PORT="${2:?}"; shift ;;
    --timing) TIMING="${2:?}"; shift ;;
    *) no_extra_args "$@" ;;
  esac
  shift
done
[[ -z "$TARGET$LAB_TARGET" ]] || refuse "a horizontal scan takes --scan-net, not --target"
[[ -n "$PI_IP" && -n "$VICTIM_NET" && -n "$PROTECTED_NET" ]] \
  || refuse "lab bounds unknown: pass --pi-ip, --victim-net and --protected-net"
[[ -n "$SCAN_NET" ]] || refuse "--scan-net is required"
require_lab_net "$SCAN_NET"
require_number "$PORT" "--port"
[[ "$TIMING" =~ ^T[2-4]$ ]] || refuse "--timing must be T4, T3 or T2"
tool_version nmap
run_attack nmap -sS -n -Pn "-${TIMING}" -p "$PORT" "$SCAN_NET"
