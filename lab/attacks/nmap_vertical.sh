#!/usr/bin/env bash
# Vertical SYN scan (nmap -sS) of one lab host at T4, T3 or T2 pacing. Attacker host only.
#   bash lab/attacks/nmap_vertical.sh --target <pi-or-victim-ip> --pi-ip IP --victim-net CIDR --protected-net CIDR \
#        [--timing T4|T3|T2] [--ports 1-1024] [--duration 60] [--dry-run]
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
parse_common "$@"
TIMING=T4
PORTS=1-1024
set -- "${REST[@]}"
while (($#)); do
  case "$1" in
    --timing) TIMING="${2:?}"; shift ;;
    --ports) PORTS="${2:?}"; shift ;;
    *) no_extra_args "$@" ;;
  esac
  shift
done
[[ "$TIMING" =~ ^T[2-4]$ ]] || refuse "--timing must be T4, T3 or T2"
[[ "$PORTS" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || refuse "--ports $PORTS is not a port list"
require_lab_target
tool_version nmap
run_attack nmap -sS -n -Pn "-${TIMING}" -p "$PORTS" "$DEST"
