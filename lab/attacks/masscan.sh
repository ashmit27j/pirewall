#!/usr/bin/env bash
# masscan, the held-out scanner (never used to fit anything). One lab host or a lab range. Attacker host only.
#   bash lab/attacks/masscan.sh (--target <pi-or-victim-ip> | --scan-net <CIDR in the lab>) \
#        --pi-ip IP --victim-net CIDR --protected-net CIDR [--rate 5000] [--ports 22,80,443] [--duration 30] [--dry-run]
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
parse_common "$@"
RATE=5000
PORTS=22,80,443
SCAN_NET=""
set -- "${REST[@]}"
while (($#)); do
  case "$1" in
    --rate) RATE="${2:?}"; shift ;;
    --ports) PORTS="${2:?}"; shift ;;
    --scan-net) SCAN_NET="${2:?}"; shift ;;
    *) no_extra_args "$@" ;;
  esac
  shift
done
require_number "$RATE" "--rate"
[[ "$PORTS" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || refuse "--ports $PORTS is not a port list"
if [[ -n "$SCAN_NET" ]]; then
  [[ -z "$TARGET$LAB_TARGET" ]] || refuse "give --target or --scan-net, not both"
  [[ -n "$PI_IP" && -n "$VICTIM_NET" && -n "$PROTECTED_NET" ]] \
    || refuse "lab bounds unknown: pass --pi-ip, --victim-net and --protected-net"
  require_lab_net "$SCAN_NET"
  DEST="$SCAN_NET"
else
  require_lab_target
fi
tool_version masscan
run_attack masscan -p "$PORTS" --rate "$RATE" --wait 0 "$DEST"
