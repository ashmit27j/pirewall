#!/usr/bin/env bash
# Victim-side capture for TTM (lab/score_run.py). Runs on the Pi, as root, during a campaign run.
#
#   sudo bash lab/capture.sh start --side forward|input --out RUN_DIR/victim.pcap [--config FILE] [--python PY]
#   sudo bash lab/capture.sh stop  --side forward|input [--config FILE] [--python PY]
#   sudo bash lab/capture.sh status
#
# --side forward  Victim B, the labvictim netns: tcpdump on the netns end of the veth. What arrives
#                 there got through every pirewall table (Ethernet link type).
# --side input    Victim A, the Pi itself. tcpdump on the LAN interface would see frames *before*
#                 netfilter, so instead a lab-only tap table (inet pirewall_lab_tap) logs every
#                 packet the input hook accepted from the LAN to NFLOG group --nflog-group, at
#                 priority 150 (after every input chain pirewall loads: pirewall_static's guard at
#                 -5 and both input chains at 0), and tcpdump records nflog:<group>. Dropped packets never reach it.
#                 `stop` deletes the tap table; it is never left behind on purpose.
#
# Names (netns, veth, LAN interface) come from the config through
# `python -m scripts.deployment.startup lab-env`, the same source pirewall-start uses.
# Headers only (-s 128). The pcap is root-owned in the run directory; run_campaign.py seals it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="/run/pirewall-lab"
TAP_TABLE="pirewall_lab_tap"
CONFIG="${REPO_ROOT}/config/local_config.toml"
PY="${PIREWALL_PYTHON:-${REPO_ROOT}/.venv/bin/python}"
SIDE=""
OUT=""
GROUP=47
SNAPLEN=128

refuse() { printf 'capture.sh: %s\n' "$1" >&2; exit 2; }

(($#)) || refuse "usage: capture.sh start|stop|status [--side forward|input] [--out FILE]"
COMMAND="$1"
shift
while (($#)); do
  case "$1" in
    --side) SIDE="${2:?}"; shift ;;
    --out) OUT="${2:?}"; shift ;;
    --config) CONFIG="${2:?}"; shift ;;
    --python) PY="${2:?}"; shift ;;
    --nflog-group) GROUP="${2:?}"; shift ;;
    *) refuse "unknown argument $1" ;;
  esac
  shift
done
[[ "$GROUP" =~ ^[0-9]+$ ]] && (( GROUP < 65536 )) || refuse "--nflog-group must be 0-65535"

pid_file() { echo "${STATE_DIR}/capture-${SIDE}.pid"; }

load_names() {
  [[ -x "$PY" ]] || refuse "no Python at ${PY} (pass --python, or set PIREWALL_PYTHON)"
  local names
  names="$(cd "$REPO_ROOT" && "$PY" -m scripts.deployment.startup --config "$CONFIG" lab-env)" \
    || refuse "could not read [lab] from ${CONFIG}"
  eval "$names"
}

tap_up() {
  nft -f - <<EOF
table inet ${TAP_TABLE} {
  chain input {
    type filter hook input priority 150; policy accept;
    iifname "${LAN_IF}" meta nfproto ipv4 log group ${GROUP} snaplen ${SNAPLEN}
  }
}
EOF
}

tap_down() { nft delete table inet "$TAP_TABLE" 2>/dev/null || true; }

start() {
  [[ "$SIDE" == forward || "$SIDE" == input ]] || refuse "--side forward|input is required"
  [[ -n "$OUT" ]] || refuse "--out FILE is required"
  (( EUID == 0 )) || refuse "start needs root (tcpdump, ip netns, nft)"
  command -v tcpdump >/dev/null || refuse "tcpdump is not installed:  sudo apt install tcpdump"
  [[ ! -e "$(pid_file)" ]] || refuse "a ${SIDE} capture is already running ($(pid_file)); stop it first"
  load_names
  install -d -m 700 "$STATE_DIR"
  if [[ "$SIDE" == forward ]]; then
    ip netns list | awk '{print $1}' | grep -qx "$LAB_NETNS" \
      || refuse "netns ${LAB_NETNS} is not up:  sudo scripts/deployment/pirewall-start --lab-victim up"
    ip netns exec "$LAB_NETNS" tcpdump -ni "$LAB_PEER_IF" -s "$SNAPLEN" -U -w "$OUT" >/dev/null 2>&1 &
  else
    tap_up
    tcpdump -ni "nflog:${GROUP}" -s "$((SNAPLEN + 256))" -U -w "$OUT" >/dev/null 2>&1 &
  fi
  echo $! > "$(pid_file)"
  sleep 1
  kill -0 "$(cat "$(pid_file)")" 2>/dev/null || { stop; refuse "tcpdump exited at once (see: tcpdump -ni ...)"; }
  echo "capture ${SIDE} -> ${OUT} (pid $(cat "$(pid_file)"))"
}

stop() {
  [[ "$SIDE" == forward || "$SIDE" == input ]] || refuse "--side forward|input is required"
  local file pid
  file="$(pid_file)"
  if [[ -f "$file" ]]; then
    pid="$(cat "$file")"
    kill -INT "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    kill -KILL "$pid" 2>/dev/null || true
    rm -f "$file"
  fi
  if [[ "$SIDE" == input ]]; then tap_down; fi
  echo "capture ${SIDE} stopped"
}

status() {
  local side file
  for side in forward input; do
    file="${STATE_DIR}/capture-${side}.pid"
    if [[ -f "$file" ]] && kill -0 "$(cat "$file")" 2>/dev/null; then
      echo "${side}: running (pid $(cat "$file"))"
    else
      echo "${side}: stopped"
    fi
  done
  if nft list table inet "$TAP_TABLE" >/dev/null 2>&1; then echo "tap table inet ${TAP_TABLE}: loaded"; fi
}

case "$COMMAND" in
  start) start ;;
  stop) stop ;;
  status) status ;;
  *) refuse "unknown command ${COMMAND} (start|stop|status)" ;;
esac
