#!/usr/bin/env bash
# Long-running benign capture on the Pi: the pi-live data for D1 thresholds, the offline G5 check
# (lab/benign_fp.py) and phase 19 training (PLAN_v3 §4, RUNBOOK_PI.md step 5). Root.
#
#   sudo bash lab/capture/benign_capture.sh start [--dir /var/lib/pirewall-lab/benign] [--iface IF]
#        [--config FILE] [--lab-macs FILE] [--threshold 85] [--i-have-consent] [--foreground]
#   sudo bash lab/capture/benign_capture.sh stop      # stops tcpdump and the watchdog, seals the session
#   sudo bash lab/capture/benign_capture.sh status
#   sudo bash lab/capture/benign_capture.sh seal SESSION_DIR   # seal a session whose stop never ran (reboot)
#
# * `tcpdump -ni <iface> -s 128 -G 3600 -w <session>/benign-%Y%m%d%H.pcap`: headers only, one file
#   per hour. Each start opens a new session directory `<dir>/<UTC stamp>/`.
# * Interface: --iface, else network.lan_interface from the config (the lab-env helper).
# * Consent: it records packet headers of every device on the LAN. `start` shows a banner and waits
#   for "yes" unless --i-have-consent is given (for unattended restarts, after you have asked).
# * Disk watchdog: every 60 s; at --threshold % full (default 85) of the session's filesystem it
#   stops tcpdump and logs why (stdout, `logger -p user.crit`, and <session>/watchdog.log).
# * Lab MACs: nothing is BPF-filtered out. `stop` seals the session with lab/seal.py, which copies
#   the lab-MAC list (--lab-macs, default /var/lib/pirewall-lab/lab_macs.txt) into the session's
#   manifest (`extra.lab_macs`), so later tools drop those MACs by window.
# * --foreground runs tcpdump in the foreground and seals on exit: the form for systemd-run
#   (lab/README.md). Without it, `start` detaches with nohup and `stop` ends it.
#
# Env tag: pi-live, always (lab/seal.py refuses it off a Pi).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE_DIR="/run/pirewall-lab"
PID_FILE="${STATE_DIR}/benign-capture.pid"
WATCHDOG_PID_FILE="${STATE_DIR}/benign-watchdog.pid"
SESSION_FILE="${STATE_DIR}/benign-session"
DIR="/var/lib/pirewall-lab/benign"
LAB_MACS="/var/lib/pirewall-lab/lab_macs.txt"
CONFIG="${REPO_ROOT}/config/local_config.toml"
PY="${PIREWALL_PYTHON:-${REPO_ROOT}/.venv/bin/python}"
IFACE=""
THRESHOLD=85
CONSENT=0
FOREGROUND=0
SNAPLEN=128

refuse() { printf 'benign_capture: %s\n' "$1" >&2; exit 2; }
say() { printf 'benign_capture: %s\n' "$1"; }

(($#)) || refuse "usage: benign_capture.sh start|stop|status|seal [options]"
COMMAND="$1"
shift
SEAL_DIR=""
if [[ "$COMMAND" == seal ]]; then SEAL_DIR="${1:?seal needs a session directory}"; shift; fi
while (($#)); do
  case "$1" in
    --dir) DIR="${2:?}"; shift ;;
    --iface) IFACE="${2:?}"; shift ;;
    --config) CONFIG="${2:?}"; shift ;;
    --lab-macs) LAB_MACS="${2:?}"; shift ;;
    --python) PY="${2:?}"; shift ;;
    --threshold) THRESHOLD="${2:?}"; shift ;;
    --i-have-consent) CONSENT=1 ;;
    --foreground) FOREGROUND=1 ;;
    *) refuse "unknown argument $1" ;;
  esac
  shift
done
[[ "$THRESHOLD" =~ ^[0-9]+$ ]] && (( THRESHOLD > 0 && THRESHOLD < 100 )) || refuse "--threshold must be 1-99 (percent)"

need_root() { (( EUID == 0 )) || refuse "$1 needs root"; }

disk_percent() { df --output=pcent "$1" | tail -1 | tr -dc 0-9; }

consent() {
  (( CONSENT )) && return 0
  cat <<'EOF'

  ------------------------------------------------------------------------------
  pirewall benign capture
  This records the packet headers (first 128 bytes) of EVERY device on this LAN,
  for hours or days. Only start it if everyone who uses this network knows and
  has agreed. The pcaps stay on this Pi and your own machine; they are never
  committed or published.
  ------------------------------------------------------------------------------
EOF
  [[ -t 0 ]] || refuse "no terminal to confirm consent; pass --i-have-consent once you have asked everyone"
  local answer
  read -r -p "  Has everyone on this network agreed? Type yes to start: " answer
  [[ "$answer" == yes ]] || refuse "not started (no consent)"
}

resolve_iface() {
  [[ -n "$IFACE" ]] && return 0
  [[ -x "$PY" ]] || refuse "no Python at ${PY} to read the config; pass --iface"
  local names
  names="$(cd "$REPO_ROOT" && "$PY" -m scripts.deployment.startup --config "$CONFIG" lab-env)" \
    || refuse "could not read the LAN interface from ${CONFIG}; pass --iface"
  eval "$names"
  IFACE="$LAN_IF"
}

seal_session() {
  local session="$1"
  [[ -d "$session" ]] || refuse "no session directory ${session}"
  if [[ -f "${session}/manifest.json" ]]; then say "${session} is already sealed"; return 0; fi
  local -a args=("${REPO_ROOT}/lab/seal.py" "$session" --kind capture --env-tag pi-live
                 --note "interface=${IFACE:-unknown}" --note "snaplen=${SNAPLEN}")
  if [[ -f "$LAB_MACS" ]]; then
    args+=(--lab-macs "$LAB_MACS")
  else
    say "WARNING: no lab-MAC list at ${LAB_MACS}; the session is sealed with none (RUNBOOK_PI.md step 6)"
  fi
  (cd "$REPO_ROOT" && "$PY" "${args[@]}")
}

watchdog() {
  local session="$1" tcpdump_pid="$2" used
  while kill -0 "$tcpdump_pid" 2>/dev/null; do
    used="$(disk_percent "$session")"
    if (( used >= THRESHOLD )); then
      local why="disk ${used}% full (>= ${THRESHOLD}%) on the filesystem of ${session}: capture stopped"
      echo "$(date -Is) ${why}" >> "${session}/watchdog.log"
      logger -p user.crit "pirewall benign capture: ${why}" 2>/dev/null || true
      say "$why"
      kill -INT "$tcpdump_pid" 2>/dev/null || true
      return 0
    fi
    sleep 60
  done
}

start() {
  need_root start
  command -v tcpdump >/dev/null || refuse "tcpdump is not installed:  sudo apt install tcpdump"
  if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    refuse "already running (pid $(cat "$PID_FILE")); stop it first"
  fi
  resolve_iface
  consent
  install -d -m 700 "$DIR" "$STATE_DIR"
  local used
  used="$(disk_percent "$DIR")"
  (( used < THRESHOLD )) || refuse "the filesystem of ${DIR} is already ${used}% full (>= ${THRESHOLD}%)"
  local session
  session="${DIR}/$(date -u +%Y%m%dT%H%M%SZ)"
  install -d -m 700 "$session"
  echo "$session" > "$SESSION_FILE"
  say "session ${session} on ${IFACE} (snaplen ${SNAPLEN}, hourly files, stops at ${THRESHOLD}% disk)"
  if (( FOREGROUND )); then
    tcpdump -Z root -ni "$IFACE" -s "$SNAPLEN" -G 3600 -w "${session}/benign-%Y%m%d%H.pcap" &
    local pid=$!
    echo "$pid" > "$PID_FILE"
    trap 'kill -INT '"$pid"' 2>/dev/null || true' INT TERM
    watchdog "$session" "$pid" &
    echo $! > "$WATCHDOG_PID_FILE"
    wait "$pid" || true
    kill "$(cat "$WATCHDOG_PID_FILE")" 2>/dev/null || true
    rm -f "$PID_FILE" "$WATCHDOG_PID_FILE"
    seal_session "$session"
    return 0
  fi
  nohup tcpdump -Z root -ni "$IFACE" -s "$SNAPLEN" -G 3600 -w "${session}/benign-%Y%m%d%H.pcap" \
    >"${session}/tcpdump.log" 2>&1 &
  echo $! > "$PID_FILE"
  nohup bash -c "$(declare -f disk_percent say watchdog); THRESHOLD=${THRESHOLD}; watchdog \"\$1\" \"\$2\"" \
    watchdog "$session" "$(cat "$PID_FILE")" >>"${session}/watchdog.log" 2>&1 &
  echo $! > "$WATCHDOG_PID_FILE"
  sleep 1
  kill -0 "$(cat "$PID_FILE")" 2>/dev/null || refuse "tcpdump exited at once; see ${session}/tcpdump.log"
  say "started (pid $(cat "$PID_FILE")); stop with: sudo bash lab/capture/benign_capture.sh stop"
}

stop() {
  need_root stop
  local pid
  if [[ -f "$PID_FILE" ]]; then
    pid="$(cat "$PID_FILE")"
    kill -INT "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    rm -f "$PID_FILE"
  fi
  if [[ -f "$WATCHDOG_PID_FILE" ]]; then kill "$(cat "$WATCHDOG_PID_FILE")" 2>/dev/null || true; rm -f "$WATCHDOG_PID_FILE"; fi
  if [[ -f "$SESSION_FILE" ]]; then
    seal_session "$(cat "$SESSION_FILE")"
    rm -f "$SESSION_FILE"
  else
    say "no session recorded; nothing to seal"
  fi
}

status() {
  if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    local session
    session="$(cat "$SESSION_FILE" 2>/dev/null || echo unknown)"
    say "running (pid $(cat "$PID_FILE")), session ${session}, disk $(disk_percent "$session")%"
    ls -l "$session" 2>/dev/null | tail -n +2 || true
  else
    say "stopped"
  fi
}

case "$COMMAND" in
  start) start ;;
  stop) stop ;;
  status) status ;;
  seal) need_root seal; seal_session "$SEAL_DIR" ;;
  *) refuse "unknown command ${COMMAND} (start|stop|status|seal)" ;;
esac
