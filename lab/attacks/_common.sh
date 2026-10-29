# shellcheck shell=bash
# Sourced by every lab/attacks/*.sh. Runs on the ATTACKER host (Kali), not the Pi.
#
# The one rule every attack script enforces before it prints or runs
# anything: the target is inside the lab.
#   --target IP       must be the Pi's LAN address (--pi-ip) or inside the
#                     [lab] victim network (--victim-net, at most a /24).
#   --lab-target IP   an explicit lab host, which must be inside the
#                     protected network (--protected-net, at most a /16).
# The bounds come from flags (run_campaign.py passes them from the Pi's
# config) or PIREWALL_LAB_PI_IP / PIREWALL_LAB_VICTIM_NET /
# PIREWALL_LAB_PROTECTED_NET. Without them the script refuses: it cannot
# prove the target is in the lab. Exit 2 on every refusal.
#
# --dry-run prints the command (prefixed "DRY-RUN:") and runs nothing.
# Every script prints TOOL_VERSION=<tool> <version> lines first, which
# run_campaign.py records in the run manifest.

set -euo pipefail

DRY_RUN=0
TARGET=""
LAB_TARGET=""
PI_IP="${PIREWALL_LAB_PI_IP:-}"
VICTIM_NET="${PIREWALL_LAB_VICTIM_NET:-}"
PROTECTED_NET="${PIREWALL_LAB_PROTECTED_NET:-}"
DURATION=10
IFACE="${PIREWALL_LAB_IFACE:-}"
REST=()

refuse() { printf 'REFUSED: %s\n' "$1" >&2; exit 2; }

ip_to_int() {
  local ip="$1" a b c d
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}; c=${BASH_REMATCH[3]}; d=${BASH_REMATCH[4]}
  (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
  echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

# in_cidr IP CIDR [MIN_PREFIX] -> 0 when IP is inside CIDR (and CIDR is at least that specific).
in_cidr() {
  local ip="$1" cidr="$2" min="${3:-0}" net prefix ip_i net_i mask
  [[ "$cidr" == */* ]] || return 1
  net="${cidr%/*}"; prefix="${cidr#*/}"
  [[ "$prefix" =~ ^[0-9]+$ ]] && (( prefix >= min && prefix <= 32 )) || return 1
  ip_i=$(ip_to_int "$ip") || return 1
  net_i=$(ip_to_int "$net") || return 1
  mask=$(( prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
  (( (ip_i & mask) == (net_i & mask) ))
}

# parse_common "$@": common flags into globals, everything else into REST.
parse_common() {
  while (($#)); do
    case "$1" in
      --dry-run) DRY_RUN=1 ;;
      --target) TARGET="${2:?--target needs an IP}"; shift ;;
      --lab-target) LAB_TARGET="${2:?--lab-target needs an IP}"; shift ;;
      --pi-ip) PI_IP="${2:?}"; shift ;;
      --victim-net) VICTIM_NET="${2:?}"; shift ;;
      --protected-net) PROTECTED_NET="${2:?}"; shift ;;
      --duration) DURATION="${2:?}"; shift ;;
      --iface) IFACE="${2:?}"; shift ;;
      *) REST+=("$1") ;;
    esac
    shift
  done
  [[ "$DURATION" =~ ^[0-9]+([.][0-9]+)?$ ]] || refuse "--duration must be a number of seconds"
}

# require_lab_target: sets DEST to the checked target, or refuses.
require_lab_target() {
  [[ -n "$PI_IP" && -n "$VICTIM_NET" && -n "$PROTECTED_NET" ]] \
    || refuse "lab bounds unknown: pass --pi-ip, --victim-net and --protected-net (or the PIREWALL_LAB_* variables)"
  ip_to_int "$PI_IP" >/dev/null || refuse "--pi-ip $PI_IP is not an IPv4 address"
  in_cidr "$PI_IP" "$PROTECTED_NET" 16 || refuse "--pi-ip $PI_IP is not inside --protected-net $PROTECTED_NET (at most a /16)"
  in_cidr "${VICTIM_NET%/*}" "$VICTIM_NET" 24 || refuse "--victim-net $VICTIM_NET must be a network of at most /24"
  if [[ -n "$TARGET" && -n "$LAB_TARGET" ]]; then refuse "give --target or --lab-target, not both"; fi
  if [[ -n "$TARGET" ]]; then
    if [[ "$TARGET" == "$PI_IP" ]] || in_cidr "$TARGET" "$VICTIM_NET" 24; then DEST="$TARGET"; return 0; fi
    refuse "target $TARGET is outside the lab (not the Pi $PI_IP, not in $VICTIM_NET)"
  fi
  if [[ -n "$LAB_TARGET" ]]; then
    in_cidr "$LAB_TARGET" "$PROTECTED_NET" 16 || refuse "--lab-target $LAB_TARGET is outside $PROTECTED_NET"
    DEST="$LAB_TARGET"; return 0
  fi
  refuse "no target: pass --target (the Pi or the lab victim) or --lab-target"
}

# require_pi_target: like require_lab_target, but only the Pi itself will do.
require_pi_target() {
  require_lab_target
  [[ "$DEST" == "$PI_IP" ]] || refuse "this attack targets the Pi only ($PI_IP), not $DEST"
}

# require_in_protected IP WHAT
require_in_protected() {
  ip_to_int "$1" >/dev/null || refuse "$2 $1 is not an IPv4 address"
  in_cidr "$1" "$PROTECTED_NET" 16 || refuse "$2 $1 is outside the protected network $PROTECTED_NET"
}

# require_lab_net CIDR: a scan range, at most a /24, inside the victim or the protected network.
require_lab_net() {
  local cidr="$1"
  [[ "$cidr" == */* ]] || refuse "--scan-net $cidr must be a CIDR (at most a /24)"
  in_cidr "${cidr%/*}" "$cidr" 24 || refuse "--scan-net $cidr must be a network of at most /24"
  if in_cidr "${cidr%/*}" "$VICTIM_NET" 24 && [[ "${cidr#*/}" -ge "${VICTIM_NET#*/}" ]]; then return 0; fi
  if in_cidr "${cidr%/*}" "$PROTECTED_NET" 16 && [[ "${cidr#*/}" -ge "${PROTECTED_NET#*/}" ]]; then return 0; fi
  refuse "--scan-net $cidr is outside the lab ($VICTIM_NET, $PROTECTED_NET)"
}

# require_number VALUE WHAT
require_number() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( $1 > 0 )) || refuse "$2 must be a positive integer, not '$1'"
}

# no_extra_args: every script parses its own flags; anything left over could name another target.
no_extra_args() {
  (( $# == 0 )) || refuse "unexpected arguments: $* (attack scripts take no free-form tool arguments)"
}

# require_iface: the attacker's LAN interface (raw-socket tools need it).
require_iface() {
  [[ -n "$IFACE" ]] || refuse "--iface (or PIREWALL_LAB_IFACE) is required by this attack"
  [[ "$IFACE" =~ ^[A-Za-z0-9_.@-]{1,15}$ ]] || refuse "--iface $IFACE is not an interface name"
}

tool_version() {
  local tool="$1" version
  if ! command -v "$tool" >/dev/null 2>&1; then echo "TOOL_VERSION=$tool missing"; return 0; fi
  case "$tool" in
    hping3) version=$(hping3 --version 2>&1 | head -1) ;;
    nmap|masscan) version=$("$tool" --version 2>&1 | grep -m1 -i version) ;;
    hydra) version=$(hydra -h 2>&1 | head -1) ;;
    ip|curl|slowhttptest|arping|arpspoof) version=$("$tool" -V 2>&1 | head -1 || true) ;;
    *) version=$("$tool" --version 2>&1 | head -1 || true) ;;
  esac
  echo "TOOL_VERSION=$tool ${version:-unknown}"
}

# run_attack CMD...: print it; unless --dry-run, run it for at most DURATION seconds.
run_attack() {
  printf '%s' "ARGV="; printf '%q ' "$@"; printf '\n'
  if (( DRY_RUN )); then
    printf 'DRY-RUN: '; printf '%q ' timeout --signal=INT "$DURATION" "$@"; printf '\n'
    return 0
  fi
  command -v "$1" >/dev/null 2>&1 || refuse "$1 is not installed on this host"
  local status=0
  timeout --signal=INT "$DURATION" "$@" || status=$?
  # timeout's 124 (and INT's 130) mean "ran for the whole duration": the expected end of a flood.
  if (( status == 124 || status == 130 )); then return 0; fi
  return "$status"
}

rate_interval_us() { echo $(( 1000000 / $1 )); }

# hping_flood KIND: the three hping3 floods share their flags.
#   --rate PPS (default 1500)  --port N (tcp/udp, default 80 / 5555)  --rand-source
hping_flood() {
  local kind="$1" rate=1500 port="" rand=0
  set -- "${REST[@]}"
  while (($#)); do
    case "$1" in
      --rate) rate="${2:?--rate needs a number}"; shift ;;
      --port) port="${2:?--port needs a number}"; shift ;;
      --rand-source) rand=1 ;;
      *) no_extra_args "$@" ;;
    esac
    shift
  done
  require_number "$rate" "--rate"
  require_lab_target
  local -a argv=(hping3 -q -i "u$(rate_interval_us "$rate")")
  case "$kind" in
    syn) require_number "${port:=80}" "--port"; argv+=(-S -p "$port") ;;
    udp) require_number "${port:=5555}" "--port"; argv+=(--udp -p "$port" -d 64) ;;
    icmp) [[ -z "$port" ]] || refuse "--port does not apply to an ICMP flood"; argv+=(--icmp -d 32) ;;
    *) refuse "unknown flood kind $kind" ;;
  esac
  (( rand )) && argv+=(--rand-source)
  argv+=("$DEST")
  tool_version hping3
  run_attack "${argv[@]}"
}
