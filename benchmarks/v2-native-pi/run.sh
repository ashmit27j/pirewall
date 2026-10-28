#!/usr/bin/env bash
# Native vs Python capture path on the Pi: frames/s and kernel drops, with and
# without GIL contention, under a synthetic SYN flood and UDP flood replayed
# at fixed rates onto a veth pair (ADDENDUM_4.md D6; v2 phase 15).
#
# NOT RUN by phase 15: written for a human to run on the Raspberry Pi. Until
# it has run there, every number it would produce is Environment-dependent.
#
#   sudo ENV_TAG=pi-scripted ./benchmarks/v2-native-pi/run.sh
#
# Needs: root (netns/veth, CAP_NET_RAW), tcpreplay, uv, and the native
# extension (uv sync --extra native). It creates its own netns "pwbench" and
# veth pair (pwb0 <-> pwb1 in the netns) and deletes them on exit; it never
# touches a real interface, nft, or pirewall's own services.
#
# ENV_TAG (ADDENDUM_4.md D7) labels the results file. It defaults to
# "sandbox" and must be set to pi-scripted explicitly to claim a Pi result.
set -euo pipefail
cd "$(dirname "$0")/../.."

ENV_TAG="${ENV_TAG:-sandbox}"
SECONDS_PER_RUN="${SECONDS_PER_RUN:-10}"
RATES="${RATES:-5000 10000 20000 40000}"   # frames per second offered
FRAMES="${FRAMES:-400000}"
case "$ENV_TAG" in pi-live|pi-scripted|sandbox|mock) ;; *) echo "bad ENV_TAG=$ENV_TAG" >&2; exit 2 ;; esac
command -v tcpreplay >/dev/null || { echo "tcpreplay is required (apt install tcpreplay)" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run as root (netns/veth and CAP_NET_RAW)" >&2; exit 2; }

WORK="$(mktemp -d)"
OUT="benchmarks/v2-native-pi/results-$(date -u +%Y%m%dT%H%M%SZ)-${ENV_TAG}.jsonl"
cleanup() {
  ip netns del pwbench 2>/dev/null || true
  ip link del pwb0 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

ip netns add pwbench
ip link add pwb0 type veth peer name pwb1
ip link set pwb1 netns pwbench
ip addr add 10.99.0.1/24 dev pwb0
ip link set pwb0 up
ip netns exec pwbench ip addr add 10.99.0.2/24 dev pwb1
ip netns exec pwbench ip link set pwb1 up
ip netns exec pwbench ip link set lo up

for kind in syn udp; do
  uv run --extra native python benchmarks/v2-native-pi/gen_pcap.py --kind "$kind" --frames "$FRAMES" \
    --out "$WORK/$kind.pcap"
done

{
  printf '{"env_tag": "%s", "host": "%s", "kernel": "%s", "machine": "%s", "started_at": "%s"}\n' \
    "$ENV_TAG" "$(hostname)" "$(uname -r)" "$(uname -m)" "$(date -u +%FT%TZ)"
} > "$OUT"

for kind in syn udp; do
  for rate in $RATES; do
    for path in python native; do
      for contend in "" "--contend"; do
        # Sender in the netns, at a fixed rate, looping until the window ends.
        ip netns exec pwbench timeout "$((SECONDS_PER_RUN + 3))" \
          tcpreplay --intf1=pwb1 --pps="$rate" --loop=0 "$WORK/$kind.pcap" >/dev/null 2>&1 &
        sender=$!
        sleep 1
        result="$(uv run --extra native python benchmarks/2026-10-15-native-capture/bench_capture.py \
          --interface pwb0 --path "$path" --seconds "$SECONDS_PER_RUN" $contend)"
        wait "$sender" || true
        printf '{"env_tag": "%s", "traffic": "%s", "offered_pps": %s, "result": %s}\n' \
          "$ENV_TAG" "$kind" "$rate" "$result" | tee -a "$OUT"
      done
    done
  done
done
echo "results: $OUT (env_tag=$ENV_TAG)"
