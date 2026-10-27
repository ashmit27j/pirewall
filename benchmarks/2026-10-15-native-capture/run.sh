#!/usr/bin/env bash
# Runs bench_capture.py for both capture paths under a SYN flood and a UDP
# flood, with and without GIL contention, on a veth pair whose far end lives
# in its own network namespace. Meant for a disposable privileged container
# (it creates the netns/veth itself); it never touches a real host's network.
set -euo pipefail
cd "$(dirname "$0")/../.."

SECONDS_PER_RUN="${SECONDS_PER_RUN:-10}"
ip netns add peer 2>/dev/null || true
ip link add veth0 type veth peer name veth1 2>/dev/null || true
ip link set veth1 netns peer 2>/dev/null || true
ip addr add 10.99.0.1/24 dev veth0 2>/dev/null || true
ip link set veth0 up
ip netns exec peer ip addr add 10.99.0.2/24 dev veth1 2>/dev/null || true
ip netns exec peer ip link set veth1 up
ip netns exec peer ip link set lo up

flood() {  # $1 = hping3 mode args
  ip netns exec peer timeout "$((SECONDS_PER_RUN + 3))" hping3 $1 10.99.0.1 >/dev/null 2>&1 &
}

for traffic in "syn:-S --flood -p 80" "udp:--udp --flood -p 53" "syn10k:-S -i u100 -p 80"; do
  name="${traffic%%:*}"; args="${traffic#*:}"
  for path in python native; do
    for contend in "" "--contend"; do
      flood "$args"
      sleep 1
      printf '%s ' "$name"
      uv run --extra native python benchmarks/2026-10-15-native-capture/bench_capture.py \
        --interface veth0 --path "$path" --seconds "$SECONDS_PER_RUN" $contend
      wait || true
    done
  done
done
