#!/usr/bin/env bash
# Sample pirewall-core's systemd status line, which is the only place the
# daemon exposes its detection-queue depth (`queued_flows`) -- the direct
# backpressure indicator. Read-only: `systemctl show` does not touch the unit.
set -u
end=$(( $(date +%s) + ${1:-600} ))
echo "timestamp,status_text"
while [ "$(date +%s)" -lt "$end" ]; do
    printf '%s,"%s"\n' "$(date -Is)" "$(systemctl show -p StatusText --value pirewall-core.service)"
    sleep 5
done
