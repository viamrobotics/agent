#!/bin/bash
set -e

network="viam-setup-$HOSTNAME"

for i in $(seq 1 10); do
    result=$(networksetup -setairportnetwork en0 "$network" "viamsetup" 2>&1)
    if [ -n "$result" ]; then
        echo "provisioning network gone"
        exit 0
    fi
    sleep 5
done

echo "provisioning network still present: $network"
exit 1
