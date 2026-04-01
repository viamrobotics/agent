#!/bin/bash
set -e

network="viam-setup-$HOSTNAME"

for i in $(seq 1 50); do
    result=$(networksetup -setairportnetwork en0 "$network" "viamsetup" 2>&1)
    if [ -z "$result" ]; then
        echo "connected to $network"
        # sleep a bit even on success so the next step doesn't try too early
        sleep 2
        exit 0
    fi
    sleep 2
done

exit 1
