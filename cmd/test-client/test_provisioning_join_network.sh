#!/bin/bash
set -e

network="viam-setup-$HOSTNAME"

for i in $(seq 1 50); do
    result=$(networksetup -setairportnetwork en0 "$network" "viamsetup" 2>&1)
    if [ -z "$result" ]; then
        echo "connected to $network"
        exit 0
    fi
    sleep 2
done

exit 1
