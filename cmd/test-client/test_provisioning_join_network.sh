#!/bin/bash
set -e

network=""
for i in $(seq 1 50); do
    network=$(system_profiler SPAirPortDataType -json \
        | grep -o '"_name" *: *"[^"]*viam-setup-'"$HOSTNAME"'[^"]*"' \
        | head -1 \
        | sed 's/.*: *"//;s/"//')
    if [ -n "$network" ]; then
        break
    fi
    sleep 5
done

echo $network

if [ -z "$network" ]; then
    exit 1
fi

current=$(networksetup -getairportnetwork en0 2>&1 | sed 's/.*: //')
if [ "$current" = "$network" ]; then
    echo "already connected to $network"
    exit 0
fi

connected=false
for i in $(seq 1 5); do
    result=$(networksetup -setairportnetwork en0 "$network" "viamsetup" 2>&1)
    if echo "$result" | grep -qi "failed\|error"; then
        continue
    else
        connected=true
        sleep 10
        break
    fi
    sleep 3
done

if [ "$connected" = false ]; then
    exit 1
fi
