#!/bin/bash
set -e

network=""
for i in $(seq 1 30); do
    network=$(system_profiler SPAirPortDataType -json \
        | grep -o '"_name" *: *"[^"]*viam-setup-'"$ROBOT_NAME"'[^"]*"' \
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

connected=false
for i in $(seq 1 5); do
    result=$(networksetup -setairportnetwork en0 "$network" "viamsetup" 2>&1)
    if echo "$result" | grep -qi "failed\|error"; then
        continue
    else
        connected=true
        break
    fi
    sleep 3
done

if [ "$connected" = false ]; then
    exit 1
fi
