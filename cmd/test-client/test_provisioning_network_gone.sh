#!/bin/bash
set -e

for i in $(seq 1 10); do
    network=$(system_profiler SPAirPortDataType -json \
        | grep -o '"_name" *: *"[^"]*viam-setup-'"$ROBOT_NAME"'[^"]*"' \
        | head -1 \
        | sed 's/.*: *"//;s/"//')
    if [ -z "$network" ]; then
        echo "provisioning network gone"
        exit 0
    fi
    sleep 5
done

echo "provisioning network still present: $network"
exit 1
