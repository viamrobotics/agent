#!/bin/bash
set -e

if [ -z "$SSID" ] || [ -z "$PASSWORD" ]; then
    echo "SSID and PASSWORD must be set"
    exit 1
fi

# Already online, nothing to do.
if ping -c 1 -W 5 app.viam.com >/dev/null 2>&1; then
    echo "host already online"
    exit 0
fi

for i in $(seq 1 30); do
    result=$(networksetup -setairportnetwork en0 "$SSID" "$PASSWORD" 2>&1)
    if [ -z "$result" ]; then
        # Wait for connectivity after joining.
        sleep 3
        if ping -c 1 -W 5 app.viam.com >/dev/null 2>&1; then
            echo "host reconnected to $SSID"
            exit 0
        fi
    fi
    sleep 5
done

echo "failed to reconnect host to $SSID"
exit 1
