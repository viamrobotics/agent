#!/bin/bash
set -e

for i in $(seq 1 3); do
    if go run ./cmd/provisioning-client -a 10.42.0.1:4772 --wifi-ssid "$SSID" --wifi-psk "$PASSWORD"; then
        exit 0
    fi
    sleep 2
done

exit 1
