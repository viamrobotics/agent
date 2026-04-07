#!/bin/bash
set -e

for i in $(seq 1 3); do
    if [[ -z "$PASSWORD" ]]; then
        if go run ./cmd/provisioning-client -a 10.42.0.1:4772 --wifi-ssid "$SSID"; then
            exit 0
        fi
    else 
        if go run ./cmd/provisioning-client -a 10.42.0.1:4772 --wifi-ssid "$SSID" --wifi-psk "$PASSWORD"; then
            exit 0
        fi
    fi
    sleep 2
done

exit 1
