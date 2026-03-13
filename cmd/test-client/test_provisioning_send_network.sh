#!/bin/bash
set -e

go run ./cmd/provisioning-client -a 10.42.0.1:4772 --wifi-ssid $SSID --wifi-psk $PASSWORD