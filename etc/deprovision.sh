#!/usr/bin/env bash
# This script deprovisions an agent system, i.e. removes the viam.json file.
# It will also remove bluetooth connections if you pass BLUETOOTH_MAC.
# Todo: clean up wifi networks.

set -eux

sudo systemctl stop viam-agent

if [ -z "$BLUETOOTH_MAC" ]; then
    echo '$BLUETOOTH_MAC not set, skipping bluetooth cleanup'
else
    bluetoothctl remove $BLUETOOTH_MAC || echo "didn't remove bluetooth device"
    bluetoothctl power off
    sudo nmcli c delete bluetooth@$BLUETOOTH_MAC || echo "didn't remove nmcli network"

    sleep 2

    bluetoothctl power on
fi

sudo rm -fv /etc/viam.json
sudo systemctl start viam-agent
