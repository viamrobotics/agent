package networking

import "time"

const (
	SubsysName = "networking"

	NetworkTypeWifi      = "wifi"
	NetworkTypeWired     = "wired"
	NetworkTypeHotspot   = "hotspot"
	NetworkTypeBluetooth = "bluetooth"

	HealthCheckTimeout = time.Minute * 2
)

var NetworkTypesKnown = []string{NetworkTypeHotspot, NetworkTypeWifi, NetworkTypeWired, NetworkTypeBluetooth}
