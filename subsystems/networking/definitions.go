package networking

import "time"

const (
	SubsysName = "networking"

	NetworkTypeWifi      = "wifi"
	NetworkTypeWired     = "wired"
	NetworkTypeHotspot   = "hotspot"
	NetworkTypeBluetooth = "bluetooth"

	HealthCheckTimeout = time.Minute
)

var NetworkTypesKnown = []string{NetworkTypeHotspot, NetworkTypeWifi, NetworkTypeWired, NetworkTypeBluetooth}
