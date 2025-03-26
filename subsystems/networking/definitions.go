package networking

import "time"

const (
	SubsysName = "networking"

	NetworkTypeWifi    = "wifi"
	NetworkTypeWired   = "wired"
	NetworkTypeHotspot = "hotspot"

	HealthCheckTimeout = time.Minute
)
