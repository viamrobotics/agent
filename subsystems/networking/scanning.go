package networking

// This file includes functions used for wifi scans.

import (
	"context"
	"strings"
	"time"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"
)

var (
	ErrScanTimeout = errw.New("wifi scanning timed out")

	// how long is a scanned network "visible" for candidate selection?
	VisibleNetworkTimeout = time.Minute
)

func (n *Networking) networkScan(ctx context.Context) error {
	if n.connState.getProvisioning() && n.netState.NoScanInHotspot() {
		return nil
	}

	wifiDev := n.netState.WifiDevice(n.Config().HotspotInterface)
	if wifiDev == nil {
		return errw.Errorf("cannot find hotspot interface: %s", n.Config().HotspotInterface)
	}

	prevScan, err := wifiDev.GetPropertyLastScan()
	if err != nil {
		return errw.Wrap(err, "scanning wifi")
	}

	err = wifiDev.RequestScan()
	if err != nil {
		return errw.Wrap(err, "scanning wifi")
	}

	scanDeadline := time.Now().Add(scanTimeout)
	for {
		lastScan, err := wifiDev.GetPropertyLastScan()
		if err != nil {
			return errw.Wrap(err, "scanning wifi")
		}
		if lastScan > prevScan {
			if n.connState.getProvisioning() {
				n.netState.ResetFailScan()
			}
			break
		}
		if !n.bgLoopHealth.Sleep(ctx, time.Second) {
			return nil
		}
		if time.Now().After(scanDeadline) {
			if n.connState.getProvisioning() {
				n.netState.IncrementFailScan()
			}
			return ErrScanTimeout
		}
	}

	wifiList, err := wifiDev.GetAccessPoints()
	if err != nil {
		return errw.Wrap(err, "scanning wifi")
	}

	// set "now" to be reusable for consistency
	now := time.Now()
	for _, ap := range wifiList {
		if ctx.Err() != nil {
			return nil //nolint:nilerr
		}
		ssid, err := ap.GetPropertySSID()
		if err != nil {
			n.logger.Warn(errw.Wrap(err, "scanning wifi"))
			continue
		}

		if ssid == "" {
			n.logger.Debug("wifi network with blank ssid, ignoring")
			continue
		}

		signal, err := ap.GetPropertyStrength()
		if err != nil {
			n.logger.Warn(errw.Wrap(err, "scanning wifi"))
			continue
		}

		apFlags, err := ap.GetPropertyFlags()
		if err != nil {
			n.logger.Warn(errw.Wrap(err, "scanning wifi"))
			continue
		}

		wpaFlags, err := ap.GetPropertyWPAFlags()
		if err != nil {
			n.logger.Warn(errw.Wrap(err, "scanning wifi"))
			continue
		}

		rsnFlags, err := ap.GetPropertyRSNFlags()
		if err != nil {
			n.logger.Warn(errw.Wrap(err, "scanning wifi"))
			continue
		}

		nw := n.netState.LockingNetwork(n.Config().HotspotInterface, ssid)
		nw.mu.Lock()

		nw.netType = NetworkTypeWifi
		nw.ssid = ssid
		nw.security = parseWPAFlags(apFlags, wpaFlags, rsnFlags)
		nw.signal = signal
		nw.lastSeen = now

		if nw.firstSeen.IsZero() {
			nw.firstSeen = now
		}

		nw.mu.Unlock()
	}

	for _, nw := range n.netState.LockingNetworks() {
		if ctx.Err() != nil {
			return nil //nolint:nilerr
		}
		nw.mu.Lock()
		// if a network isn't visible, reset the times so we'll retry if it comes back
		if nw.lastSeen.Before(time.Now().Add(VisibleNetworkTimeout * -1)) {
			nw.firstSeen = time.Time{}
			nw.lastTried = time.Time{}
		}
		nw.mu.Unlock()
	}

	return nil
}

func parseWPAFlags(apFlags, wpaFlags, rsnFlags uint32) string {
	flags := []string{}
	if apFlags&uint32(gnm.Nm80211APFlagsPrivacy) != 0 && wpaFlags == uint32(gnm.Nm80211APSecNone) && rsnFlags == uint32(gnm.Nm80211APSecNone) {
		return "WEP"
	}

	if wpaFlags == uint32(gnm.Nm80211APSecNone) && rsnFlags == uint32(gnm.Nm80211APSecNone) {
		return "-"
	}

	if wpaFlags != uint32(gnm.Nm80211APSecNone) {
		flags = append(flags, "WPA1")
	}
	if rsnFlags&uint32(gnm.Nm80211APSecKeyMgmtPSK) != 0 || rsnFlags&uint32(gnm.Nm80211APSecKeyMgmt8021X) != 0 {
		flags = append(flags, "WPA2")
	}
	if rsnFlags&uint32(gnm.Nm80211APSecKeyMgmtSAE) != 0 {
		flags = append(flags, "WPA3")
	}
	if rsnFlags&uint32(gnm.Nm80211APSecKeyMgmtOWE) != 0 {
		flags = append(flags, "OWE")
	} else if rsnFlags&uint32(gnm.Nm80211APSecKeyMgmtOWETM) != 0 {
		flags = append(flags, "OWE-TM")
	}
	if wpaFlags&uint32(gnm.Nm80211APSecKeyMgmt8021X) != 0 || rsnFlags&uint32(gnm.Nm80211APSecKeyMgmt8021X) != 0 {
		flags = append(flags, "802.1X")
	}

	return strings.Join(flags, " ")
}

// updates connections/settings from those known to NetworkManager.
func (n *Networking) updateKnownConnections(ctx context.Context) error {
	conns, err := n.settings.ListConnections()
	if err != nil {
		return err
	}

	highestPriority := make(map[string]int32)
	for _, conn := range conns {
		//nolint:nilerr
		if ctx.Err() != nil {
			return nil
		}
		settings, err := conn.GetSettings()
		if err != nil {
			return err
		}

		ifName, ssid, netType := getIfNameSSIDTypeFromSettings(settings)
		if netType == "" {
			// unknown network type, or broken network
			continue
		}

		if ifName == "" && netType == NetworkTypeWifi {
			ifName = n.Config().HotspotInterface
		}

		_, ok := highestPriority[ifName]
		if !ok {
			highestPriority[ifName] = -999
		}

		if netType != NetworkTypeWired && ssid == "" {
			n.logger.Warn("wifi network with no ssid detected, skipping")
			continue
		}

		// actually record the network
		nw := n.netState.LockingNetwork(ifName, ssid)
		nw.mu.Lock()
		nw.netType = netType
		nw.conn = conn
		nw.priority = getPriorityFromSettings(settings)

		if nw.ssid == n.Config().HotspotSSID {
			nw.netType = NetworkTypeHotspot
			nw.isHotspot = true
		} else if nw.priority > highestPriority[ifName] {
			highestPriority[ifName] = nw.priority
			n.netState.SetPrimarySSID(ifName, nw.ssid)
		}
		nw.mu.Unlock()
	}

	return nil
}

func getPriorityFromSettings(settings gnm.ConnectionSettings) int32 {
	connection, ok := settings["connection"]
	if !ok {
		return 0
	}

	priRaw, ok := connection["autoconnect-priority"]
	if !ok {
		return 0
	}

	priority, ok := priRaw.(int32)
	if !ok {
		return 0
	}
	return priority
}

func getSSIDFromSettings(settings gnm.ConnectionSettings) string {
	// gnm.ConnectionSettings is a map[string]map[string]interface{}
	wifi, ok := settings["802-11-wireless"]
	if !ok {
		return ""
	}

	modeRaw, ok := wifi["mode"]
	if !ok {
		return ""
	}

	mode, ok := modeRaw.(string)
	// we'll take hotspots and "normal" infrastructure connections only
	if !ok || !(mode == "infrastructure" || mode == "ap") {
		return ""
	}

	ssidRaw, ok := wifi["ssid"]
	if !ok {
		return ""
	}
	ssidBytes, ok := ssidRaw.([]byte)
	if !ok {
		return ""
	}
	if len(ssidBytes) == 0 {
		return ""
	}
	return string(ssidBytes)
}

func getIfNameSSIDTypeFromSettings(settings gnm.ConnectionSettings) (string, string, string) {
	_, wired := settings["802-3-ethernet"]
	_, wireless := settings["802-11-wireless"]
	if !wired && !wireless {
		return "", "", ""
	}

	var ifName string
	conn, ok := settings["connection"]
	if ok {
		ifKey, ok := conn["interface-name"]
		if ok {
			name, ok := ifKey.(string)
			if ok {
				ifName = name
			}
		}
	}

	if wired {
		return ifName, "", NetworkTypeWired
	}

	if wireless {
		ssid := getSSIDFromSettings(settings)
		if ssid == "" {
			return "", "", ""
		}
		return ifName, ssid, NetworkTypeWifi
	}

	return "", "", ""
}
