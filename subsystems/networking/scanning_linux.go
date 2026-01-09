package networking

// This file includes functions used for wifi scans.

import (
	"context"
	"fmt"
	"strings"
	"time"

	errw "github.com/pkg/errors"
	gnm "github.com/viamrobotics/gonetworkmanager/v2"
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

	state, reason, err := wifiDev.GetPropertyStateReason()
	if err != nil {
		return errw.Wrap(err, "getting wifi state and reason")
	}

	if state != gnm.NmDeviceStateDisconnected && state != gnm.NmDeviceStateActivated {
		n.logger.Debugf("wifi device state: %s, reason: %s, skipping scan", state, reason)
		return nil
	}

	prevScan, err := wifiDev.GetPropertyLastScan()
	if err != nil {
		return errw.Wrap(err, "getting last wifi scan")
	}

	err = wifiDev.RequestScan()
	if err != nil {
		return errw.Wrap(err, "requesting wifi scan")
	}

	scanDeadline := time.Now().Add(scanTimeout)
	for {
		lastScan, err := wifiDev.GetPropertyLastScan()
		if err != nil {
			return errw.Wrap(err, "getting last wifi scan")
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
			n.logger.Warn(errw.Wrap(err, "getting ssid of discovered wifi network"))
			continue
		}

		if ssid == "" {
			n.logger.Debug("wifi network with blank ssid, ignoring")
			continue
		}

		signal, err := ap.GetPropertyStrength()
		if err != nil {
			n.logger.Warn(errw.Wrap(err, "getting signal strength of discovered wifi network"))
			continue
		}

		apFlags, err := ap.GetPropertyFlags()
		if err != nil {
			n.logger.Warn(errw.Wrap(err, "getting flags of discovered wifi network"))
			continue
		}

		wpaFlags, err := ap.GetPropertyWPAFlags()
		if err != nil {
			n.logger.Warn(errw.Wrap(err, "getting wpa flags of discovered wifi network"))
			continue
		}

		rsnFlags, err := ap.GetPropertyRSNFlags()
		if err != nil {
			n.logger.Warn(errw.Wrap(err, "getting rsn flags of discovered wifi network"))
			continue
		}

		id := n.netState.GenNetKey(NetworkTypeWifi, "", ssid)
		if id == NetKeyUnknown {
			continue
		}
		nw := n.netState.LockingNetwork(id)
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
		if nw.netType == NetworkTypeWifi && nw.lastSeen.Before(time.Now().Add(VisibleNetworkTimeout*-1)) {
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

		id := n.getNetKeyFromSettings(settings)
		if id == NetKeyUnknown {
			// unknown network type, or broken network
			continue
		}

		if id.Interface() == "" && id.Type() == NetworkTypeWifi {
			id = n.netState.GenNetKey(id.Type(), "", id.SSID())
		}

		_, ok := highestPriority[id.Interface()]
		if !ok {
			highestPriority[id.Interface()] = -999
		}

		if id.Type() != NetworkTypeBluetooth && id.Type() != NetworkTypeWired && id.SSID() == "" {
			n.logger.Warnf("wifi network (%s) with no ssid detected, skipping: %v", id.Type(), settings)
			continue
		}

		if id.Type() == NetworkTypeBluetooth && !getAutoConnectFromSettings(settings) {
			settings["connection"]["autoconnect"] = true
			delete(settings["ipv6"], "addresses")
			delete(settings["ipv6"], "routes")
			if err := conn.Update(settings); err != nil {
				n.logger.Warn(errw.Wrap(err, "updating bluetooth autoconnect"))
			}
		}

		// actually record the network
		nw := n.netState.LockingNetwork(id)
		nw.mu.Lock()
		nw.netType = id.Type()
		nw.conn = conn
		nw.priority = getPriorityFromSettings(settings)

		if nw.ssid == n.Config().HotspotSSID {
			nw.netType = NetworkTypeHotspot
			nw.isHotspot = true
		} else if nw.priority > highestPriority[id.Interface()] {
			highestPriority[id.Interface()] = nw.priority
			n.netState.SetPrimarySSID(id.Interface(), nw.ssid)
		}

		switch id.Type() {
		case NetworkTypeWired:
			if n.netState.ActiveConn(nw.interfaceName) != nil {
				nw.connected = true
			} else {
				nw.connected = false
			}
		case NetworkTypeBluetooth:
			n.btAgent.TrustDevice(nw.interfaceName)
			// if this was JUST added, we dont want to force its activation before it is fully set up
			if nw.lastTried.IsZero() {
				nw.lastTried = time.Now()
			}
			fallthrough
		case NetworkTypeWifi:
			if n.netState.ActiveConn(nw.interfaceName) != nil && n.netState.ActiveSSID(id.Interface()) == nw.ssid {
				nw.connected = true
			} else {
				nw.connected = false
			}
		}
		nw.mu.Unlock()
	}

	return nil
}

// this will look backwards, because autoconnect is "true" by default (when absent).
func getAutoConnectFromSettings(settings gnm.ConnectionSettings) bool {
	connection, ok := settings["connection"]
	if !ok {
		return true
	}
	autoRaw, ok := connection["autoconnect"]
	if !ok {
		return true
	}

	auto, ok := autoRaw.(bool)
	if !ok {
		return true
	}
	return auto
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
	if !ok || (mode != "infrastructure" && mode != "ap") {
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

func getBTAddrFromSettings(settings gnm.ConnectionSettings) string {
	bt, ok := settings["bluetooth"]
	if !ok {
		return ""
	}

	addrRaw, ok := bt["bdaddr"]
	if !ok {
		return ""
	}

	addr, ok := addrRaw.([]byte)
	if !ok {
		return ""
	}

	return formatHexWithColons(addr)
}

func formatHexWithColons(data []byte) string {
	hexValues := make([]string, len(data))
	for i, b := range data {
		hexValues[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(hexValues, ":")
}

func (n *Networking) getNetKeyFromSettings(settings gnm.ConnectionSettings) NetKey {
	_, wired := settings["802-3-ethernet"]
	_, wireless := settings["802-11-wireless"]
	_, bluetooth := settings["bluetooth"]
	if !wired && !wireless && !bluetooth {
		return NetKeyUnknown
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
		return n.netState.GenNetKey(NetworkTypeWired, ifName, "")
	}

	if wireless {
		ssid := getSSIDFromSettings(settings)
		if ssid == "" {
			return n.netState.GenNetKey("", "", "")
		}
		if ssid == n.Config().HotspotSSID {
			return n.netState.GenNetKey(NetworkTypeHotspot, "", ssid)
		}
		return n.netState.GenNetKey(NetworkTypeWifi, "", ssid)
	}

	if bluetooth {
		return n.netState.GenNetKey(NetworkTypeBluetooth, getBTAddrFromSettings(settings), "")
	}

	return n.netState.GenNetKey("", "", "")
}
