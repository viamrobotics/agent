package networking

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"time"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
)

func (w *Provisioning) warnIfMultiplePrimaryNetworks() {
	if w.cfg.TurnOnHotspotIfWifiHasNoInternet {
		return
	}
	var primaryCandidates []string
	highestPriority := int32(-999)
	for _, nw := range w.netState.Networks() {
		if nw.conn == nil || nw.isHotspot || nw.netType != NetworkTypeWifi ||
			(nw.interfaceName != "" && nw.interfaceName != w.Config().HotspotInterface) {
			continue
		}

		if nw.priority > highestPriority {
			highestPriority = nw.priority
			primaryCandidates = []string{nw.ssid}
		} else if nw.priority == highestPriority {
			primaryCandidates = append(primaryCandidates, nw.ssid)
		}
	}
	if len(primaryCandidates) > 1 {
		w.logger.Warnf(
			"Multiple networks %s tied for highest priority (%d), selection will be arbitrary. Consider using Roaming Mode.",
			primaryCandidates,
			highestPriority,
		)
	}
}

func (w *Provisioning) getVisibleNetworks() []NetworkInfo {
	var visible []NetworkInfo
	for _, nw := range w.netState.Networks() {
		// note this does NOT use VisibleNetworkTimeout (like getCandidates does)
		recentlySeen := nw.lastSeen.After(w.connState.getProvisioningChange().Add(time.Duration(w.Config().OfflineBeforeStartingHotspotMinutes * -2)))

		if !nw.isHotspot && recentlySeen {
			visible = append(visible, nw.getInfo())
		}
	}

	// sort by strongest signal
	sort.SliceStable(visible, func(i, j int) bool {
		return visible[i].Signal > visible[j].Signal
	})

	return visible
}

func (w *Provisioning) getLastNetworkTried() NetworkInfo {
	lastNetwork := w.netState.LastNetwork(w.Config().HotspotInterface)
	return lastNetwork.getInfo()
}

func (w *Provisioning) checkOnline(force bool) error {
	if force {
		if err := w.nm.CheckConnectivity(); err != nil {
			w.logger.Error(err)
		}
	}

	state, err := w.nm.State()
	if err != nil {
		return err
	}

	var online bool

	//nolint:exhaustive
	switch state {
	case gnm.NmStateConnectedGlobal:
		online = true
	case gnm.NmStateConnectedSite:
		fallthrough
	case gnm.NmStateConnectedLocal:
		// do nothing, but may need these two in the future
	case gnm.NmStateUnknown:
		err = errors.New("unable to determine network state")
	default:
		err = nil
	}

	w.connState.setOnline(online)
	return err
}

func (w *Provisioning) checkConnections() error {
	var connected bool
	defer func() {
		w.connState.setConnected(connected)
	}()

	for ifName, dev := range w.netState.Devices() {
		activeConnection, err := dev.GetPropertyActiveConnection()
		if err != nil {
			return err
		}
		if activeConnection == nil {
			w.netState.SetActiveConn(ifName, nil)
			w.netState.SetActiveSSID(ifName, "")
			continue
		}

		connection, err := activeConnection.GetPropertyConnection()
		if err != nil {
			return err
		}

		settings, err := connection.GetSettings()
		if err != nil {
			return err
		}

		connIfName, ssid, _ := getIfNameSSIDTypeFromSettings(settings)
		nw := w.netState.LockingNetwork(connIfName, ssid)

		state, err := activeConnection.GetPropertyState()
		nw.mu.Lock()
		if err != nil {
			w.logger.Error(errw.Wrapf(err, "getting state of active connection: %s", w.netState.GenNetKey(ifName, ssid)))
			w.netState.SetActiveConn(ifName, nil)
			w.netState.SetActiveSSID(ifName, "")
			nw.connected = false
		} else {
			w.netState.SetActiveConn(ifName, activeConnection)
			w.netState.SetActiveSSID(ifName, ssid)
			nw.connected = true
		}
		nw.mu.Unlock()

		// if this isn't the primary wifi device, we're done
		if ifName != w.Config().HotspotInterface {
			continue
		}

		// in roaming mode, we don't care WHAT network is connected
		if w.cfg.TurnOnHotspotIfWifiHasNoInternet && state == gnm.NmActiveConnectionStateActivated && ssid != w.Config().HotspotSSID {
			connected = true
		}

		// in normal (single) mode, we need to be connected to the primary (highest priority) network
		if !w.cfg.TurnOnHotspotIfWifiHasNoInternet && state == gnm.NmActiveConnectionStateActivated && ssid == w.netState.PrimarySSID(w.Config().HotspotInterface) {
			connected = true
		}
	}

	return nil
}

// StartProvisioning puts the wifi in hotspot mode and starts a captive portal.
func (w *Provisioning) StartProvisioning(ctx context.Context, inputChan chan<- userInput) error {
	if w.connState.getProvisioning() {
		return errors.New("provisioning mode already started")
	}

	w.opMu.Lock()
	defer w.opMu.Unlock()

	w.logger.Info("Starting provisioning mode.")
	_, err := w.addOrUpdateConnection(utils.NetworkDefinition{
		Type:      NetworkTypeHotspot,
		Interface: w.Config().HotspotInterface,
		SSID:      w.Config().HotspotSSID,
	})
	if err != nil {
		return err
	}
	if err := w.activateConnection(ctx, w.Config().HotspotInterface, w.Config().HotspotSSID); err != nil {
		return errw.Wrap(err, "starting provisioning mode hotspot")
	}

	// start portal with ssid list and known connections
	if err := w.startPortal(inputChan); err != nil {
		err = errors.Join(err, w.deactivateConnection(w.Config().HotspotInterface, w.Config().HotspotSSID))
		return errw.Wrap(err, "starting web/grpc portal")
	}

	w.connState.setProvisioning(true)
	return nil
}

func (w *Provisioning) StopProvisioning() error {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	return w.stopProvisioning()
}

func (w *Provisioning) stopProvisioning() error {
	w.logger.Info("Stopping provisioning mode.")
	w.connState.setProvisioning(false)
	err := w.stopPortal()
	err2 := w.deactivateConnection(w.Config().HotspotInterface, w.Config().HotspotSSID)
	if errors.Is(err2, ErrNoActiveConnectionFound) {
		return err
	}
	return errors.Join(err, err2)
}

func (w *Provisioning) ActivateConnection(ctx context.Context, ifName, ssid string) error {
	if w.connState.getProvisioning() && ifName == w.Config().HotspotInterface {
		return errors.New("cannot activate another connection while in provisioning mode")
	}

	w.opMu.Lock()
	defer w.opMu.Unlock()
	return w.activateConnection(ctx, ifName, ssid)
}

func (w *Provisioning) activateConnection(ctx context.Context, ifName, ssid string) error {
	now := time.Now()
	nw := w.netState.LockingNetwork(ifName, ssid)
	nw.mu.Lock()
	defer nw.mu.Unlock()

	if nw.conn == nil {
		return errw.Errorf("no settings found for network: %s", w.netState.GenNetKey(ifName, ssid))
	}

	w.logger.Infof("Activating connection: %s", w.netState.GenNetKey(ifName, ssid))

	var netDev gnm.Device
	if nw.netType == NetworkTypeWifi || nw.netType == NetworkTypeHotspot {
		// wifi
		if nw.netType != NetworkTypeHotspot {
			nw.lastTried = now
			w.netState.SetLastSSID(ifName, ssid)
		}
		netDev = w.netState.WifiDevice(ifName)
	} else {
		// wired
		nw.lastTried = now
		netDev = w.netState.EthDevice(ifName)
	}

	if netDev == nil {
		return errw.Errorf("cannot activate connection due to missing interface: %s", ifName)
	}

	activeConnection, err := w.nm.ActivateConnection(nw.conn, netDev, nil)
	if err != nil {
		nw.lastError = err
		return errw.Wrapf(err, "activating connection: %s", w.netState.GenNetKey(ifName, ssid))
	}

	if err := w.waitForConnect(ctx, netDev); err != nil {
		nw.lastError = err
		nw.connected = false
		return err
	}

	nw.connected = true
	nw.lastConnected = now
	nw.lastError = nil
	w.netState.SetActiveConn(ifName, activeConnection)

	w.logger.Infof("Successfully activated connection: %s", w.netState.GenNetKey(ifName, ssid))

	if nw.netType != NetworkTypeHotspot {
		w.netState.SetActiveSSID(ifName, ssid)
		if ifName == w.Config().HotspotInterface && (w.cfg.TurnOnHotspotIfWifiHasNoInternet || w.netState.PrimarySSID(ifName) == ssid) {
			w.connState.setConnected(true)
		}
		return w.checkOnline(true)
	}

	return nil
}

func (w *Provisioning) DeactivateConnection(ifName, ssid string) error {
	if w.connState.getProvisioning() && ifName == w.Config().HotspotInterface {
		return errors.New("cannot deactivate another connection while in provisioning mode")
	}

	w.opMu.Lock()
	defer w.opMu.Unlock()
	return w.deactivateConnection(ifName, ssid)
}

func (w *Provisioning) deactivateConnection(ifName, ssid string) error {
	activeConn := w.netState.ActiveConn(ifName)
	if activeConn == nil {
		return errw.Wrapf(ErrNoActiveConnectionFound, "interface: %s", ifName)
	}

	nw := w.netState.LockingNetwork(ifName, ssid)
	nw.mu.Lock()
	defer nw.mu.Unlock()

	w.logger.Infof("Deactivating connection: %s", w.netState.GenNetKey(ifName, ssid))

	if err := w.nm.DeactivateConnection(activeConn); err != nil {
		nw.lastError = err
		return errw.Wrapf(err, "deactivating connection: %s", w.netState.GenNetKey(ifName, ssid))
	}

	w.logger.Infof("Successfully deactivated connection: %s", w.netState.GenNetKey(ifName, ssid))

	if ifName == w.Config().HotspotInterface {
		w.connState.setConnected(false)
	}

	nw.connected = false
	nw.lastConnected = time.Now()
	nw.lastError = nil
	w.netState.SetActiveSSID(ifName, "")
	return nil
}

func (w *Provisioning) waitForConnect(ctx context.Context, device gnm.Device) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	changeChan := make(chan gnm.DeviceStateChange, 32)
	exitChan := make(chan struct{})
	defer close(exitChan)

	if err := device.SubscribeState(changeChan, exitChan); err != nil {
		return errw.Wrap(err, "monitoring connection activation")
	}

	for {
		select {
		case update := <-changeChan:
			w.logger.Debugf("%s->%s (%s)", update.OldState, update.NewState, update.Reason)
			//nolint:exhaustive
			switch update.NewState {
			case gnm.NmDeviceStateActivated:
				return nil
			case gnm.NmDeviceStateFailed:
				if update.Reason == gnm.NmDeviceStateReasonNoSecrets {
					return ErrBadPassword
				}
				// custom error if it's some other reason for failure
				return errw.Errorf("connection failed: %s", update.Reason)
			default:
			}
		default:
			if !w.mainLoopHealth.Sleep(timeoutCtx, time.Second) {
				return errw.Wrap(ctx.Err(), "waiting for network activation")
			}
		}
	}
}

func (w *Provisioning) AddOrUpdateConnection(cfg utils.NetworkDefinition) (bool, error) {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	return w.addOrUpdateConnection(cfg)
}

// returns true if network was new (added) and not updated.
func (w *Provisioning) addOrUpdateConnection(cfg utils.NetworkDefinition) (bool, error) {
	var changesMade bool

	if cfg.Type != NetworkTypeWifi && cfg.Type != NetworkTypeHotspot && cfg.Type != NetworkTypeWired {
		return changesMade, errw.Errorf("unspported network type %s, only %s and %s currently supported",
			cfg.Type, NetworkTypeWifi, NetworkTypeWired)
	}

	if cfg.Type != NetworkTypeWired && cfg.PSK != "" && len(cfg.PSK) < 8 {
		return changesMade, errors.New("wifi passwords must be at least 8 characters long, or completely empty (for unsecured networks)")
	}

	netKey := w.netState.GenNetKey(cfg.Interface, cfg.SSID)
	nw := w.netState.LockingNetwork(cfg.Interface, cfg.SSID)
	nw.lastTried = time.Time{}
	nw.priority = cfg.Priority

	var settings gnm.ConnectionSettings
	var err error
	if cfg.Type == NetworkTypeHotspot {
		if cfg.SSID != w.Config().HotspotSSID {
			return changesMade, errw.Errorf("only the builtin provisioning hotspot may use the %s network type", NetworkTypeHotspot)
		}
		nw.isHotspot = true
		settings = generateHotspotSettings(w.cfg.HotspotPrefix, w.Config().HotspotSSID, w.cfg.HotspotPassword, w.Config().HotspotInterface)
	} else {
		id := w.cfg.Manufacturer + "-" + netKey
		settings, err = generateNetworkSettings(id, cfg)
		w.logger.Debugf("Network settings: ", settings)
		if err != nil {
			return changesMade, errw.Errorf("error generating network settings for %s: %v", id, err)
		}
	}

	if cfg.Type == NetworkTypeWifi && !w.cfg.TurnOnHotspotIfWifiHasNoInternet && cfg.Priority == 999 {
		// lower the priority of any existing/prior primary network
		w.lowerMaxNetPriorities(cfg.SSID)
		w.netState.SetPrimarySSID(w.Config().HotspotInterface, cfg.SSID)
	}

	w.logger.Infof("Adding/updating settings for network %s", netKey)

	var oldSettings gnm.ConnectionSettings
	if nw.conn != nil {
		oldSettings, err = nw.conn.GetSettings()
		if err != nil {
			return changesMade, errw.Wrapf(err, "getting current settings for %s", netKey)
		}

		if err := nw.conn.Update(settings); err != nil {
			// we may be out of sync with NetworkManager
			nw.conn = nil
			w.logger.Warn(errw.Wrapf(err, "updating settings for %s, attempting to add as new network", netKey))
		}
	}

	if nw.conn == nil {
		changesMade = true
		newConn, err := w.settings.AddConnection(settings)
		if err != nil {
			return changesMade, errw.Wrap(err, "adding new connection")
		}
		nw.conn = newConn
		return changesMade, nil
	}

	newSettings, err := nw.conn.GetSettings()
	if err != nil {
		return changesMade, errw.Wrapf(err, "getting new settings for %s", netKey)
	}

	changesMade = !reflect.DeepEqual(oldSettings, newSettings) || changesMade

	return changesMade, nil
}

// this doesn't error as it's not technically fatal if it fails.
func (w *Provisioning) lowerMaxNetPriorities(skip string) {
	for _, nw := range w.netState.LockingNetworks() {
		netKey := w.netState.GenNetKey(nw.interfaceName, nw.ssid)
		if netKey == skip || netKey == w.netState.GenNetKey(w.Config().HotspotInterface, w.Config().HotspotSSID) || nw.priority < 999 ||
			nw.netType != NetworkTypeWifi || (nw.interfaceName != "" && nw.interfaceName != w.Config().HotspotInterface) {
			continue
		}

		nw.mu.Lock()
		if nw.conn != nil {
			settings, err := nw.conn.GetSettings()
			if err != nil {
				nw.conn = nil
				w.logger.Warnf("error (%s) encountered when getting settings for %s", err, nw.ssid)
				nw.mu.Unlock()
				continue
			}

			if getPriorityFromSettings(settings) == 999 {
				settings["connection"]["autoconnect-priority"] = 998

				// deprecated fields that are read-only, so can't try to set them
				delete(settings["ipv6"], "addresses")
				delete(settings["ipv6"], "routes")

				w.logger.Debugf("Lowering priority of %s to 998", netKey)

				if err := nw.conn.Update(settings); err != nil {
					nw.conn = nil
					w.logger.Warnf("error (%s) encountered when updating settings for %s", err, netKey)
				}
			}
			nw.priority = getPriorityFromSettings(settings)
		}
		nw.mu.Unlock()
	}
}

func (w *Provisioning) checkConfigured() {
	_, err := os.ReadFile(utils.AppConfigFilePath)
	w.connState.setConfigured(err == nil)
}

// tryCandidates returns true if a network activated.
func (w *Provisioning) tryCandidates(ctx context.Context) bool {
	for _, ssid := range w.getCandidates(w.Config().HotspotInterface) {
		err := w.ActivateConnection(ctx, w.Config().HotspotInterface, ssid)
		if err != nil {
			w.logger.Error(err)
			continue
		}

		// in single mode we just need a connection
		if !w.cfg.TurnOnHotspotIfWifiHasNoInternet {
			return true
		}

		// in roaming mode we need full internet
		if w.connState.getOnline() {
			return true
		}

		w.logger.Warnf("SSID %s connected, but does not provide internet access.", ssid)
	}
	return false
}

func (w *Provisioning) getCandidates(ifName string) []string {
	var candidates []network
	for _, nw := range w.netState.Networks() {
		if nw.netType != NetworkTypeWifi || (nw.interfaceName != "" && nw.interfaceName != ifName) {
			continue
		}
		// ssid seen within the past minute
		visible := nw.lastSeen.After(time.Now().Add(VisibleNetworkTimeout * -1))

		// ssid has a connection known to network manager
		configured := nw.conn != nil

		// firstSeen/lastTried are reset if a network disappears for more than a minute, so retry if it comes back (or 10 mins)
		recentlyTried := nw.lastTried.After(nw.firstSeen) && nw.lastTried.After(time.Now().Add(time.Duration(w.cfg.RetryConnectionTimeoutMinutes)*-1))

		if !nw.isHotspot && visible && configured && !recentlyTried {
			candidates = append(candidates, nw)
		}
	}

	if !w.cfg.TurnOnHotspotIfWifiHasNoInternet {
		for _, nw := range candidates {
			if nw.ssid == w.netState.PrimarySSID(w.Config().HotspotInterface) {
				return []string{nw.ssid}
			}
		}
	}

	// sort by priority
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].priority > candidates[j].priority })

	var out []string
	for _, nw := range candidates {
		out = append(out, nw.ssid)
	}

	return out
}

func (w *Provisioning) backgroundLoop(ctx context.Context, scanChan chan<- bool) {
	defer w.monitorWorkers.Done()
	w.logger.Info("Background state monitors started")
	defer w.logger.Info("Background state monitors stopped")
	for {
		if !w.bgLoopHealth.Sleep(ctx, scanLoopDelay) {
			return
		}

		w.checkConfigured()
		if err := w.networkScan(ctx); err != nil {
			w.logger.Error(err)
		}
		if err := w.updateKnownConnections(ctx); err != nil {
			w.logger.Error(err)
		}
		if err := w.checkConnections(); err != nil {
			w.logger.Error(err)
		}
		if err := w.checkOnline(false); err != nil {
			w.logger.Error(err)
		}
		scanChan <- true
	}
}

func (w *Provisioning) mainLoop(ctx context.Context) {
	defer w.monitorWorkers.Done()

	scanChan := make(chan bool, 16)
	inputChan := make(chan userInput, 1)

	w.monitorWorkers.Add(1)
	go w.backgroundLoop(ctx, scanChan)

	for {
		var userInputReceived bool

		select {
		case <-ctx.Done():
			return
		case userInput := <-inputChan:
			if userInput.RawConfig != "" || userInput.PartID != "" {
				w.logger.Info("Device config received")
				err := WriteDeviceConfig(utils.AppConfigFilePath, userInput)
				if err != nil {
					w.errors.Add(err)
					w.logger.Error(err)
					continue
				}
				w.checkConfigured()
				userInputReceived = true
			}

			var newSSID string
			var changesMade bool
			if userInput.SSID != "" {
				w.logger.Infof("Wifi settings received for %s", userInput.SSID)
				priority := int32(999)
				if w.cfg.TurnOnHotspotIfWifiHasNoInternet {
					priority = 100
				}
				cfg := utils.NetworkDefinition{
					Type:     NetworkTypeWifi,
					SSID:     userInput.SSID,
					PSK:      userInput.PSK,
					Priority: priority,
				}
				var err error
				changesMade, err = w.AddOrUpdateConnection(cfg)
				if err != nil {
					w.errors.Add(err)
					w.logger.Error(err)
					continue
				}
				userInputReceived = true
				newSSID = cfg.SSID
			}

			// wait 3 seconds so responses can be sent to/seen by user
			if !w.mainLoopHealth.Sleep(ctx, time.Second*3) {
				return
			}
			if changesMade {
				err := w.StopProvisioning()
				if err != nil {
					w.logger.Error(err)
					continue
				}
				err = w.ActivateConnection(ctx, w.Config().HotspotInterface, newSSID)
				if err != nil {
					w.logger.Error(err)
					continue
				}
				if !w.connState.getOnline() {
					err := w.deactivateConnection(w.Config().HotspotInterface, newSSID)
					if err != nil {
						w.logger.Error(err)
					}
					nw := w.netState.LockingNetwork("", newSSID)
					nw.mu.Lock()
					if nw.conn != nil {
						// add a user warning for the portal
						err = errw.New("Network has no internet. Resubmit to use anyway.")
						nw.lastError = err
						w.logger.Warn(err)
					} else {
						w.logger.Error("cannot find %s in network list", w.netState.GenNetKey("", newSSID))
					}
					nw.mu.Unlock()
					err = w.StartProvisioning(ctx, inputChan)
					if err != nil {
						w.logger.Error(err)
					}
				}
			}
		case <-scanChan:
		case <-time.After((scanLoopDelay + scanTimeout) * 2):
			// safety fallback if something hangs
			w.logger.Warnf("wifi scan has not completed for %s", (scanLoopDelay+scanTimeout)*2)
		}

		w.mainLoopHealth.MarkGood()

		isOnline := w.connState.getOnline()
		lastOnline := w.connState.getLastOnline()
		isConnected := w.connState.getConnected()
		lastConnected := w.connState.getLastConnected()
		hasConnectivity := isConnected || isOnline
		lastConnectivity := lastConnected
		if lastOnline.After(lastConnected) {
			lastConnectivity = lastOnline
		}
		isConfigured := w.connState.getConfigured()
		allGood := isConfigured && (isConnected || isOnline)
		if w.cfg.TurnOnHotspotIfWifiHasNoInternet {
			allGood = isOnline && isConfigured
			hasConnectivity = isOnline
			lastConnectivity = lastOnline
		}
		pMode := w.connState.getProvisioning()
		pModeChange := w.connState.getProvisioningChange()
		now := time.Now()

		w.logger.Debugf("wifi: %t (%s), internet: %t, config present: %t",
			isConnected,
			w.netState.GenNetKey(w.Config().HotspotInterface, w.netState.ActiveSSID(w.Config().HotspotInterface)),
			isOnline,
			isConfigured,
		)

		if pMode {
			// complex logic, so wasting some variables for readability

			// portal interaction time is updated when a user loads a page or makes a grpc request
			inactivePortal := w.connState.getLastInteraction().Before(now.Add(time.Duration(w.cfg.UserIdleMinutes)*-1)) || userInputReceived

			// exit/retry to test networks only if there's no recent user interaction AND configuration is present
			haveCandidates := len(w.getCandidates(w.Config().HotspotInterface)) > 0 && inactivePortal && isConfigured

			// exit/retry every FallbackTimeout (10 minute default), unless user is active
			fallbackHit := pModeChange.Before(now.Add(time.Duration(w.cfg.RetryConnectionTimeoutMinutes)*-1)) && inactivePortal

			shouldExit := allGood || haveCandidates || fallbackHit

			w.logger.Debugf("inactive portal: %t, have candidates: %t, fallback timeout: %t", inactivePortal, haveCandidates, fallbackHit)

			if shouldExit {
				if err := w.StopProvisioning(); err != nil {
					w.logger.Error(err)
				} else {
					pMode = w.connState.getProvisioning()
					pModeChange = w.connState.getProvisioningChange()
				}
			}
		}

		if allGood || pMode {
			continue
		}

		// not in provisioning mode
		if !hasConnectivity {
			if w.tryCandidates(ctx) {
				hasConnectivity = w.connState.getConnected() || w.connState.getOnline()
				// if we're roaming or this network was JUST added, it must have internet
				if w.cfg.TurnOnHotspotIfWifiHasNoInternet {
					hasConnectivity = w.connState.getOnline()
				}
				if hasConnectivity {
					continue
				}
				lastConnectivity = w.connState.getLastConnected()
				if w.cfg.TurnOnHotspotIfWifiHasNoInternet {
					lastConnectivity = w.connState.getLastOnline()
				}
			}
		}

		offlineRebootTimeout := w.cfg.DeviceRebootAfterOfflineMinutes > 0 &&
			lastConnectivity.Before(now.Add(time.Duration(w.cfg.DeviceRebootAfterOfflineMinutes)*-1))
		if offlineRebootTimeout {
			w.logger.Infof("device has been offline for more than %s, rebooting", time.Duration(w.cfg.DeviceRebootAfterOfflineMinutes))
			cmd := exec.Command("systemctl", "reboot")
			output, err := cmd.CombinedOutput()
			if err != nil {
				w.logger.Error(errw.Wrapf(err, "running 'systemctl reboot' %s", output))
			}
			if !w.mainLoopHealth.Sleep(ctx, time.Minute*5) {
				return
			}
			w.logger.Errorf("failed to reboot after %s time", time.Minute*5)
		}

		hitOfflineTimeout := lastConnectivity.Before(now.Add(time.Duration(w.cfg.OfflineBeforeStartingHotspotMinutes)*-1)) &&
			pModeChange.Before(now.Add(time.Duration(w.cfg.OfflineBeforeStartingHotspotMinutes)*-1))
		// not in provisioning mode, so start it if not configured (/etc/viam.json)
		// OR as long as we've been offline AND out of provisioning mode for at least OfflineTimeout (2 minute default)
		if !isConfigured || hitOfflineTimeout {
			if err := w.StartProvisioning(ctx, inputChan); err != nil {
				w.logger.Error(err)
			}
		}
	}
}
