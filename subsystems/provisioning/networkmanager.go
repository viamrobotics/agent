package provisioning

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sort"
	"time"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"
)

func (w *Provisioning) GetHotspotInterface() string {
	w.dataMu.Lock()
	defer w.dataMu.Unlock()
	return w.hotspotInterface
}

func (w *Provisioning) warnIfMultiplePrimaryNetworks() {
	if w.cfg.RoamingMode {
		return
	}
	w.dataMu.Lock()
	defer w.dataMu.Unlock()
	var primaryCandidates []string
	highestPriority := int32(-999)
	for _, nw := range w.netState.Networks() {
		if nw.conn == nil || nw.isHotspot || nw.netType != NetworkTypeWifi ||
			(nw.interfaceName != "" && nw.interfaceName != w.hotspotInterface) {
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
		if nw.lastSeen.After(time.Now().Add(time.Minute*-1)) && !nw.isHotspot {
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
	lastNetwork := w.netState.LastNetwork(w.hotspotInterface)
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

func (w *Provisioning) CheckConnections() error {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	var connected bool
	defer func() {
		if connected && w.activeSSID[w.hotspotInterface] != "" {
			w.logger.Debugf("Connected to: %s", w.activeSSID[w.hotspotInterface])
		}
		w.connState.setConnected(connected)
	}()

	// merge the two device types into a single generic list
	allDevices := make(map[string]gnm.Device)
	for ifName, dev := range w.wifiDevices {
		allDevices[ifName] = dev
	}
	for ifName, dev := range w.wifiDevices {
		allDevices[ifName] = dev
	}

	for ifName, dev := range allDevices {
		activeConnection, err := dev.GetPropertyActiveConnection()
		if err != nil {
			return err
		}
		if activeConnection == nil {
			w.activeConn[ifName] = nil
			w.activeSSID[ifName] = ""
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

		ssid := getSSIDFromSettings(settings)
		netKey := genNetKey(ifName, ssid)
		nw, ok := w.networks[netKey]
		if !ok {
			netKey := genNetKey("any", ssid)
			nw = w.networks[netKey]
		}
		if nw == nil {
			continue
		}

		state, err := activeConnection.GetPropertyState()
		if err != nil {
			w.logger.Error(errw.Wrapf(err, "getting state of active connection: %s", ssid))
			w.activeConn[ifName] = nil
			nw.connected = false
			w.activeSSID[ifName] = ""
		}

		w.activeConn[ifName] = activeConnection
		w.activeSSID[ifName] = ssid
		nw.connected = true

		// if this isn't the primary wifi device, we're done
		if ifName != w.hotspotInterface {
			continue
		}

		// in roaming mode, we don't care WHAT network is connected
		if w.cfg.RoamingMode && state == gnm.NmActiveConnectionStateActivated && ssid != w.hotspotSSID {
			connected = true
		}

		// in normal (single) mode, we need to be connected to the primary (highest priority) network
		if !w.cfg.RoamingMode && state == gnm.NmActiveConnectionStateActivated && ssid == w.primarySSID[w.hotspotInterface] {
			connected = true
		}
	}

	return nil
}

// StartProvisioning puts the wifi in hotspot mode and starts a captive portal.
func (w *Provisioning) StartProvisioning(ctx context.Context) error {
	if w.connState.getProvisioning() {
		return errors.New("provisioning mode already started")
	}

	w.opMu.Lock()
	defer w.opMu.Unlock()

	w.logger.Info("Starting provisioning mode.")
	_, err := w.addOrUpdateConnection(NetworkConfig{
		Type:      NetworkTypeHotspot,
		Interface: w.hotspotInterface,
		SSID:      w.hotspotSSID,
	})
	if err != nil {
		return err
	}
	if err := w.activateConnection(ctx, w.hotspotInterface, w.hotspotSSID); err != nil {
		return errw.Wrap(err, "error starting provisioning mode hotspot")
	}

	// start portal with ssid list and known connections
	if err := w.startPortal(); err != nil {
		err = errors.Join(err, w.deactivateConnection(w.hotspotInterface, w.hotspotSSID))
		return errw.Wrap(err, "could not start web/grpc portal")
	}

	w.connState.setProvisioning(true)
	return nil
}

func (w *Provisioning) StopProvisioning() error {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	w.logger.Info("Stopping provisioning mode.")
	w.connState.setProvisioning(false)
	err := w.stopPortal()
	w.provisioningWorkers.Wait()
	err2 := w.deactivateConnection(w.hotspotInterface, w.hotspotSSID)
	if errors.Is(err2, ErrNoActiveConnectionFound) {
		return err
	}
	return errors.Join(err, err2)
}

func (w *Provisioning) ActivateConnection(ctx context.Context, ifName, ssid string) error {
	if w.connState.getProvisioning() && ifName == w.hotspotInterface {
		return errors.New("cannot activate another connection while in provisioning mode")
	}

	w.opMu.Lock()
	defer w.opMu.Unlock()
	return w.activateConnection(ctx, ifName, ssid)
}

func (w *Provisioning) activateConnection(ctx context.Context, ifName, ssid string) error {
	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	now := time.Now()
	netKey := genNetKey(ifName, ssid)
	nw, ok := w.networks[netKey]
	if !ok && ssid != "" {
		netKey = genNetKey("any", ssid)
		nw = w.networks[netKey]
	}
	if nw == nil || nw.conn == nil {
		return errw.Errorf("no settings found for ssid: %s", netKey)
	}

	w.logger.Infof("Activating connection: %s", netKey)

	var netDev gnm.Device
	if nw.netType == NetworkTypeWifi || nw.netType == NetworkTypeHotspot {
		// use the main wifi device if it's not explicitly set
		ifNameOpt := ifName
		if ifNameOpt == "" {
			ifNameOpt = w.hotspotInterface
		}

		// wifi
		if nw.netType != NetworkTypeHotspot {
			nw.lastTried = now
			w.lastSSID[ifName] = ssid
		}

		netDev, ok = w.wifiDevices[ifNameOpt]
		if !ok {
			return errw.Errorf("cannot find wifi interface: %s", ifName)
		}
	} else {
		// wired
		nw.lastTried = now
		netDev, ok = w.ethDevices[ifName]
		if !ok {
			return errw.Errorf("cannot find wired interface: %s", ifName)
		}
	}

	activeConnection, err := w.nm.ActivateConnection(nw.conn, netDev, nil)
	if err != nil {
		nw.lastError = err
		return errw.Wrapf(err, "activating connection: %s", netKey)
	}

	if err := w.waitForConnect(ctx, netDev); err != nil {
		nw.lastError = err
		nw.connected = false
		return err
	}

	nw.connected = true
	nw.lastConnected = now
	w.activeConn[ifName] = activeConnection
	nw.lastError = nil

	w.logger.Infof("Successfully activated connection: %s", netKey)

	if nw.netType != NetworkTypeHotspot {
		w.activeSSID[ifName] = ssid
		if ifName == w.hotspotInterface && (w.cfg.RoamingMode || w.primarySSID[ifName] == ssid) {
			w.connState.setConnected(true)
		}
		return w.checkOnline(true)
	}

	return nil
}

func (w *Provisioning) DeactivateConnection(ifName, ssid string) error {
	if w.connState.getProvisioning() && ifName == w.hotspotInterface {
		return errors.New("cannot deactivate another connection while in provisioning mode")
	}

	w.opMu.Lock()
	defer w.opMu.Unlock()
	return w.deactivateConnection(ifName, ssid)
}

func (w *Provisioning) deactivateConnection(ifName, ssid string) error {
	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	activeConn, ok := w.activeConn[ifName]
	if !ok {
		return errw.Wrapf(ErrNoActiveConnectionFound, "cannot find interface: %s", ifName)
	}

	netKey := genNetKey(ifName, ssid)
	nw, ok := w.networks[netKey]
	if !ok && ssid != "" {
		netKey = genNetKey("any", ssid)
		nw = w.networks[netKey]
	}
	if nw == nil {
		return errw.Wrapf(ErrNoActiveConnectionFound, "%s", netKey)
	}

	w.logger.Infof("Deactivating connection: %s", netKey)

	if err := w.nm.DeactivateConnection(activeConn); err != nil {
		nw.lastError = err
		return errw.Wrapf(err, "deactivating connection: %s", netKey)
	}

	w.logger.Infof("Successfully deactivated connection: %s", netKey)

	w.connState.setConnected(false)
	nw.connected = false
	nw.lastConnected = time.Now()
	nw.lastError = nil
	w.activeSSID[ifName] = ""
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
			if !HealthySleep(timeoutCtx, time.Second) {
				return errw.Wrap(ctx.Err(), "waiting for network activation")
			}
		}
	}
}

func (w *Provisioning) AddOrUpdateConnection(cfg NetworkConfig) (bool, error) {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	return w.addOrUpdateConnection(cfg)
}

// returns true if network was new (added) and not updated.
func (w *Provisioning) addOrUpdateConnection(cfg NetworkConfig) (bool, error) {
	var changesMade bool

	if cfg.Type != NetworkTypeWifi && cfg.Type != NetworkTypeHotspot && cfg.Type != NetworkTypeWired {
		return changesMade, errw.Errorf("unspported network type %s, only %s and %s currently supported",
			cfg.Type, NetworkTypeWifi, NetworkTypeWired)
	}

	if cfg.Type != NetworkTypeWired && cfg.PSK != "" && len(cfg.PSK) < 8 {
		return changesMade, errors.New("wifi passwords must be at least 8 characters long, or completely empty (for unsecured networks)")
	}

	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	netKey := genNetKey(cfg.Interface, cfg.SSID)
	nw, ok := w.networks[netKey]
	if !ok && cfg.SSID != "" {
		netKey = genNetKey("any", cfg.SSID)
		nw = w.networks[netKey]
	}

	if nw == nil {
		nw = &network{
			netType:       cfg.Type,
			interfaceName: cfg.Interface,
			ssid:          cfg.SSID,
		}
		netKey = genNetKey(cfg.Interface, cfg.SSID)
		w.networks[netKey] = nw
	}

	nw.lastTried = time.Time{}
	nw.priority = cfg.Priority

	var settings gnm.ConnectionSettings
	var err error
	if cfg.Type != NetworkTypeHotspot {
		settings, err = generateNetworkSettings(w.cfg.Manufacturer+"-"+netKey, cfg)
		if err != nil {
			return changesMade, err
		}
	} else {
		if cfg.SSID != w.hotspotSSID {
			return changesMade, errw.Errorf("only the builtin provisioning hotspot may use the %s network type", NetworkTypeHotspot)
		}
		nw.isHotspot = true
		settings = generateHotspotSettings(w.cfg.HotspotPrefix, w.hotspotSSID, w.cfg.HotspotPassword, w.hotspotInterface)
	}

	if !w.cfg.RoamingMode && cfg.Priority == 999 {
		// lower the priority of any existing/prior primary network
		w.lowerMaxNetPriorities(cfg.SSID)
		w.primarySSID[w.hotspotInterface] = cfg.SSID
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
	for netKey, nw := range w.networks {
		if netKey == skip || netKey == genNetKey(w.hotspotInterface, w.hotspotSSID) || nw.priority < 999 ||
			nw.netType != NetworkTypeWifi || (nw.interfaceName != "" && nw.interfaceName != w.hotspotInterface) {
			continue
		}

		if nw.conn != nil {
			settings, err := nw.conn.GetSettings()
			if err != nil {
				nw.conn = nil
				w.logger.Warnf("error (%s) encountered when getting settings for %s", err, nw.ssid)
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
	}
}

func (w *Provisioning) checkConfigured() {
	_, err := os.ReadFile(w.AppCfgPath)
	w.connState.setConfigured(err == nil)
}

// tryCandidates returns true if a network activated.
func (w *Provisioning) tryCandidates(ctx context.Context) bool {
	for _, ssid := range w.getCandidates(w.hotspotInterface) {
		err := w.ActivateConnection(ctx, w.hotspotInterface, ssid)
		if err != nil {
			w.logger.Error(err)
			continue
		}

		// in single mode we just need a connection
		if !w.cfg.RoamingMode {
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
	w.dataMu.Lock()
	defer w.dataMu.Unlock()
	var candidates []*network
	for _, nw := range w.networks {
		if nw.netType != NetworkTypeWifi || (nw.interfaceName != "" && nw.interfaceName != ifName) {
			continue
		}
		// ssid seen within the past minute
		visible := nw.lastSeen.After(time.Now().Add(time.Minute * -1))

		// ssid has a connection known to network manager
		configured := nw.conn != nil

		// firstSeen is reset if a network disappears for more than a minute, so retry if it comes back (or generally after 10 minutes)
		recentlyTried := nw.lastTried.After(nw.firstSeen) && nw.lastTried.After(time.Now().Add(time.Duration(w.cfg.FallbackTimeout)*-1))

		if !nw.isHotspot && visible && configured && !recentlyTried {
			candidates = append(candidates, nw)
		}
	}

	if !w.cfg.RoamingMode {
		for _, nw := range candidates {
			if nw.ssid == w.primarySSID[w.hotspotInterface] {
				return []string{nw.ssid}
			}
		}
		return []string{}
	}

	// sort by priority
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].priority > candidates[j].priority })

	var out []string
	for _, nw := range candidates {
		out = append(out, nw.ssid)
	}

	return out
}

func (w *Provisioning) startStateMonitors(ctx context.Context) {
	if err := w.checkOnline(true); err != nil {
		w.logger.Error(err)
	}

	w.monitorWorkers.Add(1)
	go func() {
		defer w.monitorWorkers.Done()
		w.logger.Info("Background state monitors started")
		defer w.logger.Info("Background state monitors stopped")
		for {
			if !Sleep(ctx, scanLoopDelay) {
				return
			}

			w.checkConfigured()
			if err := w.NetworkScan(ctx); err != nil {
				w.logger.Error(err)
			}
			if err := w.CheckConnections(); err != nil {
				w.logger.Error(err)
			}
			if err := w.checkOnline(false); err != nil {
				w.logger.Error(err)
			}
		}
	}()
}

func (w *Provisioning) StartMonitoring(ctx context.Context) error {
	w.startStateMonitors(ctx)

	var userInputReceived bool

	for {
		if !HealthySleep(ctx, mainLoopDelay) {
			return nil
		}
		userInput := w.GetUserInput()
		if userInput != nil {
			if userInput.RawConfig != "" || userInput.PartID != "" {
				w.logger.Info("Device config received")
				err := WriteDeviceConfig(w.AppCfgPath, *userInput)
				if err != nil {
					w.dataMu.Lock()
					w.errors = append(w.errors, err)
					w.dataMu.Unlock()
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
				if w.cfg.RoamingMode {
					priority = 100
				}
				cfg := NetworkConfig{
					Type:     "wifi",
					SSID:     userInput.SSID,
					PSK:      userInput.PSK,
					Priority: priority,
				}
				var err error
				changesMade, err = w.AddOrUpdateConnection(cfg)
				if err != nil {
					w.dataMu.Lock()
					w.errors = append(w.errors, err)
					w.dataMu.Unlock()
					w.logger.Error(err)
					continue
				}
				userInputReceived = true
				newSSID = cfg.SSID
			}

			// wait 3 seconds so responses can be sent to/seen by user
			if !HealthySleep(ctx, time.Second*3) {
				return nil
			}
			if changesMade {
				err := w.StopProvisioning()
				if err != nil {
					w.logger.Error(err)
					continue
				}
				err = w.ActivateConnection(ctx, w.hotspotInterface, newSSID)
				if err != nil {
					w.logger.Error(err)
					continue
				}
				if !w.connState.getOnline() {
					err := w.deactivateConnection(w.hotspotInterface, newSSID)
					if err != nil {
						w.logger.Error(err)
					}
					w.dataMu.Lock()
					netKey := genNetKey("", newSSID)
					nw, ok := w.networks[netKey]
					if ok {
						// add a user warning for the portal
						err = errw.New("Network has no internet. Resubmit to use anyway.")
						nw.lastError = err
						w.logger.Warn(err)
					} else {
						w.logger.Error("cannot find %s in network list", netKey)
					}
					w.dataMu.Unlock()
					err = w.StartProvisioning(ctx)
					if err != nil {
						w.logger.Error(err)
					}
				}
			}
		}

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
		if w.cfg.RoamingMode {
			allGood = isOnline && isConfigured
			hasConnectivity = isOnline
			lastConnectivity = lastOnline
		}
		pMode := w.connState.getProvisioning()
		pModeChange := w.connState.getProvisioningChange()
		now := time.Now()

		w.logger.Debugf("wifi connected: %t, internet reachable: %t, config present: %t", isConnected, isOnline, isConfigured)

		if pMode {
			// complex logic, so wasting some variables for readability

			// portal interaction time is updated when a user loads a page or makes a grpc request
			inactivePortal := w.connState.getLastInteraction().Before(now.Add(time.Duration(w.cfg.UserTimeout)*-1)) || userInputReceived

			// exit/retry to test networks only if there's no recent user interaction AND configuration is present
			haveCandidates := len(w.getCandidates(w.hotspotInterface)) > 0 && inactivePortal && isConfigured

			// exit/retry every FallbackTimeout (10 minute default), unless user is active
			fallbackHit := pModeChange.Before(now.Add(time.Duration(w.cfg.FallbackTimeout)*-1)) && inactivePortal

			shouldExit := allGood || haveCandidates || fallbackHit

			w.logger.Debugf("inactive portal: %t, have candidates: %t, fallback timeout: %t", inactivePortal, haveCandidates, fallbackHit)

			if shouldExit {
				if err := w.StopProvisioning(); err != nil {
					w.logger.Error(err)
				} else {
					pMode = w.connState.getProvisioning()
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
				if w.cfg.RoamingMode {
					hasConnectivity = w.connState.getOnline()
				}
				if hasConnectivity {
					continue
				}
				lastConnectivity = w.connState.getLastConnected()
				if w.cfg.RoamingMode {
					lastConnectivity = w.connState.getLastOnline()
				}
			}
		}

		// not in provisioning mode, so start it if not configured (/etc/viam.json)
		// OR as long as we've been offline for at least OfflineTimeout (2 minute default)
		if !isConfigured || lastConnectivity.Before(now.Add(time.Duration(w.cfg.OfflineTimeout)*-1)) {
			if err := w.StartProvisioning(ctx); err != nil {
				w.logger.Error(err)
			}
		}
	}
}
