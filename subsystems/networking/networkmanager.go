package networking

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"time"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
)

func (n *Networking) warnIfMultiplePrimaryNetworks() {
	if n.Config().TurnOnHotspotIfWifiHasNoInternet {
		return
	}
	var primaryCandidates []string
	highestPriority := int32(-999)
	for _, nw := range n.netState.Networks() {
		if nw.conn == nil || nw.isHotspot || nw.netType != NetworkTypeWifi ||
			(nw.interfaceName != "" && nw.interfaceName != n.Config().HotspotInterface) {
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
		n.logger.Warnf(
			"Multiple networks %s tied for highest priority (%d), selection will be arbitrary. Consider using Roaming Mode.",
			primaryCandidates,
			highestPriority,
		)
	}
}

func (n *Networking) getVisibleNetworks() []NetworkInfo {
	var visible []NetworkInfo
	for _, nw := range n.netState.Networks() {
		// note this does NOT use VisibleNetworkTimeout (like getCandidates does)
		recentlySeen := nw.lastSeen.After(n.connState.getProvisioningChange().Add(
			time.Duration(n.Config().OfflineBeforeStartingHotspotMinutes * -2)))

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

func (n *Networking) getLastNetworkTried() NetworkInfo {
	lastNetwork := n.netState.LastNetwork(n.Config().HotspotInterface)
	return lastNetwork.getInfo()
}

func (n *Networking) checkOnline(force bool) error {
	if force {
		if err := n.nm.CheckConnectivity(); err != nil {
			n.logger.Error(err)
		}
	}

	state, err := n.nm.State()
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

	n.connState.setOnline(online)
	return err
}

func (n *Networking) checkConnections() error {
	var connected bool
	defer func() {
		n.connState.setConnected(connected)
	}()

	for ifName, dev := range n.netState.Devices() {
		activeConnection, err := dev.GetPropertyActiveConnection()
		if err != nil {
			return err
		}
		if activeConnection == nil {
			n.netState.SetActiveConn(ifName, nil)
			n.netState.SetActiveSSID(ifName, "")
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
		nw := n.netState.LockingNetwork(connIfName, ssid)

		state, err := activeConnection.GetPropertyState()
		nw.mu.Lock()
		if err != nil {
			n.logger.Error(errw.Wrapf(err, "getting state of active connection: %s", n.netState.GenNetKey(ifName, ssid)))
			n.netState.SetActiveConn(ifName, nil)
			n.netState.SetActiveSSID(ifName, "")
			nw.connected = false
		} else {
			n.netState.SetActiveConn(ifName, activeConnection)
			n.netState.SetActiveSSID(ifName, ssid)
			nw.connected = true
		}
		nw.mu.Unlock()

		// if this isn't the primary wifi device, we're done
		if ifName != n.Config().HotspotInterface {
			continue
		}

		// in roaming mode, we don't care WHAT network is connected
		if n.Config().TurnOnHotspotIfWifiHasNoInternet && state == gnm.NmActiveConnectionStateActivated && ssid != n.Config().HotspotSSID {
			connected = true
		}

		// in normal (single) mode, we need to be connected to the primary (highest priority) network
		if !n.Config().TurnOnHotspotIfWifiHasNoInternet && state == gnm.NmActiveConnectionStateActivated &&
			ssid == n.netState.PrimarySSID(n.Config().HotspotInterface) {
			connected = true
		}
	}

	return nil
}

// StartProvisioning puts the wifi in hotspot mode and starts a captive portal.
func (n *Networking) StartProvisioning(ctx context.Context, inputChan chan<- userInput) error {
	if n.connState.getProvisioning() {
		return errors.New("provisioning mode already started")
	}

	n.opMu.Lock()
	defer n.opMu.Unlock()

	n.logger.Info("Starting provisioning mode.")

	var hotspotErr error
	if err := n.startProvisioningHotspot(ctx, inputChan); err != nil {
		hotspotErr = err
	}
	var bluetoothErr error
	if err := n.startProvisioningBluetooth(ctx, inputChan); err != nil {
		bluetoothErr = err
	}
	if hotspotErr != nil && bluetoothErr != nil { //nolint:gocritic
		n.connState.setProvisioningMode(hotspotAndBluetooth)
		return nil
	} else if hotspotErr == nil && bluetoothErr != nil {
		n.connState.setProvisioningMode(hotspotOnly)
		return bluetoothErr
	} else if hotspotErr != nil && bluetoothErr == nil {
		n.connState.setProvisioningMode(bluetoothOnly)
		return hotspotErr
	} else {
		n.connState.setProvisioningMode(none)
		return errors.Join(hotspotErr, bluetoothErr)
	}
}

// startProvisioningHotspot should only be called by 'StartProvisioning' (to ensure opMutex is acquired).
func (n *Networking) startProvisioningHotspot(ctx context.Context, inputChan chan<- userInput) error {
	_, err := n.addOrUpdateConnection(utils.NetworkDefinition{
		Type:      NetworkTypeHotspot,
		Interface: n.Config().HotspotInterface,
		SSID:      n.Config().HotspotSSID,
	})
	if err != nil {
		return err
	}
	if err := n.activateConnection(ctx, n.Config().HotspotInterface, n.Config().HotspotSSID); err != nil {
		return errw.Wrap(err, "starting provisioning mode hotspot")
	}

	// start portal with ssid list and known connections
	if err := n.startPortal(inputChan); err != nil {
		err = errors.Join(err, n.deactivateConnection(n.Config().HotspotInterface, n.Config().HotspotSSID))
		return errw.Wrap(err, "starting web/grpc portal")
	}
	n.logger.Info("Hotspot provisioning set up successfully.")
	return nil
}

// startProvisioningBluetooth should only be called by 'StartProvisioning' (to ensure opMutex is acquired).
func (n *Networking) startProvisioningBluetooth(ctx context.Context, inputChan chan<- userInput,
) error {
	if err := n.prepareBluetooth(); err != nil {
		return err
	}
	if err := n.bluetoothService.start(ctx, true, true, inputChan); err != nil {
		return err
	}
	n.logger.Info("Bluetooth provisioning set up successfully.")
	return nil
}

func (n *Networking) prepareBluetooth() error {
	if n.bluetoothService != nil {
		return nil
	}
	deviceName := fmt.Sprintf("%s.%s.%s", n.Config().Manufacturer, n.Config().Model, n.Config().FragmentID)
	bt, health, err := newBluetoothService(n.logger, deviceName, n.getVisibleNetworks)
	if err != nil {
		return err
	}
	n.bluetoothService = bt
	n.bluetoothHealth = health
	return nil
}

func (n *Networking) StopProvisioning() error {
	n.opMu.Lock()
	defer n.opMu.Unlock()
	return n.stopProvisioning()
}

func (n *Networking) stopProvisioning() error {
	n.logger.Info("Stopping provisioning mode.")
	n.connState.setProvisioningMode(none)
	return errors.Join(
		n.stopProvisioningHotspot(),
		n.stopProvisioningBluetooth(),
	)
}

func (n *Networking) stopProvisioningHotspot() error {
	err := n.stopPortal()
	err2 := n.deactivateConnection(n.Config().HotspotInterface, n.Config().HotspotSSID)
	if errors.Is(err2, ErrNoActiveConnectionFound) {
		return err
	}
	if err := errors.Join(err, err2); err != nil {
		return err
	}
	n.logger.Info("Stopped hotspot provisioning mode.")
	return nil
}

// stopProvisioningBluetooth should only be called by a caller who has verified the
// bluetooth service is active.
func (n *Networking) stopProvisioningBluetooth() error {
	if err := n.bluetoothService.stop(); err != nil {
		return err
	}
	n.logger.Info("Stopped bluetooth provisioning mode.")
	return nil
}

func (n *Networking) ActivateConnection(ctx context.Context, ifName, ssid string) error {
	if n.connState.getProvisioning() && ifName == n.Config().HotspotInterface {
		return errors.New("cannot activate another connection while in provisioning mode")
	}

	n.opMu.Lock()
	defer n.opMu.Unlock()
	return n.activateConnection(ctx, ifName, ssid)
}

func (n *Networking) activateConnection(ctx context.Context, ifName, ssid string) error {
	now := time.Now()
	nw := n.netState.LockingNetwork(ifName, ssid)
	nw.mu.Lock()
	defer nw.mu.Unlock()

	if nw.conn == nil {
		return errw.Errorf("no settings found for network: %s", n.netState.GenNetKey(ifName, ssid))
	}

	n.logger.Infof("Activating connection: %s", n.netState.GenNetKey(ifName, ssid))

	var netDev gnm.Device
	if nw.netType == NetworkTypeWifi || nw.netType == NetworkTypeHotspot {
		// wifi
		if nw.netType != NetworkTypeHotspot {
			nw.lastTried = now
			n.netState.SetLastSSID(ifName, ssid)
		}
		netDev = n.netState.WifiDevice(ifName)
	} else {
		// wired
		nw.lastTried = now
		netDev = n.netState.EthDevice(ifName)
	}

	if netDev == nil {
		return errw.Errorf("cannot activate connection due to missing interface: %s", ifName)
	}

	activeConnection, err := n.nm.ActivateConnection(nw.conn, netDev, nil)
	if err != nil {
		nw.lastError = err
		return errw.Wrapf(err, "activating connection: %s", n.netState.GenNetKey(ifName, ssid))
	}

	if err := n.waitForConnect(ctx, netDev); err != nil {
		nw.lastError = err
		nw.connected = false
		return err
	}

	nw.connected = true
	nw.lastConnected = now
	nw.lastError = nil
	n.netState.SetActiveConn(ifName, activeConnection)

	n.logger.Infof("Successfully activated connection: %s", n.netState.GenNetKey(ifName, ssid))

	if nw.netType != NetworkTypeHotspot {
		n.netState.SetActiveSSID(ifName, ssid)
		if ifName == n.Config().HotspotInterface && (n.Config().TurnOnHotspotIfWifiHasNoInternet || n.netState.PrimarySSID(ifName) == ssid) {
			n.connState.setConnected(true)
		}
		return n.checkOnline(true)
	}

	return nil
}

func (n *Networking) DeactivateConnection(ifName, ssid string) error {
	if n.connState.getProvisioning() && ifName == n.Config().HotspotInterface {
		return errors.New("cannot deactivate another connection while in provisioning mode")
	}

	n.opMu.Lock()
	defer n.opMu.Unlock()
	return n.deactivateConnection(ifName, ssid)
}

func (n *Networking) deactivateConnection(ifName, ssid string) error {
	activeConn := n.netState.ActiveConn(ifName)
	if activeConn == nil {
		return errw.Wrapf(ErrNoActiveConnectionFound, "interface: %s", ifName)
	}

	nw := n.netState.LockingNetwork(ifName, ssid)
	nw.mu.Lock()
	defer nw.mu.Unlock()

	n.logger.Infof("Deactivating connection: %s", n.netState.GenNetKey(ifName, ssid))

	if err := n.nm.DeactivateConnection(activeConn); err != nil {
		nw.lastError = err
		return errw.Wrapf(err, "deactivating connection: %s", n.netState.GenNetKey(ifName, ssid))
	}

	n.logger.Infof("Successfully deactivated connection: %s", n.netState.GenNetKey(ifName, ssid))

	if ifName == n.Config().HotspotInterface {
		n.connState.setConnected(false)
	}

	nw.connected = false
	nw.lastConnected = time.Now()
	nw.lastError = nil
	n.netState.SetActiveSSID(ifName, "")
	return nil
}

func (n *Networking) waitForConnect(ctx context.Context, device gnm.Device) error {
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
			n.logger.Debugf("%s->%s (%s)", update.OldState, update.NewState, update.Reason)
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
			if !n.mainLoopHealth.Sleep(timeoutCtx, time.Second) {
				return errw.Wrap(ctx.Err(), "waiting for network activation")
			}
		}
	}
}

func (n *Networking) AddOrUpdateConnection(cfg utils.NetworkDefinition) (bool, error) {
	n.opMu.Lock()
	defer n.opMu.Unlock()
	return n.addOrUpdateConnection(cfg)
}

// returns true if network was new (added) and not updated.
func (n *Networking) addOrUpdateConnection(cfg utils.NetworkDefinition) (bool, error) {
	var changesMade bool

	if cfg.Type != NetworkTypeWifi && cfg.Type != NetworkTypeHotspot && cfg.Type != NetworkTypeWired {
		return changesMade, errw.Errorf("unspported network type %s, only %s and %s currently supported",
			cfg.Type, NetworkTypeWifi, NetworkTypeWired)
	}

	if cfg.Type != NetworkTypeWired && cfg.PSK != "" && len(cfg.PSK) < 8 {
		return changesMade, errors.New("wifi passwords must be at least 8 characters long, or completely empty (for unsecured networks)")
	}

	netKey := n.netState.GenNetKey(cfg.Interface, cfg.SSID)
	nw := n.netState.LockingNetwork(cfg.Interface, cfg.SSID)
	nw.mu.Lock()
	nw.lastTried = time.Time{}
	nw.priority = cfg.Priority
	nw.mu.Unlock()

	var settings gnm.ConnectionSettings
	var err error
	if cfg.Type == NetworkTypeHotspot {
		if cfg.SSID != n.Config().HotspotSSID {
			return changesMade, errw.Errorf("only the builtin provisioning hotspot may use the %s network type", NetworkTypeHotspot)
		}
		nw.mu.Lock()
		nw.isHotspot = true
		nw.mu.Unlock()
		settings = generateHotspotSettings(
			n.Config().HotspotPrefix,
			n.Config().HotspotSSID,
			n.Config().HotspotPassword,
			n.Config().HotspotInterface,
		)
	} else {
		id := n.Config().Manufacturer + "-" + netKey
		settings, err = generateNetworkSettings(id, cfg)
		n.logger.Debugf("Network settings: %#v", settings)
		if err != nil {
			return changesMade, errw.Errorf("error generating network settings for %s: %v", id, err)
		}
	}

	if cfg.Type == NetworkTypeWifi && !n.Config().TurnOnHotspotIfWifiHasNoInternet && cfg.Priority == 999 {
		// lower the priority of any existing/prior primary network
		n.lowerMaxNetPriorities(cfg.SSID)
		n.netState.SetPrimarySSID(n.Config().HotspotInterface, cfg.SSID)
	}

	n.logger.Infof("Adding/updating settings for network %s", netKey)

	var oldSettings gnm.ConnectionSettings
	nw.mu.Lock()
	defer nw.mu.Unlock()
	if nw.conn != nil {
		oldSettings, err = nw.conn.GetSettings()
		if err != nil {
			nw.conn = nil
			n.logger.Warn(errw.Wrapf(err, "getting current settings for %s, attempting to add as new network", netKey))
		} else if err := nw.conn.Update(settings); err != nil {
			// we may be out of sync with NetworkManager
			nw.conn = nil
			n.logger.Warn(errw.Wrapf(err, "updating settings for %s, attempting to add as new network", netKey))
		}
	}

	if nw.conn == nil {
		changesMade = true
		newConn, err := n.settings.AddConnection(settings)
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

	changesMade = changesMade || !reflect.DeepEqual(oldSettings, newSettings)

	return changesMade, nil
}

// this doesn't error as it's not technically fatal if it fails.
func (n *Networking) lowerMaxNetPriorities(skip string) {
	for _, nw := range n.netState.LockingNetworks() {
		netKey := n.netState.GenNetKey(nw.interfaceName, nw.ssid)
		if netKey == skip || netKey == n.netState.GenNetKey(n.Config().HotspotInterface, n.Config().HotspotSSID) || nw.priority < 999 ||
			nw.netType != NetworkTypeWifi || (nw.interfaceName != "" && nw.interfaceName != n.Config().HotspotInterface) {
			continue
		}

		nw.mu.Lock()
		if nw.conn != nil {
			settings, err := nw.conn.GetSettings()
			if err != nil {
				nw.conn = nil
				n.logger.Warnf("error (%s) encountered when getting settings for %s", err, nw.ssid)
				nw.mu.Unlock()
				continue
			}

			if getPriorityFromSettings(settings) == 999 {
				settings["connection"]["autoconnect-priority"] = 998

				// deprecated fields that are read-only, so can't try to set them
				delete(settings["ipv6"], "addresses")
				delete(settings["ipv6"], "routes")

				n.logger.Debugf("Lowering priority of %s to 998", netKey)

				if err := nw.conn.Update(settings); err != nil {
					nw.conn = nil
					n.logger.Warnf("error (%s) encountered when updating settings for %s", err, netKey)
				}
			}
			nw.priority = getPriorityFromSettings(settings)
		}
		nw.mu.Unlock()
	}
}

func (n *Networking) checkConfigured() {
	_, err := os.ReadFile(utils.AppConfigFilePath)
	n.connState.setConfigured(err == nil)
}

// tryCandidates returns true if a network activated.
func (n *Networking) tryCandidates(ctx context.Context) bool {
	for _, ssid := range n.getCandidates(n.Config().HotspotInterface) {
		err := n.ActivateConnection(ctx, n.Config().HotspotInterface, ssid)
		if err != nil {
			n.logger.Error(err)
			continue
		}

		// in single mode we just need a connection
		if !n.Config().TurnOnHotspotIfWifiHasNoInternet {
			return true
		}

		// in roaming mode we need full internet
		if n.connState.getOnline() {
			return true
		}

		n.logger.Warnf("SSID %s connected, but does not provide internet access.", ssid)
	}
	return false
}

func (n *Networking) getCandidates(ifName string) []string {
	var candidates []network
	for _, nw := range n.netState.Networks() {
		if nw.netType != NetworkTypeWifi || (nw.interfaceName != "" && nw.interfaceName != ifName) {
			continue
		}
		// ssid seen within the past minute
		visible := nw.lastSeen.After(time.Now().Add(VisibleNetworkTimeout * -1))

		// ssid has a connection known to network manager
		configured := nw.conn != nil

		// firstSeen/lastTried are reset if a network disappears for more than a minute, so retry if it comes back (or 10 mins)
		recentlyTried := nw.lastTried.After(nw.firstSeen) &&
			nw.lastTried.After(time.Now().Add(time.Duration(n.Config().RetryConnectionTimeoutMinutes)*-1))

		if !nw.isHotspot && visible && configured && !recentlyTried {
			candidates = append(candidates, nw)
		}
	}

	if !n.Config().TurnOnHotspotIfWifiHasNoInternet {
		for _, nw := range candidates {
			if nw.ssid == n.netState.PrimarySSID(n.Config().HotspotInterface) {
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

func (n *Networking) backgroundLoop(ctx context.Context, scanChan chan<- bool) {
	defer n.monitorWorkers.Done()
	n.logger.Info("Background state monitors started")
	defer n.logger.Info("Background state monitors stopped")
	for {
		if !n.bgLoopHealth.Sleep(ctx, scanLoopDelay) {
			return
		}

		n.checkConfigured()
		if err := n.networkScan(ctx); err != nil {
			n.logger.Error(err)
		}
		if err := n.updateKnownConnections(ctx); err != nil {
			n.logger.Error(err)
		}
		if err := n.checkConnections(); err != nil {
			n.logger.Error(err)
		}
		if err := n.checkOnline(false); err != nil {
			n.logger.Error(err)
		}
		scanChan <- true
	}
}

func (n *Networking) mainLoop(ctx context.Context) {
	defer n.monitorWorkers.Done()

	scanChan := make(chan bool, 16)
	inputChan := make(chan userInput, 1)

	n.monitorWorkers.Add(1)
	go n.backgroundLoop(ctx, scanChan)

	for {
		var userInputReceived bool

		select {
		case <-ctx.Done():
			return
		case userInput := <-inputChan:
			if userInput.RawConfig != "" || userInput.PartID != "" {
				n.logger.Info("Device config received")
				err := WriteDeviceConfig(utils.AppConfigFilePath, userInput)
				if err != nil {
					n.errors.Add(err)
					n.logger.Error(err)
					continue
				}
				n.checkConfigured()
				userInputReceived = true
			}

			var newSSID string
			var changesMade bool
			if userInput.SSID != "" {
				n.logger.Infof("Wifi settings received for %s", userInput.SSID)
				priority := int32(999)
				if n.Config().TurnOnHotspotIfWifiHasNoInternet {
					priority = 100
				}
				cfg := utils.NetworkDefinition{
					Type:     NetworkTypeWifi,
					SSID:     userInput.SSID,
					PSK:      userInput.PSK,
					Priority: priority,
				}
				var err error
				changesMade, err = n.AddOrUpdateConnection(cfg)
				if err != nil {
					n.errors.Add(err)
					n.logger.Error(err)
					continue
				}
				userInputReceived = true
				newSSID = cfg.SSID
			}

			// wait 3 seconds so responses can be sent to/seen by user
			if !n.mainLoopHealth.Sleep(ctx, time.Second*3) {
				return
			}
			if changesMade {
				err := n.StopProvisioning()
				if err != nil {
					n.logger.Error(err)
					continue
				}
				err = n.ActivateConnection(ctx, n.Config().HotspotInterface, newSSID)
				if err != nil {
					n.logger.Error(err)
					continue
				}
				if !n.connState.getOnline() {
					err := n.deactivateConnection(n.Config().HotspotInterface, newSSID)
					if err != nil {
						n.logger.Error(err)
					}
					nw := n.netState.LockingNetwork("", newSSID)
					nw.mu.Lock()
					if nw.conn != nil {
						// add a user warning for the portal
						err = errw.New("Network has no internet. Resubmit to use anyway.")
						nw.lastError = err
						n.logger.Warn(err)
					} else {
						n.logger.Error("cannot find %s in network list", n.netState.GenNetKey("", newSSID))
					}
					nw.mu.Unlock()
					err = n.StartProvisioning(ctx, inputChan)
					if err != nil {
						n.logger.Error(err)
					}
				}
			}
		case <-scanChan:
		case <-time.After((scanLoopDelay + scanTimeout) * 2):
			// safety fallback if something hangs
			n.logger.Warnf("wifi scan has not completed for %s", (scanLoopDelay+scanTimeout)*2)
		}

		n.mainLoopHealth.MarkGood()

		isOnline := n.connState.getOnline()
		lastOnline := n.connState.getLastOnline()
		isConnected := n.connState.getConnected()
		lastConnected := n.connState.getLastConnected()
		hasConnectivity := isConnected || isOnline
		lastConnectivity := lastConnected
		if lastOnline.After(lastConnected) {
			lastConnectivity = lastOnline
		}
		isConfigured := n.connState.getConfigured()
		allGood := isConfigured && (isConnected || isOnline)
		if n.Config().TurnOnHotspotIfWifiHasNoInternet {
			allGood = isOnline && isConfigured
			hasConnectivity = isOnline
			lastConnectivity = lastOnline
		}
		pMode := n.connState.getProvisioning()
		pModeChange := n.connState.getProvisioningChange()
		now := time.Now()

		n.logger.Debugf("wifi: %t (%s), internet: %t, config present: %t",
			isConnected,
			n.netState.GenNetKey(n.Config().HotspotInterface, n.netState.ActiveSSID(n.Config().HotspotInterface)),
			isOnline,
			isConfigured,
		)

		if pMode {
			// complex logic, so wasting some variables for readability

			// portal interaction time is updated when a user loads a page or makes a grpc request
			inactivePortal := n.connState.getLastInteraction().Before(now.Add(time.Duration(n.Config().UserIdleMinutes)*-1)) || userInputReceived

			// exit/retry to test networks only if there's no recent user interaction AND configuration is present
			haveCandidates := len(n.getCandidates(n.Config().HotspotInterface)) > 0 && inactivePortal && isConfigured

			// exit/retry every FallbackTimeout (10 minute default), unless user is active
			fallbackHit := pModeChange.Before(now.Add(time.Duration(n.Config().RetryConnectionTimeoutMinutes)*-1)) && inactivePortal

			shouldReboot := n.Config().DeviceRebootAfterOfflineMinutes > 0 &&
				lastConnectivity.Before(now.Add(time.Duration(n.Config().DeviceRebootAfterOfflineMinutes)*-1))

			shouldExit := allGood || haveCandidates || fallbackHit || shouldReboot

			n.logger.Debugf("inactive portal: %t, have candidates: %t, fallback timeout: %t", inactivePortal, haveCandidates, fallbackHit)

			if shouldExit {
				if err := n.StopProvisioning(); err != nil {
					n.logger.Error(err)
				} else {
					pMode = n.connState.getProvisioning()
					pModeChange = n.connState.getProvisioningChange()
				}
			}

			if shouldReboot && n.doReboot(ctx) {
				return
			}
		}

		if allGood || pMode {
			continue
		}

		// not in provisioning mode
		if !hasConnectivity {
			if n.tryCandidates(ctx) {
				hasConnectivity = n.connState.getConnected() || n.connState.getOnline()
				// if we're roaming or this network was JUST added, it must have internet
				if n.Config().TurnOnHotspotIfWifiHasNoInternet {
					hasConnectivity = n.connState.getOnline()
				}
				if hasConnectivity {
					continue
				}
				lastConnectivity = n.connState.getLastConnected()
				if n.Config().TurnOnHotspotIfWifiHasNoInternet {
					lastConnectivity = n.connState.getLastOnline()
				}
			}
		}

		shouldReboot := n.Config().DeviceRebootAfterOfflineMinutes > 0 &&
			lastConnectivity.Before(now.Add(time.Duration(n.Config().DeviceRebootAfterOfflineMinutes)*-1))

		if shouldReboot && n.doReboot(ctx) {
			return
		}

		hitOfflineTimeout := lastConnectivity.Before(now.Add(time.Duration(n.Config().OfflineBeforeStartingHotspotMinutes)*-1)) &&
			pModeChange.Before(now.Add(time.Duration(n.Config().OfflineBeforeStartingHotspotMinutes)*-1))
		// not in provisioning mode, so start it if not configured (/etc/viam.json)
		// OR as long as we've been offline AND out of provisioning mode for at least OfflineTimeout (2 minute default)
		if !isConfigured || hitOfflineTimeout {
			if err := n.StartProvisioning(ctx, inputChan); err != nil {
				n.logger.Error(err)
			}
		}
	}
}

func (n *Networking) doReboot(ctx context.Context) bool {
	n.logger.Infof("device has been offline for more than %s, rebooting", time.Duration(n.Config().DeviceRebootAfterOfflineMinutes))
	cmd := exec.Command("systemctl", "reboot")
	output, err := cmd.CombinedOutput()
	if err != nil {
		n.logger.Error(errw.Wrapf(err, "running 'systemctl reboot' %s", output))
	}
	if !n.mainLoopHealth.Sleep(ctx, time.Minute*5) {
		return true
	}
	n.logger.Errorf("failed to reboot after %s time", time.Minute*5)
	return false
}
