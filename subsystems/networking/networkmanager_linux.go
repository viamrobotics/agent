package networking

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"time"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/utils/rpc"
)

const (
	socksTestURL      = "http://packages.viam.com/check_network_status.txt"
	socksTestContents = "NetworkManager is online"

	socksTestIntervalShort = time.Second * 15
	socksTestIntervalLong  = time.Minute * 2
)

func (n *Networking) warnIfMultiplePrimaryNetworks() {
	if n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() {
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

func (n *Networking) checkOnline(ctx context.Context, force bool) error {
	if force {
		if err := n.nm.CheckConnectivity(); err != nil {
			n.logger.Warn(err)
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
		n.logger.Debug("unable to determine network state")
	default:
	}

	if !online && os.Getenv("SOCKS_PROXY") != "" {
		if force ||
			(n.connState.getOnline() && time.Now().After(n.connState.getLastTested().Add(socksTestIntervalLong))) ||
			(!n.connState.getOnline() && time.Now().After(n.connState.getLastTested().Add(socksTestIntervalShort))) {
			var errSocks error
			online, errSocks = n.CheckInternetViaSOCKS(ctx)
			n.connState.setLastTested()
			if errSocks != nil {
				n.logger.Debug(errw.Wrap(errSocks, "testing connectivity via possible SOCKS proxy"))
			}
		} else {
			// if it's not time for a new test, we want to avoid mistakenly recording "offline"
			return nil
		}
	}

	n.connState.setOnline(online)
	return nil
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
			n.logger.Warn(errw.Wrapf(err, "getting state of active connection: %s", n.netState.GenNetKey(ifName, ssid)))
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
		if n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() && state == gnm.NmActiveConnectionStateActivated && ssid != n.Config().HotspotSSID {
			connected = true
		}

		// in normal (single) mode, we need to be connected to the primary (highest priority) network
		if !n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() && state == gnm.NmActiveConnectionStateActivated &&
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
	if ctx.Err() != nil {
		return ctx.Err()
	}

	n.logger.Info("Starting provisioning mode.")

	n.portalData.resetInputData(inputChan)
	hotspotErr := n.startProvisioningHotspot(ctx)
	if hotspotErr != nil {
		n.logger.Errorw("failed to start hotspot provisioning", "error", hotspotErr)
	}
	bluetoothErr := n.startProvisioningBluetooth(ctx)
	if bluetoothErr != nil {
		n.logger.Errorw("failed to start bluetooth provisioning", "error", bluetoothErr)
	}

	// Do not return an error if at least one provisioning method succeeds.
	n.connState.setProvisioning(hotspotErr == nil || bluetoothErr == nil)
	if hotspotErr == nil || bluetoothErr == nil {
		return nil
	}
	return errors.Join(hotspotErr, bluetoothErr)
}

// startProvisioningHotspot should only be called by 'StartProvisioning' (to ensure opMutex is acquired).
func (n *Networking) startProvisioningHotspot(ctx context.Context) error {
	if n.Config().DisableWifiProvisioning.Get() {
		return nil
	}

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
	if err := n.startPortal(PortalBindAddr); err != nil {
		err = errors.Join(err, n.deactivateConnection(n.Config().HotspotInterface, n.Config().HotspotSSID))
		return errw.Wrap(err, "starting web/grpc portal")
	}
	n.logger.Info("Hotspot provisioning set up successfully.")
	return nil
}

func (n *Networking) StopProvisioning() error {
	n.opMu.Lock()
	defer n.opMu.Unlock()
	return n.stopProvisioning()
}

func (n *Networking) stopProvisioning() error {
	n.logger.Info("Stopping provisioning mode.")
	n.errors.Clear()
	err := errors.Join(
		n.stopProvisioningHotspot(),
		n.stopProvisioningBluetooth(),
	)
	if err != nil {
		return err
	}
	n.connState.setProvisioning(false)
	return nil
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

func (n *Networking) ActivateConnection(ctx context.Context, ifName, ssid string) error {
	if n.connState.getProvisioning() && ifName == n.Config().HotspotInterface {
		return errors.New("cannot activate another connection while in provisioning mode")
	}
	n.opMu.Lock()
	defer n.opMu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
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
	switch nw.netType {
	case NetworkTypeWifi:
		n.netState.SetLastSSID(ifName, ssid)
		netDev = n.netState.WifiDevice(ifName)
	case NetworkTypeHotspot:
		netDev = n.netState.WifiDevice(ifName)
	case NetworkTypeBluetooth:
		netDev = n.netState.BTDevice(ifName)
	case NetworkTypeWired:
		fallthrough
	default:
		// wired
		netDev = n.netState.EthDevice(ifName)
	}

	if netDev == nil {
		// we're trying to activate something on a missing adapter, perhaps it was hotplugged, so re-init devices for future retries
		n.dataMu.Lock()
		if err := n.initDevices(); err != nil {
			n.logger.Warn(err)
		}
		n.dataMu.Unlock()
		return errw.Errorf("cannot activate connection due to missing interface: %s", ifName)
	}

	nw.lastTried = now
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
		if ifName == n.Config().HotspotInterface &&
			(n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() || n.netState.PrimarySSID(ifName) == ssid) {
			n.connState.setConnected(true)
		}
		return n.checkOnline(ctx, true)
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
		return changesMade, errw.Errorf("unspported network type %s, only %s, and %s currently supported",
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
		if err != nil {
			return changesMade, errw.Errorf("error generating network settings for %s: %v", id, err)
		}
	}

	if cfg.Type == NetworkTypeWifi && !n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() && cfg.Priority == 999 {
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

func (n *Networking) tryBluetoothTether(ctx context.Context) bool {
	if !n.bluetoothEnabled() {
		return false
	}

	for _, nw := range n.netState.Networks() {
		if nw.netType != NetworkTypeBluetooth || nw.connected {
			continue
		}

		if !time.Now().After(nw.lastTried.Add(VisibleNetworkTimeout)) {
			continue
		}
		if err := n.ActivateConnection(ctx, nw.interfaceName, nw.ssid); err != nil {
			n.logger.Info(errw.Wrap(err, "activating bluetooth tether"))
			continue
		}

		// in single mode we just need a connection
		if !n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() {
			return true
		}

		// in roaming mode we need full internet
		if n.connState.getOnline() {
			return true
		}
	}
	return false
}

// tryCandidates returns true if a network activated.
func (n *Networking) tryCandidates(ctx context.Context) bool {
	for _, ssid := range n.getCandidates(n.Config().HotspotInterface) {
		err := n.ActivateConnection(ctx, n.Config().HotspotInterface, ssid)
		if err != nil {
			n.logger.Warn(err)
			continue
		}

		// in single mode we just need a connection
		if !n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() {
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

	if !n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() {
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
	defer utils.Recover(n.logger, nil)
	defer n.monitorWorkers.Done()
	n.logger.Info("Background state monitors started")
	defer n.logger.Info("Background state monitors stopped")
	for {
		if !n.bgLoopHealth.Sleep(ctx, scanLoopDelay) {
			return
		}

		n.checkConfigured()
		if err := n.networkScan(ctx); err != nil {
			n.logger.Warn(err)
		}
		if err := n.updateKnownConnections(ctx); err != nil {
			n.logger.Warn(err)
		}
		if err := n.checkConnections(); err != nil {
			n.logger.Warn(err)
		}
		if err := n.checkOnline(ctx, false); err != nil {
			n.logger.Warn(err)
		}
		select {
		case scanChan <- true:
		case <-ctx.Done():
			return
		default:
		}
	}
}

// Process user input (viam.json and/or Wifi settings) and return true if everything succeeded without error, false otherwise.
func (n *Networking) processUserInput(userInput userInput) bool {
	if userInput.RawConfig != "" || userInput.PartID != "" {
		n.logger.Info("Device config received")
		err := WriteDeviceConfig(utils.AppConfigFilePath, userInput)
		if err != nil {
			n.errors.Add(err)
			n.logger.Warn(err)
			return false
		}
		n.checkConfigured()
	}

	if userInput.SSID != "" {
		n.logger.Infof("Wifi settings received for %s", userInput.SSID)
		priority := int32(999)
		if n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() {
			priority = 100
		}
		cfg := utils.NetworkDefinition{
			Type:     NetworkTypeWifi,
			SSID:     userInput.SSID,
			PSK:      userInput.PSK,
			Priority: priority,
		}
		var err error
		_, err = n.AddOrUpdateConnection(cfg)
		if err != nil {
			n.errors.Add(err)
			n.logger.Warn(err)
			return false
		}
	}
	return true
}

func (n *Networking) mainLoop(ctx context.Context) {
	defer utils.Recover(n.logger, nil)
	defer n.monitorWorkers.Done()

	scanChan := make(chan bool, 16)
	inputChan := make(chan userInput, 10)

	n.monitorWorkers.Add(1)
	go n.backgroundLoop(ctx, scanChan)
	for {
		var userInputReceived bool
		var userInputSSID string

		// select on inputChan twice: it's unlikely but possible scanChan is always ready and gets selected.
		select {
		case <-ctx.Done():
			return
		case userInput := <-inputChan:
			userInputReceived = true
			userInputSSID = userInput.SSID
			if !n.processUserInput(userInput) {
				continue
			}
		default:
			select {
			case <-ctx.Done():
				return
			case userInput := <-inputChan:
				userInputReceived = true
				userInputSSID = userInput.SSID
				if !n.processUserInput(userInput) {
					continue
				}
			case <-scanChan:
				// ticks after every completed scan/update cycle (minimum of scanLoopDelay), see backgroundLoop()
			case <-time.After((scanLoopDelay + scanTimeout) * 2):
				// safety fallback if something hangs
				n.logger.Warnf("wifi scan has not completed for %s", (scanLoopDelay+scanTimeout)*2)
			}
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
		if n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() {
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
			if n.bluetoothEnabled() {
				// Update bluetooth read-only characteristics
				if err := n.btChar.updateStatus(isConfigured, hasConnectivity); err != nil {
					n.logger.Warn("could not update BT status characteristic")
				}
				if err := n.btChar.updateNetworks(n.getVisibleNetworks()); err != nil {
					n.logger.Warn("could not update BT networks characteristic")
				}
				if err := n.btChar.updateErrors(n.errListAsStrings()); err != nil {
					n.logger.Warn("could not update BT errors characteristic")
				}
			}

			if !hasConnectivity && n.tryBluetoothTether(ctx) {
				continue
			}

			// complex logic, so wasting some variables for readability

			// portal interaction time is updated when a user loads a page or makes a grpc request
			inactivePortal := now.After(n.connState.getLastInteraction().Add(time.Duration(n.Config().UserIdleMinutes)))

			// exit/retry to test networks only if there's no recent user interaction AND configuration is present
			haveCandidates := len(n.getCandidates(n.Config().HotspotInterface)) > 0 && inactivePortal && isConfigured

			// exit/retry every FallbackTimeout (10 minute default), unless user is active
			fallbackRemaining := pModeChange.Add(time.Duration(n.Config().RetryConnectionTimeoutMinutes)).Sub(now)
			fallbackHit := fallbackRemaining <= 0 && inactivePortal

			shouldRebootSystem := n.Config().DeviceRebootAfterOfflineMinutes > 0 &&
				lastConnectivity.Before(now.Add(time.Duration(n.Config().DeviceRebootAfterOfflineMinutes)*-1))

			shouldExitPMode := allGood || haveCandidates || fallbackHit || shouldRebootSystem || userInputReceived

			n.logger.Debugf("inactive portal: %t, have candidates: %t, fallback timeout: %t (%s remaining)",
				inactivePortal, haveCandidates, fallbackHit, fallbackRemaining)

			if shouldExitPMode {
				if userInputReceived {
					// We could get to this point before the user receives our response (poor UX, but likely not critical)
					// E.g. try to avoid "Not connected" web portal screen.
					n.mainLoopHealth.Sleep(ctx, 3*time.Second)
				}
				if err := n.StopProvisioning(); err != nil {
					n.logger.Warn(err)
				} else {
					pMode = n.connState.getProvisioning()
					pModeChange = n.connState.getProvisioningChange()
				}
			}

			if shouldRebootSystem && n.doReboot(ctx) {
				return
			}
		}

		if allGood || pMode {
			continue
		}

		// not in provisioning mode
		var forceStartPMode bool
		if !hasConnectivity {
			connectOk := n.tryCandidates(ctx)
			if connectOk || n.tryBluetoothTether(ctx) {
				hasConnectivity = n.connState.getConnected() || n.connState.getOnline()
				// if we're roaming or this network was JUST added, it must have internet
				if n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() {
					hasConnectivity = n.connState.getOnline()
				}
				if hasConnectivity {
					continue
				}
				lastConnectivity = n.connState.getLastConnected()
				if n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() {
					lastConnectivity = n.connState.getLastOnline()
				}
			} else if !connectOk && userInputReceived && userInputSSID != "" {
				// Special case: received AP credentials and exited provisioning to try it, but it's unsuccessful.
				// Most commonly a wrong password. In roaming mode, we can get here too if we're connected but offline.
				// Note: the network tests of `allGood` are updated in the background loop, so we may not get here
				// in the same iteration as when user input was actually received, but rather a future iteration -
				// `userInputReceived` and `userInputSSID` will have already been wiped.

				// LockingNetwork is called with these same args in portalSave and tryCandidates; so should exist.
				nw := n.netState.Network(n.Config().HotspotInterface, userInputSSID)

				// In normal mode, tryCandidates will only try a single AP, the PrimarySSID (set in the latest processUserInput).
				// In roaming mode, all configured connections known to NetworkManager will be tried.
				// In either case, if we're still offline and the most recent user-provided credentials are bad,
				// assume it's a mistake and go back to pMode. The lastError will be visible to the user.
				if nw.lastError != nil && errors.Is(nw.lastError, ErrBadPassword) {
					n.logger.Warnw("Received incorrect password for AP. Reactivating provisioning mode.",
						"ssid", userInputSSID, "err", nw.lastError)
					forceStartPMode = true
				}
			}
		}

		shouldRebootSystem := n.Config().DeviceRebootAfterOfflineMinutes > 0 &&
			lastConnectivity.Before(now.Add(time.Duration(n.Config().DeviceRebootAfterOfflineMinutes)*-1))

		if shouldRebootSystem && n.doReboot(ctx) {
			return
		}

		hitOfflineTimeout := now.After(lastConnectivity.Add(time.Duration(n.Config().OfflineBeforeStartingHotspotMinutes))) &&
			now.After(pModeChange.Add(time.Duration(n.Config().OfflineBeforeStartingHotspotMinutes)))
		// not in provisioning mode, so start it if not configured (/etc/viam.json)
		// OR as long as we've been offline AND out of provisioning mode for at least OfflineTimeout (2 minute default)
		if !isConfigured || hitOfflineTimeout || forceStartPMode {
			if err := n.StartProvisioning(ctx, inputChan); err != nil {
				n.logger.Warn(err)
			}
		}
	}
}

func (n *Networking) doReboot(ctx context.Context) bool {
	n.logger.Infof("device has been offline for more than %s, rebooting", time.Duration(n.Config().DeviceRebootAfterOfflineMinutes))
	cmd := exec.Command("systemctl", "reboot")
	output, err := cmd.CombinedOutput()
	if err != nil {
		n.logger.Warn(errw.Wrapf(err, "running 'systemctl reboot' %s", output))
	}
	if !n.mainLoopHealth.Sleep(ctx, time.Minute*5) {
		return true
	}
	n.logger.Errorf("failed to reboot after %s time", time.Minute*5)
	return false
}

func (n *Networking) CheckInternetViaSOCKS(ctx context.Context) (bool, error) {
	n.logger.Debug("checking internet via possible SOCKS proxy")
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*15)
	defer cancel()
	req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, socksTestURL, nil)
	if err != nil {
		return false, errw.Wrap(err, "request setup")
	}

	// Use SOCKS proxy from environment as gRPC proxy dialer.
	httpClient := &http.Client{Transport: &http.Transport{
		DialContext: rpc.SocksProxyFallbackDialContext(socksTestURL, n.logger),
	}}

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, errw.Wrap(err, "connection test")
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			n.logger.Warn(errw.Wrap(err, "closing connection test request"))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false, errw.Errorf("got response '%s' while checking %s", resp.Status, socksTestURL)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, errw.Wrap(err, "reading document body")
	}

	online := bytes.Contains(data, []byte(socksTestContents))

	n.logger.Debugf("connection test to %s and possibly via SOCKS result: %t", socksTestURL, online)

	return online, nil
}
