package networking

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	gnm "github.com/viamrobotics/gonetworkmanager/v2"
	"go.viam.com/utils/rpc"
)

const (
	manualCheckURL          = "http://packages.viam.com/check_network_status.txt"
	manualCheckTestContents = "NetworkManager is online"

	// different check intervals when behind and not behind socks proxy.
	nonSocksManualCheckInterval   = time.Minute * 2
	socksManualCheckIntervalShort = time.Second * 15
	socksManualCheckIntervalLong  = time.Minute * 2
)

func (n *Subsystem) warnIfMultiplePrimaryNetworks() {
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

func (n *Subsystem) getVisibleNetworks() []NetworkInfo {
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

func (n *Subsystem) getLastNetworkTried() NetworkInfo {
	lastNetwork := n.netState.LastNetwork(NetworkTypeWifi, n.Config().HotspotInterface)
	return lastNetwork.getInfo()
}

func (n *Subsystem) checkOnline(ctx context.Context, force bool) error {
	networkStatusLogger := n.logger.Sublogger("network_status")
	if force {
		// note: this call blocks; may take 30s+
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
		networkStatusLogger.Debugw("NetworkManager reports full connectivity (global).", "state", state)
	case gnm.NmStateConnectedLocal:
		// do nothing, but may need these two in the future
		networkStatusLogger.Infow("NetworkManager reports limited connectivity (local-only). Check your internet connection.", "state", state)
	case gnm.NmStateConnectedSite:
		networkStatusLogger.Infow("NetworkManager reports limited connectivity (site-only). Check your internet connection.", "state", state)
	case gnm.NmStateUnknown:
		networkStatusLogger.Infow("unable to determine network state", "state", state)
	default:
	}

	// if NM reports not online, see if we can download a test file as a backup.
	if !online {
		behindSocksProxy := os.Getenv("SOCKS_PROXY") != ""
		// We perform a manual check when *NetworkManager reports we're offline* and:
		// 1) force
		// 2) not behind socks proxy and we're
		//    - currently offline && last manual check >= 2 mins ago. either 1) we're actually offline 2) NetworkManager is wrong (uncommon)
		// 3) behind socks proxy and we're:
		//    - currently offline && last manual check >= 15 secs ago (initial check)
		//    - currently online && last manual check >= 2 mins ago (verify still online)
		// otherwise, if none of these, we exit early without updating connState.
		if force ||
			(!behindSocksProxy &&
				!n.connState.getOnline() && time.Now().After(n.connState.getManualCheckLastTested().Add(nonSocksManualCheckInterval))) ||
			(behindSocksProxy &&
				!n.connState.getOnline() && time.Now().After(n.connState.getManualCheckLastTested().Add(socksManualCheckIntervalShort))) ||
			(behindSocksProxy &&
				n.connState.getOnline() && time.Now().After(n.connState.getManualCheckLastTested().Add(socksManualCheckIntervalLong))) {
			networkStatusLogger.Infow("NetworkManager reports not online. Trying manual check.", "state", state)
			var errManualCheck error
			online, errManualCheck = n.CheckInternetManual(ctx, behindSocksProxy)
			n.connState.setManualCheckLastTested()
			if errManualCheck != nil {
				networkStatusLogger.Info(errw.Wrap(errManualCheck, "testing connectivity via file download"))
			}
			if online {
				networkStatusLogger.Infof(
					"test file download successful. overriding NetworkManager's reported offline (current state: %v) and marking Agent as online.", state)
			}
		} else {
			// if it's not time for a new test, we want to avoid mistakenly recording "offline"
			networkStatusLogger.Infow("NetworkManager reports not online. Not performing manual check.",
				"last_manual_check", n.connState.getManualCheckLastTested().String(), "state", state)
			return nil
		}
	}

	n.connState.setOnline(online)
	return nil
}

// isObjectNotExistError checks if the error indicates that an object no longer exists at the given path.
func isObjectNotExistError(err error) bool {
	if err == nil {
		return false
	}

	// Fallback to string matching as dbus doesn't return "true" Go-like enumerated errors, and has it's own string-based error type.
	return strings.Contains(err.Error(), "Object does not exist at path")
}

func (n *Subsystem) checkConnections() {
	var connected bool
	defer func() {
		n.connState.setConnected(connected)
	}()

	for ifName, dev := range n.netState.Devices() {
		activeConnection, err := dev.GetPropertyActiveConnection()
		if err != nil {
			if isObjectNotExistError(err) {
				n.logger.Warnf("device %s no longer exists, removing from network state: %v", ifName, err)
				n.netState.RemoveDevice(ifName)
			} else {
				n.logger.Warnf("failed to get active connection for device %s: %v", ifName, err)
			}
			continue
		}
		if activeConnection == nil {
			n.netState.SetActiveConn(ifName, nil)
			n.netState.SetActiveSSID(ifName, "")
			continue
		}

		connection, err := activeConnection.GetPropertyConnection()
		if err != nil {
			if isObjectNotExistError(err) {
				n.logger.Warnf("device %s no longer exists, removing from network state: %v", ifName, err)
				n.netState.RemoveDevice(ifName)
			} else {
				n.logger.Warnf("failed to get connection property for device %s: %v", ifName, err)
			}
			continue
		}

		settings, err := connection.GetSettings()
		if err != nil {
			if isObjectNotExistError(err) {
				n.logger.Warnf("device %s no longer exists, removing from network state: %v", ifName, err)
				n.netState.RemoveDevice(ifName)
			} else {
				n.logger.Warnf("failed to get connection settings for device %s: %v", ifName, err)
			}
			continue
		}

		id := n.getNetKeyFromSettings(settings)
		if id == NetKeyUnknown {
			n.logger.Warnf("unknown network, interface: %s, settings: %+v", ifName, settings)
			continue
		}
		nw := n.netState.LockingNetwork(id)

		state, err := activeConnection.GetPropertyState()
		nw.mu.Lock()
		if err != nil {
			n.logger.Warn(errw.Wrapf(err, "getting state of active connection: %s", id))
			n.netState.SetActiveConn(ifName, nil)
			n.netState.SetActiveSSID(ifName, "")
			nw.connected = false
		} else {
			n.netState.SetActiveConn(ifName, activeConnection)
			n.netState.SetActiveSSID(ifName, id.SSID())
			nw.connected = true
		}
		nw.mu.Unlock()

		// if this isn't the primary wifi device, we're done
		if ifName != n.Config().HotspotInterface {
			continue
		}

		// in roaming mode, we don't care WHAT network is connected
		if n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() &&
			state == gnm.NmActiveConnectionStateActivated &&
			id.SSID() != n.Config().HotspotSSID {
			connected = true
		}

		// in normal (single) mode, we need to be connected to the primary (highest priority) network
		if !n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() && state == gnm.NmActiveConnectionStateActivated &&
			id.SSID() == n.netState.PrimarySSID(n.Config().HotspotInterface) {
			connected = true
		}
	}
}

// StartProvisioning puts the wifi in hotspot mode and starts a captive portal.
func (n *Subsystem) startProvisioning(ctx context.Context, inputChan chan<- userInput) error {
	if n.connState.getProvisioning() {
		return errors.New("provisioning mode already started")
	}
	n.internalOpMu.Lock()
	defer n.internalOpMu.Unlock()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	// try to rebase the current config onto the default. since we no longer merge configs once a cloud config is available,
	// it may not include provisioning settings that were in the viam-defaults.json.
	if provisioningCfg, err := rebaseNetworkConfiguration(n.cfg); err != nil {
		n.logger.Infof("merging current networking config over viam-defaults.json failed with err. Continuing with current config.",
			"err", err, "current_cfg", n.cfg)
	} else if provisioningCfg != n.cfg {
		// only log if merge produced diffs: current cfg should be either base+cloud or base+defaults; rebased cfg should be base+defaults+cloud.
		// diffs should be entirely the fields set in viam-defaults that are not present in cloud.
		n.logger.Infof("starting provisioning. temporarily merging current networking config with 'viam-defaults' (if available)",
			"defaults_path", utils.DefaultsFilePath)
		// this has either 1) no change if we've never been online 2) will be restored to options from cloud-only once we're online & refetch.
		n.cfg = provisioningCfg
	}

	n.portalData.resetInputData(inputChan)
	hotspotErr := n.startProvisioningHotspot(ctx)
	if hotspotErr != nil {
		n.logger.Errorw("failed to start hotspot provisioning", "err", hotspotErr)
	}
	bluetoothErr := n.startProvisioningBluetooth(ctx)
	if bluetoothErr != nil {
		n.logger.Errorw("failed to start bluetooth provisioning", "err", bluetoothErr)
	}

	// Do not return an error if at least one provisioning method succeeds.
	n.connState.setProvisioning(hotspotErr == nil || bluetoothErr == nil)
	if hotspotErr == nil || bluetoothErr == nil {
		return nil
	}
	return errors.Join(hotspotErr, bluetoothErr)
}

// rebaseNetworkConfiguration reapplies a NetworkConfiguration over the default configuration.
func rebaseNetworkConfiguration(nCfg utils.NetworkConfiguration) (utils.NetworkConfiguration, error) {
	asJSON, err := json.Marshal(nCfg)
	if err != nil {
		return nCfg, err
	}

	// get default cfg. Hardcoded values + viam_defaults.json (if available - does not err if file does not exist).
	newCfg, err := utils.StackOfflineConfig()
	if err != nil {
		return nCfg, err
	}

	// merge current cfg on over
	err = json.Unmarshal(asJSON, &newCfg.NetworkConfiguration)
	if err != nil {
		return nCfg, err
	}

	return newCfg.NetworkConfiguration, err
}

// startProvisioningHotspot should only be called by 'StartProvisioning' (to
// ensure opMutex is acquired).
func (n *Subsystem) startProvisioningHotspot(ctx context.Context) error {
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
	if err := n.activateConnection(ctx, n.netState.GenNetKey(NetworkTypeHotspot, "", n.Config().HotspotSSID)); err != nil {
		return errw.Wrap(err, "starting provisioning mode hotspot")
	}

	if err := n.startPortal(PortalBindAddr); err != nil {
		err = errors.Join(err, n.deactivateConnection(n.netState.GenNetKey(NetworkTypeHotspot, "", n.Config().HotspotSSID)))
		return errw.Wrap(err, "starting web/grpc portal")
	}
	n.logger.Info("Hotspot provisioning set up successfully.")
	return nil
}

func (n *Subsystem) stopProvisioning() error {
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

func (n *Subsystem) stopProvisioningHotspot() error {
	// Always attempt to stop the portal, if it's not running this is just a noop.
	err := n.stopPortal()

	// Try to take down the wifi hotspot only if we're in provisioning mode. The
	// dbus/NetworkManager request goes by wifi device and not connection id, so
	// unconditionally calling deactivateConnection can disconnect a working wifi
	// connection when the agent stops.
	isProvisioning := n.connState.getProvisioning()
	if isProvisioning {
		err2 := n.deactivateConnection(n.netState.GenNetKey(NetworkTypeHotspot, "", n.Config().HotspotSSID))
		if errors.Is(err2, ErrNoActiveConnectionFound) {
			return err
		}
		err = errors.Join(err, err2)
	} else {
		n.logger.Debug("Not in provisioning mode, hotspot should not be active so will not modify wifi connections")
	}

	if err != nil {
		return err
	}
	// This makes the code a bit ugly but logging this when we haven't actually
	// touched the wifi state could cause a lot of confusion.
	if isProvisioning {
		n.logger.Info("Stopped hotspot provisioning mode.")
	}
	return nil
}

func (n *Subsystem) ActivateConnection(ctx context.Context, id NetKey) error {
	if n.connState.getProvisioning() && id.Interface() == n.Config().HotspotInterface {
		return errors.New("cannot activate another connection while in provisioning mode")
	}
	n.internalOpMu.Lock()
	defer n.internalOpMu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return n.activateConnection(ctx, id)
}

func (n *Subsystem) activateConnection(ctx context.Context, id NetKey) error {
	now := time.Now()
	nw := n.netState.LockingNetwork(id)
	nw.mu.Lock()
	defer nw.mu.Unlock()

	if nw.conn == nil {
		return errw.Errorf("no settings found for network: %s", id)
	}

	n.logger.Infow("activating connection", "id", id)
	nw.lastTried = now

	// Track the last WiFi network that attempted activation
	if nw.netType == NetworkTypeWifi {
		n.netState.SetLastSSID(id.Interface(), id.SSID())
	}

	netDev := n.netState.GetNetworkDevice(nw.netType, id.Interface())

	if netDev == nil {
		// we're trying to activate something on a missing adapter, perhaps it was hotplugged, so re-init devices and retry
		n.dataMu.Lock()
		if err := n.initDevices(); err != nil {
			n.logger.Warn(err)
		}
		n.dataMu.Unlock()

		// Retry getting the device after re-initializing
		netDev = n.netState.GetNetworkDevice(nw.netType, id.Interface())

		if netDev == nil {
			return errw.Errorf("cannot activate connection due to missing interface: %s", id.Interface())
		}
	}

	activeConnection, err := n.waitForConnect(ctx, nw, netDev)
	if err != nil {
		nw.lastError = err
		nw.connected = false
		return err
	}

	nw.connected = true
	nw.lastConnected = now
	nw.lastError = nil
	n.netState.SetActiveConn(id.Interface(), activeConnection)

	n.logger.Infof("Successfully activated connection: %s", id)

	if nw.netType != NetworkTypeHotspot {
		n.netState.SetActiveSSID(id.Interface(), id.SSID())
		if id.Interface() == n.Config().HotspotInterface &&
			(n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() || n.netState.PrimarySSID(id.Interface()) == id.SSID()) {
			n.connState.setConnected(true)
		}
		return n.checkOnline(ctx, true)
	}

	return nil
}

func (n *Subsystem) DeactivateConnection(id NetKey) error {
	if n.connState.getProvisioning() && id.Interface() == n.Config().HotspotInterface {
		return errors.New("cannot deactivate another connection while in provisioning mode")
	}

	n.internalOpMu.Lock()
	defer n.internalOpMu.Unlock()
	return n.deactivateConnection(id)
}

func (n *Subsystem) deactivateConnection(id NetKey) error {
	activeConn := n.netState.ActiveConn(id.Interface())
	if activeConn == nil {
		return errw.Wrapf(ErrNoActiveConnectionFound, "interface: %s", id.Interface())
	}

	nw := n.netState.LockingNetwork(id)
	nw.mu.Lock()
	defer nw.mu.Unlock()

	n.logger.Infof("Deactivating connection: %s", id)

	if err := n.nm.DeactivateConnection(activeConn); err != nil {
		nw.lastError = err
		return errw.Wrapf(err, "deactivating connection: %s", id)
	}

	n.logger.Infof("Successfully deactivated connection: %s", id)

	// TODO figure out what it means to be "disconnected" with bluetooth or multiple adapters
	if id.Interface() == n.Config().HotspotInterface {
		n.connState.setConnected(false)
	}

	nw.connected = false
	nw.lastConnected = time.Now()
	nw.lastError = nil
	n.netState.SetActiveSSID(id.Interface(), "")
	return nil
}

// waitForConnect activates a network after subscribing to state changes to monitor. The nw object should already be locked.
func (n *Subsystem) waitForConnect(ctx context.Context, nw *lockingNetwork, device gnm.Device) (gnm.ActiveConnection, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	changeChan := make(chan gnm.DeviceStateChange, 32)
	exitChan := make(chan struct{})
	defer close(exitChan)

	if err := device.SubscribeState(changeChan, exitChan); err != nil {
		return nil, errw.Wrap(err, "monitoring connection activation")
	}

	activeConnection, err := n.nm.ActivateConnection(nw.conn, device, nil)
	if err != nil {
		return activeConnection, errw.Wrapf(err, "activating connection: %s", n.netState.GenNetKey(nw.netType, nw.interfaceName, nw.ssid))
	}

	for {
		select {
		case update := <-changeChan:
			n.logger.Debugf("%s->%s (%s)", update.OldState, update.NewState, update.Reason)
			//nolint:exhaustive
			switch update.NewState {
			case gnm.NmDeviceStateActivated:
				return activeConnection, nil
			case gnm.NmDeviceStateFailed:
				if update.Reason == gnm.NmDeviceStateReasonNoSecrets {
					return activeConnection, errw.Wrapf(
						ErrBadPassword,
						"activating connection: %s",
						n.netState.GenNetKey(nw.netType, nw.interfaceName, nw.ssid),
					)
				}
				// custom error if it's some other reason for failure
				return activeConnection, errw.Errorf("connection failed: %s", update.Reason)
			default:
			}
		default:
			if !n.mainLoopHealth.Sleep(timeoutCtx, time.Second) {
				return activeConnection, errw.Wrap(timeoutCtx.Err(), "waiting for network activation")
			}
		}
	}
}

func (n *Subsystem) AddOrUpdateConnection(cfg utils.NetworkDefinition) (bool, error) {
	n.internalOpMu.Lock()
	defer n.internalOpMu.Unlock()
	return n.addOrUpdateConnection(cfg)
}

// returns true if network was new (added) and not updated.
func (n *Subsystem) addOrUpdateConnection(cfg utils.NetworkDefinition) (bool, error) {
	var changesMade bool

	if !slices.Contains(NetworkTypesKnown, cfg.Type) {
		return changesMade, errw.Errorf("network type (%s) not found, expected one of %v", cfg.Type, NetworkTypesKnown)
	}

	if cfg.Type != NetworkTypeWired && cfg.PSK != "" && len(cfg.PSK) < 8 {
		return changesMade, errors.New("wifi passwords must be at least 8 characters long, or completely empty (for unsecured networks)")
	}

	id := n.netState.GenNetKey(cfg.Type, cfg.Interface, cfg.SSID)
	nw := n.netState.LockingNetwork(id)
	nw.mu.Lock()
	nw.lastTried = time.Time{}
	if cfg.Type == NetworkTypeBluetooth {
		// if we activate bluetooth too quickly, while the device is still connecting, it can cause problems
		nw.lastTried = time.Now()
	}
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
		settings = generateHotspotSettings(id, n.Config().HotspotPassword)
	} else {
		settings, err = generateNetworkSettings(id, cfg)
		if err != nil {
			return changesMade, errw.Errorf("error generating network settings for %s: %v", id, err)
		}
	}

	if cfg.Type == NetworkTypeWifi && !n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() && cfg.Priority == 999 {
		// lower the priority of any existing/prior primary network
		n.lowerMaxNetPriorities(id)
		n.netState.SetPrimarySSID(n.Config().HotspotInterface, cfg.SSID)
	}

	n.logger.Infof("Adding/updating settings for network %s", id)

	var oldSettings gnm.ConnectionSettings
	nw.mu.Lock()
	defer nw.mu.Unlock()
	if nw.conn != nil {
		oldSettings, err = nw.conn.GetSettings()
		if err != nil {
			nw.conn = nil
			n.logger.Warn(errw.Wrapf(err, "getting current settings for %s, attempting to add as new network", id))
		} else if err := nw.conn.Update(settings); err != nil {
			// we may be out of sync with NetworkManager
			nw.conn = nil
			n.logger.Warn(errw.Wrapf(err, "updating settings for %s, attempting to add as new network", id))
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
		return changesMade, errw.Wrapf(err, "getting new settings for %s", id)
	}

	changesMade = changesMade || !reflect.DeepEqual(oldSettings, newSettings)

	return changesMade, nil
}

// this doesn't error as it's not technically fatal if it fails.
func (n *Subsystem) lowerMaxNetPriorities(skip NetKey) {
	for _, nw := range n.netState.LockingNetworks() {
		netKey := n.netState.GenNetKey(NetworkTypeWifi, nw.interfaceName, nw.ssid)
		if netKey == skip || netKey == n.netState.GenNetKey(NetworkTypeWifi, "", n.Config().HotspotSSID) ||
			nw.priority < 999 || nw.netType != NetworkTypeWifi ||
			(nw.interfaceName != "" && nw.interfaceName != n.Config().HotspotInterface && nw.interfaceName != n.Config().HotspotInterface) {
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

func (n *Subsystem) checkConfigured() {
	_, err := os.ReadFile(utils.AppConfigFilePath)
	n.connState.setConfigured(err == nil)
}

func (n *Subsystem) tryBluetoothTether(ctx context.Context) bool {
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

		if err := n.checkOnline(ctx, true); err != nil {
			n.logger.Warn(err)
			continue
		}

		if n.connState.getOnline() {
			return true
		}

		if err := n.ActivateConnection(ctx, n.netState.GenNetKey(nw.netType, nw.interfaceName, nw.ssid)); err != nil {
			n.logger.Info(errw.Wrap(err, "activating bluetooth tether"))
			continue
		}

		// in normal mode we just need a connection
		if !n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() {
			return true
		}

		// otherwise need the full online state
		return n.connState.getOnline()
	}
	return false
}

// tryCandidates returns true if a network activated.
func (n *Subsystem) tryCandidates(ctx context.Context) bool {
	for _, ssid := range n.getCandidates(n.Config().HotspotInterface) {
		err := n.ActivateConnection(ctx, n.netState.GenNetKey(NetworkTypeWifi, "", ssid))
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

func (n *Subsystem) getCandidates(ifName string) []string {
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

func (n *Subsystem) backgroundLoop(ctx context.Context, scanChan chan<- bool) {
	defer utils.Recover(n.logger, nil)
	defer n.monitorWorkers.Done()
	n.logger.Info("Background state monitors started")
	defer n.logger.Info("Background state monitors stopped")
	for {
		// note: these operations may not return immediately: despite scanLoopDelay,
		// the actual frequencies that each function runs at will depend on your system.
		if !n.bgLoopHealth.Sleep(ctx, scanLoopDelay) {
			return
		}

		n.checkConfigured()
		// this may block for 30s+
		if err := n.networkScan(ctx); err != nil {
			n.logger.Warn(err)
		}
		if err := n.updateKnownConnections(ctx); err != nil {
			n.logger.Warn(err)
		}
		n.checkConnections()
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
func (n *Subsystem) processUserInput(userInput userInput) bool {
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

func (n *Subsystem) checkForceProvisioning() bool {
	touchFile := path.Join(utils.ViamDirs.Etc, "force_provisioning_mode")

	// Check if the touch file exists
	if _, err := os.Stat(touchFile); err == nil {
		// File exists, remove it and set force provisioning time
		if err := os.Remove(touchFile); err != nil {
			n.logger.Errorw(
				"failed to remove force provisioning touch file, ignoring it to avoid getting stuck in provisioning mode",
				"path", touchFile, "err", err)
			return false
		} else {
			n.logger.Infow("force provisioning touch file found, will enter provisioning mode", "path", touchFile)
		}
		n.connState.setForceProvisioningTime(true)
		return true
	}

	// Check if the force was triggered less recently than the retry connection timeout
	return time.Since(n.connState.getForceProvisioningTime()) < time.Duration(n.Config().RetryConnectionTimeoutMinutes)
}

func (n *Subsystem) mainLoop(ctx context.Context) {
	defer utils.Recover(n.logger, nil)
	defer n.monitorWorkers.Done()
	defer func() {
		n.logger.Infow("stopping provisioning, networking shutting down")
		if err := n.stopProvisioning(); err != nil {
			n.logger.Warn(err)
		}
	}()

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
		startProvisioningIfNoInternet := n.Config().TurnOnHotspotIfWifiHasNoInternet.Get()
		if startProvisioningIfNoInternet {
			allGood = isOnline && isConfigured
			hasConnectivity = isOnline
			lastConnectivity = lastOnline
		}
		pMode := n.connState.getProvisioning()
		pModeChange := n.connState.getProvisioningChange()
		now := time.Now()

		// [Networking.checkForceProvisioning] involves a bit of disk I/O so be
		// sure to call it early and cache the result.
		forceProvisioning := n.checkForceProvisioning()
		n.logger.Debugw("networking main loop",
			"wifiConnected", isConnected,
			"wifiConnection", n.netState.GenNetKey(NetworkTypeWifi, "", n.netState.ActiveSSID(n.Config().HotspotInterface)),
			"internet", isOnline,
			"configPresent", isConfigured,
			"forceProvisioning", forceProvisioning,
		)

		if pMode {
			if n.bluetoothEnabled() {
				// Update bluetooth read-only characteristics
				if err := n.btChar.updateStatus(isConfigured, hasConnectivity); err != nil {
					n.logger.Warnw("could not update BT status characteristic", "err", err)
				}
				if err := n.btChar.updateNetworks(n.getVisibleNetworks()); err != nil {
					n.logger.Warnw("could not update BT networks characteristic", "err", err)
				}
				if err := n.btChar.updateErrors(n.errListAsStrings()); err != nil {
					n.logger.Warnw("could not update BT errors characteristic", "err", err)
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

			// only way for exit early when in forceProvisioning is userInput, otherwise the logic is any of the remaining conditions
			shouldExitPMode := (!forceProvisioning || userInputReceived) &&
				(allGood || haveCandidates || fallbackHit || shouldRebootSystem || userInputReceived)

			if shouldExitPMode {
				if userInputReceived {
					// user theoretically finished their interaction, so reset the trigger timer
					n.connState.setForceProvisioningTime(false)
					// We could get to this point before the user receives our response (poor UX, but likely not critical)
					// E.g. try to avoid "Not connected" web portal screen.
					n.mainLoopHealth.Sleep(ctx, 3*time.Second)
				}
				n.netState.mu.RLock()
				n.logger.Infow("stopping provisioning, condition change",
					"forceProvisioning", forceProvisioning,
					"userInputReceived", userInputReceived,
					"allGood", allGood,
					"haveCandidates", haveCandidates,
					"fallbackHit", fallbackHit,
					"shouldRebootSystem", shouldRebootSystem,
					"inactivePortal", inactivePortal,
					"isConfigured", isConfigured,
					"isConnected", isConnected,
					"isOnline", isOnline,
					"startProvisioningIfNoInternet", startProvisioningIfNoInternet,
					"activeConnections", n.netState.activeConn,
					"lastSsid", n.netState.lastSSID,
				)
				n.netState.mu.RUnlock()
				if err := n.stopProvisioning(); err != nil {
					n.logger.Warnw("failed to stop provisioning", "err", err)
				} else {
					pMode = n.connState.getProvisioning()
					pModeChange = n.connState.getProvisioningChange()
				}
			}

			if shouldRebootSystem && n.doReboot(ctx) {
				return
			}
		}

		if pMode || (!forceProvisioning && allGood) {
			continue
		}

		// not in provisioning mode
		if !hasConnectivity {
			var nwFound bool
			if userInputReceived && userInputSSID != "" {
				err := n.ActivateConnection(ctx, n.netState.GenNetKey(NetworkTypeWifi, "", userInputSSID))
				if err != nil {
					n.logger.Warnw("Failed to connect to newly provided WiFi", "ssid", userInputSSID)
				} else {
					nwFound = true
				}
			} else {
				nwFound = n.tryCandidates(ctx) || n.tryBluetoothTether(ctx)
			}

			if nwFound {
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
		if !isConfigured || hitOfflineTimeout || userInputReceived || forceProvisioning {
			n.netState.mu.RLock()
			n.logger.Infow("starting provisioning",
				"isConfigured", isConfigured,
				"hitOfflineTimeout", hitOfflineTimeout,
				"userInputReceived", userInputReceived,
				"forceProvisioning", forceProvisioning,
				"activeConnections", n.netState.activeConn,
				"lastSsid", n.netState.lastSSID,
			)
			n.netState.mu.RUnlock()
			if err := n.startProvisioning(ctx, inputChan); err != nil {
				n.logger.Warnw("failed to start provisioning mode", "err", err)
			}
		}
	}
}

func (n *Subsystem) doReboot(ctx context.Context) bool {
	n.logger.Infow(
		"device has been offline too long, rebooting",
		"configuredRebootTimeout",
		time.Duration(n.Config().DeviceRebootAfterOfflineMinutes),
	)
	cmd := exec.CommandContext(ctx, "systemctl", "reboot")
	output, err := cmd.CombinedOutput()
	if err != nil {
		n.logger.Warnw("Error running systemctl reboot", "output", output, "err", err)
	}
	const rebootWaitDuration = time.Minute * 5
	if !n.mainLoopHealth.Sleep(ctx, rebootWaitDuration) {
		return true
	}
	n.logger.Error("failed to reboot", "timeout", rebootWaitDuration)
	return false
}

func (n *Subsystem) CheckInternetManual(ctx context.Context, behindSocksProxy bool) (bool, error) {
	n.logger.Debug("checking internet by attempting to download test file.")
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*15)
	defer cancel()
	req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, manualCheckURL, nil)
	if err != nil {
		return false, errw.Wrap(err, "request setup")
	}

	// Use SOCKS proxy from environment as gRPC proxy dialer.
	httpClient := &http.Client{}
	if behindSocksProxy {
		httpClient.Transport = &http.Transport{
			DialContext: rpc.SocksProxyFallbackDialContext(manualCheckURL, n.logger),
		}
	}

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
		return false, errw.Errorf("got response '%s' while checking %s", resp.Status, manualCheckURL)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, errw.Wrap(err, "reading document body")
	}

	online := bytes.Contains(data, []byte(manualCheckTestContents))

	n.logger.Debugf("manual connection test to %s result: %t", manualCheckURL, online)

	return online, nil
}
