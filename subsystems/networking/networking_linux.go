package networking

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	semver "github.com/Masterminds/semver/v3"
	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/utils"
	gnm "github.com/viamrobotics/gonetworkmanager/v2"
	pb "go.viam.com/api/provisioning/v1"
	"go.viam.com/rdk/logging"
	"google.golang.org/grpc"
	"tinygo.org/x/bluetooth"
)

type Networking struct {
	monitorWorkers sync.WaitGroup

	// blocks start/stop/update operations for the subsystem
	externalOpMu sync.RWMutex
	running      bool
	noNM         bool

	// blocks internal ops like activate/deactivate connections and provisioning mode
	internalOpMu sync.Mutex

	// used to stop main/bg loops
	cancel context.CancelFunc

	// only set during NewProvisioning, no lock
	nm       gnm.NetworkManager
	settings gnm.Settings
	logger   logging.Logger

	// internal locking
	connState *connectionState
	netState  *networkState
	errors    *errorList
	banner    *banner

	mainLoopHealth *health
	bgLoopHealth   *health
	btHealthy      bool

	// locking for config updates
	dataMu sync.RWMutex
	cfg    utils.NetworkConfiguration
	nets   utils.AdditionalNetworks

	// portal
	webServer  *http.Server
	grpcServer *grpc.Server
	portalData *userInputData

	// bluetooth
	noBT    bool
	btChar  *btCharacteristics
	btAdv   *bluetooth.Advertisement
	btAgent *pairingAgent

	pb.UnimplementedProvisioningServiceServer
}

func NewSubsystem(ctx context.Context, logger logging.Logger, cfg utils.AgentConfig) subsystems.Subsystem {
	subsys := &Networking{
		cfg:    cfg.NetworkConfiguration,
		nets:   cfg.AdditionalNetworks,
		logger: logger,

		connState: NewConnectionState(logger),
		netState:  NewNetworkState(logger),

		errors: &errorList{},
		banner: &banner{},

		mainLoopHealth: &health{},
		bgLoopHealth:   &health{},
	}
	subsys.portalData = &userInputData{connState: subsys.connState}
	subsys.btAgent = &pairingAgent{
		logger:     logger,
		networking: subsys,
		trusted:    make(map[string]bool),
		trustAll:   cfg.NetworkConfiguration.BluetoothTrustAll.Get(),
	}
	subsys.btChar = newBTCharacteristics(logger, subsys.portalData, cfg.NetworkConfiguration.HotspotPassword, subsys.btAgent.TrustAll)
	return subsys
}

func (n *Networking) IsRunning() bool {
	n.externalOpMu.RLock()
	defer n.externalOpMu.RUnlock()
	return n.isRunning()
}

func (n *Networking) isRunning() bool {
	return n.running || n.noNM
}

func (n *Networking) getNM() (gnm.NetworkManager, error) {
	nm, err := gnm.NewNetworkManager()
	if err != nil {
		n.logger.Warn(err)
		return nil, ErrNM
	}

	ver, err := nm.GetPropertyVersion()
	if err != nil {
		n.logger.Warn(err)
		return nil, ErrNM
	}

	n.logger.Infof("Found NetworkManager version: %s", ver)

	sv, err := semver.NewVersion(ver)
	if err != nil {
		n.logger.Warn(err)
		return nil, ErrNM
	}

	if !sv.GreaterThanEqual(semver.MustParse("1.30.0")) {
		return nil, ErrNM
	}

	// Bail out here early if we can't find a wifi radio
	// Older versions will bail out during initDevices() if scan fails to find a wifi interface
	if sv.GreaterThanEqual(semver.MustParse("1.38.0")) {
		flags, err := nm.GetPropertyRadioFlags()
		if err != nil {
			n.logger.Warn(err)
			return nil, ErrNoWifi
		}

		if flags&gnm.NmRadioFlagsWlanAvailable != gnm.NmRadioFlagsWlanAvailable {
			return nil, ErrNoWifi
		}
	}

	return nm, nil
}

func (n *Networking) init(ctx context.Context) error {
	n.mainLoopHealth.MarkGood()
	n.bgLoopHealth.MarkGood()

	nm, err := n.getNM()
	if err != nil {
		n.noNM = true
		return err
	}

	settings, err := gnm.NewSettings()
	if err != nil {
		return err
	}

	n.nm = nm
	n.settings = settings

	n.netState.SetHotspotInterface(n.Config().HotspotInterface)

	if err := n.writeDNSMasq(); err != nil {
		return errw.Wrap(err, "writing dnsmasq configuration")
	}

	if err := n.testConnCheck(); err != nil {
		return err
	}

	if err := n.enableWifi(ctx); err != nil {
		return err
	}

	if err := n.initDevices(); err != nil {
		n.noNM = true
		return err
	}

	n.checkConfigured()
	if err := n.networkScan(ctx); err != nil {
		n.logger.Warn(err)
	}
	if err := n.updateKnownConnections(ctx); err != nil {
		n.logger.Warn(err)
	}

	n.warnIfMultiplePrimaryNetworks()

	if n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() {
		n.logger.Info("Wifi internet checking enabled. Will try all connections for global internet connectivity.")
	} else {
		primarySSID := n.netState.PrimarySSID(n.Config().HotspotInterface)
		n.logger.Infof("Internet checks disabled. Will directly connect to primary network: %s", primarySSID)
		if primarySSID == "" {
			n.logger.Warnf("cannot find primary SSID for %s", n.Config().HotspotInterface)
		}
	}

	n.checkConnections()

	// Is there a configured wifi network? If so, set last times to now so we use normal timeouts.
	// Otherwise, hotspot will start immediately if not connected, while wifi network might still be booting.
	for _, nw := range n.netState.Networks() {
		if nw.conn != nil && nw.netType == NetworkTypeWifi && (nw.interfaceName == "" || nw.interfaceName == n.Config().HotspotInterface) {
			n.connState.lastConnected = time.Now()
			n.connState.lastOnline = time.Now()
			break
		}
	}

	return nil
}

func (n *Networking) Start(ctx context.Context) error {
	// don't hold the write lock if we'd basically do nothing
	if n.IsRunning() {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	n.externalOpMu.Lock()
	defer n.externalOpMu.Unlock()
	// We may have blocked waiting for a lock, so check status again, using non-locking call
	if n.isRunning() {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	n.logger.Infof("Starting networking subsystem")

	if n.nm == nil || n.settings == nil {
		if err := n.init(ctx); err != nil {
			return err
		}
	}

	if err := n.writeWifiPowerSave(ctx); err != nil {
		n.logger.Warn(errw.Wrap(err, "applying wifi power save configuration"))
	}

	n.processAdditionalnetworks(ctx)

	if err := n.checkOnline(ctx, true); err != nil {
		n.logger.Warn(err)
	}

	if !n.Config().DisableBTProvisioning.Get() || !n.Config().DisableWifiProvisioning.Get() {
		cancelCtx, cancel := context.WithCancel(ctx)
		n.cancel = cancel // This will loop indefinitely until context cancellation or serious error
		n.monitorWorkers.Add(1)
		n.mainLoopHealth.MarkGood()
		n.bgLoopHealth.MarkGood()
		go n.mainLoop(cancelCtx)
	} else {
		n.logger.Warn("Both wifi and bluetooth provisioning have been disabled by configuration. Provisioning will not be available.")
	}

	n.logger.Info("Networking startup complete")
	n.running = true
	return nil
}

func (n *Networking) Stop(ctx context.Context) error {
	// don't hold the write lock if we'd basically do nothing
	if !n.IsRunning() {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	n.externalOpMu.Lock()
	defer n.externalOpMu.Unlock()
	// We may have blocked waiting for a lock, so check status again, using non-locking call
	if !n.isRunning() {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	n.logger.Infof("Stopping networking subsystem")
	if n.cancel != nil {
		n.cancel()
	}
	n.monitorWorkers.Wait()
	n.running = false
	return nil
}

// Update validates and/or updates a subsystem, returns true if subsystem should be restarted.
func (n *Networking) Update(ctx context.Context, cfg utils.AgentConfig) (needRestart bool) {
	if ctx.Err() != nil {
		return false
	}
	n.externalOpMu.Lock()
	defer n.externalOpMu.Unlock()
	if ctx.Err() != nil {
		return false
	}
	if n.noNM {
		return needRestart
	}

	if n.nm == nil || n.settings == nil {
		if err := n.init(ctx); err != nil {
			n.logger.Warn(err)
			return needRestart
		}
	}

	if cfg.NetworkConfiguration.HotspotInterface == "" {
		cfg.NetworkConfiguration.HotspotInterface = n.Config().HotspotInterface
	}
	n.netState.SetHotspotInterface(cfg.NetworkConfiguration.HotspotInterface)

	if reflect.DeepEqual(cfg.NetworkConfiguration, n.Config()) && reflect.DeepEqual(cfg.AdditionalNetworks, n.nets) {
		return needRestart
	}

	needRestart = true
	n.logger.Debugf("Updated config differs from previous. Previous: %#v New: %#v", n.Config(), cfg)

	n.dataMu.Lock()
	defer n.dataMu.Unlock()
	n.cfg = cfg.NetworkConfiguration
	n.nets = cfg.AdditionalNetworks

	n.btAgent.mu.Lock()
	defer n.btAgent.mu.Unlock()
	n.btAgent.trustAll = cfg.NetworkConfiguration.BluetoothTrustAll.Get()

	if err := n.writeDNSMasq(); err != nil {
		n.logger.Warn(errw.Wrap(err, "writing dnsmasq configuration"))
	}

	return needRestart
}

// HealthCheck reports if a subsystem is running correctly (it is restarted if not).
func (n *Networking) HealthCheck(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if n.noNM || (n.Config().DisableBTProvisioning.Get() && n.Config().DisableWifiProvisioning.Get()) {
		return nil
	}
	bgLoopHealthy := n.bgLoopHealth.IsHealthy()
	mainLoopHealthy := n.mainLoopHealth.IsHealthy()
	btEnabled := n.bluetoothEnabled()
	btAdvUnset := n.btAdv == nil
	btHealthy := n.btHealthy
	wifiOk := bgLoopHealthy && mainLoopHealthy
	btOk := !btEnabled || btAdvUnset || btHealthy
	if wifiOk || btOk {
		if !wifiOk || (btEnabled && !btOk) {
			// If any form of networking is still working we should return nil so the
			// agent doesn't shut down the entire subsystem, for example shutting
			// down a functioning wifi access point when only bluetooth is broken,
			// but still log that something is wrong.
			n.logger.Warnw("Networking subsystem is partially unhealthy",
				"wikiOk", wifiOk,
				"bluetoothOk", btOk)
		}
		return nil
	}
	return networkingUnresponsiveError{
		bgLoopHealthy:   bgLoopHealthy,
		mainLoopHealthy: mainLoopHealthy,
		btEnabled:       btEnabled,
		btAdvUnset:      btAdvUnset,
		btHealthy:       btHealthy,
	}
}

type networkingUnresponsiveError struct {
	bgLoopHealthy   bool
	mainLoopHealthy bool
	btEnabled       bool
	btAdvUnset      bool
	btHealthy       bool
}

func (e networkingUnresponsiveError) Error() string {
	reasons := make([]string, 0, 4)
	if !e.bgLoopHealthy {
		reasons = append(reasons, "background loop unhealthy")
	}
	if !e.mainLoopHealthy {
		reasons = append(reasons, "main loop unhealthy")
	}
	if e.btEnabled && !e.btAdvUnset && !e.btHealthy {
		reasons = append(reasons, "bluetooth unhealthy")
	}
	return "networking system not responsive )" +
		strings.Join(reasons, ", ") +
		")"
}

func (n *Networking) Config() utils.NetworkConfiguration {
	n.dataMu.RLock()
	defer n.dataMu.RUnlock()
	return n.cfg
}

func (n *Networking) Nets() utils.AdditionalNetworks {
	n.dataMu.RLock()
	defer n.dataMu.RUnlock()
	return n.nets
}

func (n *Networking) processAdditionalnetworks(ctx context.Context) {
	if !n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() && len(n.Nets()) > 0 {
		n.logger.Warn("Additional networks configured, but internet checking is not enabled. Additional networks may be unused.")
	}

	for _, network := range n.Nets() {
		_, err := n.addOrUpdateConnection(network)
		if err != nil {
			n.logger.Warnw("error adding network", "err", err, "ssid", network.SSID)
			continue
		}
		if network.Interface != "" {
			if err := n.activateConnection(ctx, n.netState.GenNetKey(network.Type, network.Interface, network.SSID)); err != nil {
				n.logger.Warn(err)
			}
		}
	}
}

// must be run inside dataMu lock.
func (n *Networking) writeWifiPowerSave(ctx context.Context) error {
	contents := wifiPowerSaveContentsDefault
	if n.Config().WifiPowerSave.IsSet() {
		if n.Config().WifiPowerSave.Get() {
			contents = wifiPowerSaveContentsEnable
		} else {
			contents = wifiPowerSaveContentsDisable
		}
	}

	isNew, err := utils.WriteFileIfNew(wifiPowerSaveFilepath, []byte(contents))
	if err != nil {
		return errw.Wrap(err, "writing wifi-powersave.conf")
	}

	if isNew {
		n.logger.Infof("Updated %s to: %q", wifiPowerSaveFilepath, contents)
		// Reload NetworkManager to apply changes
		if err := n.nm.Reload(0); err != nil {
			return errw.Wrap(err, "reloading NetworkManager after wifi-powersave.conf update")
		}

		ssid := n.netState.ActiveSSID(n.Config().HotspotInterface)
		if n.connState.getConnected() && ssid != "" {
			if err := n.activateConnection(ctx, n.netState.GenNetKey(NetworkTypeWifi, "", ssid)); err != nil {
				return errw.Wrapf(err, "reactivating %s to enforce powersave setting", ssid)
			}
		}
	}

	return nil
}

// MarkAppTriggeredRestart is a noop for the networking subsystem.
func (s *Networking) MarkAppTriggeredRestart() {}

// RestartAllowed always returns true for the networking subsystem.
func (n *Networking) RestartAllowed(_ context.Context) bool {
	return true
}

// DoesNotHandleNeedsRestart always returns false for the networking subsystem.
func (n *Networking) DoesNotHandleNeedsRestart() bool {
	return false
}
