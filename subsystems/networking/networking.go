// Package networking is the subsystem responsible for network/wifi management, and initial device setup via hotspot.
package networking

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"time"

	semver "github.com/Masterminds/semver/v3"
	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/utils"
	pb "go.viam.com/api/provisioning/v1"
	"go.viam.com/rdk/logging"
	"google.golang.org/grpc"
)

type Provisioning struct {
	monitorWorkers sync.WaitGroup

	// blocks start/stop/etc operations
	opMu    sync.Mutex
	running bool
	noNM    bool

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

	// locking for config updates
	dataMu sync.Mutex

	// SMURF process these in Update
	cfg  utils.NetworkConfiguration
	nets utils.AdditionalNetworks

	// portal
	webServer  *http.Server
	grpcServer *grpc.Server
	portalData *portalData

	pb.UnimplementedProvisioningServiceServer
}

func NewSubsystem(ctx context.Context, logger logging.Logger, cfg utils.AgentConfig) subsystems.Subsystem {
	return &Provisioning{
		cfg:    cfg.NetworkConfiguration,
		nets:   cfg.AdditionalNetworks,
		logger: logger,

		connState: NewConnectionState(logger),
		netState:  NewNetworkState(logger),

		errors:     &errorList{},
		banner:     &banner{},
		portalData: &portalData{},

		mainLoopHealth: &health{},
		bgLoopHealth:   &health{},
	}
}

func (w *Provisioning) getNM() (gnm.NetworkManager, error) {
	nm, err := gnm.NewNetworkManager()
	if err != nil {
		w.noNM = true
		w.logger.Error(err)
		return nil, ErrNM
	}

	ver, err := nm.GetPropertyVersion()
	if err != nil {
		w.noNM = true
		w.logger.Error(err)
		return nil, ErrNM
	}

	w.logger.Infof("Found NetworkManager version: %s", ver)

	sv, err := semver.NewVersion(ver)
	if err != nil {
		w.noNM = true
		w.logger.Error(err)
		return nil, ErrNM
	}

	if !sv.GreaterThanEqual(semver.MustParse("1.30.0")) {
		w.noNM = true
		return nil, ErrNM
	}

	// Bail out here early if we can't find a wifi radio
	// Older versions will bail out during initDevices() if scan fails to find a wifi interface
	if sv.GreaterThanEqual(semver.MustParse("1.38.0")) {
		flags, err := nm.GetPropertyRadioFlags()
		if err != nil {
			w.noNM = true
			w.logger.Error(err)
			return nil, ErrNoWifi
		}

		if flags&gnm.NmRadioFlagsWlanAvailable != gnm.NmRadioFlagsWlanAvailable {
			w.noNM = true
			return nil, ErrNoWifi
		}
	}

	return nm, nil
}

func (w *Provisioning) init(ctx context.Context) error {
	w.mainLoopHealth.MarkGood()
	w.bgLoopHealth.MarkGood()

	nm, err := w.getNM()
	if err != nil {
		return err
	}

	settings, err := gnm.NewSettings()
	if err != nil {
		return err
	}

	w.nm = nm
	w.settings = settings

	w.netState.SetHotspotInterface(w.cfg.HotspotInterface)

	if err := w.writeDNSMasq(); err != nil {
		return errw.Wrap(err, "writing dnsmasq configuration")
	}

	if err := w.testConnCheck(); err != nil {
		return err
	}

	if err := w.enableWifi(ctx); err != nil {
		return err
	}

	if err := w.initDevices(); err != nil {
		if errors.Is(err, ErrNoWifi) {
			w.noNM = true
		}
		return err
	}

	w.checkConfigured()
	if err := w.networkScan(ctx); err != nil {
		w.logger.Error(err)
	}
	if err := w.updateKnownConnections(ctx); err != nil {
		w.logger.Error(err)
	}

	w.warnIfMultiplePrimaryNetworks()

	if w.cfg.TurnOnHotspotIfWifiHasNoInternet {
		w.logger.Info("Wifi internet checking enabled. Will try all connections for global internet connectivity.")
	} else {
		primarySSID := w.netState.PrimarySSID(w.Config().HotspotInterface)
		w.logger.Infof("Internet checks disabled. Will directly connect to primary network: %s", primarySSID)
		if primarySSID == "" {
			w.logger.Warnf("cannot find primary SSID for %s", w.Config().HotspotInterface)
		}
	}

	if err := w.checkConnections(); err != nil {
		w.logger.Error(err)
	}

	// Is there a configured wifi network? If so, set last times to now so we use normal timeouts.
	// Otherwise, hotspot will start immediately if not connected, while wifi network might still be booting.
	for _, nw := range w.netState.Networks() {
		if nw.conn != nil && nw.netType == NetworkTypeWifi && (nw.interfaceName == "" || nw.interfaceName == w.Config().HotspotInterface) {
			w.connState.lastConnected = time.Now()
			w.connState.lastOnline = time.Now()
			break
		}
	}

	return nil
}

func (w *Provisioning) Start(ctx context.Context) error {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	if w.running {
		return nil
	}

	if w.nm == nil || w.settings == nil {
		if err := w.init(ctx); err != nil {
			return err
		}
	}

	if err := w.writeWifiPowerSave(ctx); err != nil {
		w.logger.Error(errw.Wrap(err, "applying wifi power save configuration"))
	}

	w.processAdditionalnetworks(ctx)

	if err := w.checkOnline(true); err != nil {
		w.logger.Error(err)
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel

	// This will loop indefinitely until context cancellation or serious error
	w.monitorWorkers.Add(1)
	go w.mainLoop(cancelCtx)

	w.logger.Info("agent-provisioning startup complete")
	w.running = true
	return nil
}

func (w *Provisioning) Stop(ctx context.Context) error {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	if !w.running {
		return nil
	}

	w.logger.Infof("%s subsystem exiting", SubsysName)
	if w.connState.getProvisioning() {
		err := w.stopProvisioning()
		if err != nil {
			w.logger.Error(err)
		}
	}
	if w.cancel != nil {
		w.cancel()
	}
	w.monitorWorkers.Wait()
	w.running = false
	return nil
}

// Update validates and/or updates a subsystem, returns true if subsystem should be restarted.
func (w *Provisioning) Update(ctx context.Context, cfg utils.AgentConfig) (needRestart bool) {
	w.opMu.Lock()
	defer w.opMu.Unlock()

	if w.noNM {
		return needRestart
	}

	if w.nm == nil || w.settings == nil {
		if err := w.init(ctx); err != nil {
			w.logger.Error(err)
			return needRestart
		}
	}

	if cfg.NetworkConfiguration.HotspotInterface == "" {
		cfg.NetworkConfiguration.HotspotInterface = w.Config().HotspotInterface
	}
	w.netState.SetHotspotInterface(cfg.NetworkConfiguration.HotspotInterface)

	if reflect.DeepEqual(cfg.NetworkConfiguration, w.cfg) && reflect.DeepEqual(cfg.AdditionalNetworks, w.nets) {
		return needRestart
	}

	needRestart = true
	w.logger.Debugf("Updated config differs from previous. Previous: %+v New: %+v", w.cfg, cfg)

	w.dataMu.Lock()
	defer w.dataMu.Unlock()
	w.cfg = cfg.NetworkConfiguration
	w.nets = cfg.AdditionalNetworks

	return needRestart
}

// HealthCheck reports if a subsystem is running correctly (it is restarted if not).
func (w *Provisioning) HealthCheck(ctx context.Context) error {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	if w.noNM {
		return nil
	}

	if w.bgLoopHealth.IsHealthy() && w.mainLoopHealth.IsHealthy() {
		return nil
	}

	return errw.New("provisioning not responsive")
}

func (w *Provisioning) Config() utils.NetworkConfiguration {
	w.dataMu.Lock()
	defer w.dataMu.Unlock()
	return w.cfg
}

func (w *Provisioning) processAdditionalnetworks(ctx context.Context) {
	if !w.cfg.TurnOnHotspotIfWifiHasNoInternet && len(w.nets) > 0 {
		w.logger.Warn("Additional networks configured, but internet checking is not enabled. Additional networks may be unused.")
	}

	for _, network := range w.nets {
		_, err := w.addOrUpdateConnection(network)
		if err != nil {
			w.logger.Error(errw.Wrapf(err, "adding network %s", network.SSID))
			continue
		}
		if network.Interface != "" {
			if err := w.activateConnection(ctx, network.Interface, network.SSID); err != nil {
				w.logger.Error(err)
			}
		}
	}
}

// must be run inside dataMu lock.
func (w *Provisioning) writeWifiPowerSave(ctx context.Context) error {
	contents := wifiPowerSaveContentsDefault
	if w.cfg.WifiPowerSave != nil {
		if *w.cfg.WifiPowerSave {
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
		w.logger.Infof("Updated %s to: %q", wifiPowerSaveFilepath, contents)
		// Reload NetworkManager to apply changes
		if err := w.nm.Reload(0); err != nil {
			return errw.Wrap(err, "reloading NetworkManager after wifi-powersave.conf update")
		}

		ssid := w.netState.ActiveSSID(w.cfg.HotspotInterface)
		if w.connState.getConnected() && ssid != "" {
			if err := w.activateConnection(ctx, w.cfg.HotspotInterface, ssid); err != nil {
				return errw.Wrapf(err, "reactivating %s to enforce powersave setting", ssid)
			}
		}
	}

	return nil
}
