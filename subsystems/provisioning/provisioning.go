// Package provisioning is the subsystem responsible for network/wifi management, and initial device setup via hotspot.
package provisioning

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	semver "github.com/Masterminds/semver/v3"
	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/subsystems/registry"
	agentpb "go.viam.com/api/app/agent/v1"
	pb "go.viam.com/api/provisioning/v1"
	"go.viam.com/rdk/logging"
	"google.golang.org/grpc"
)

const (
	wifiPowerSaveFilepath = "/etc/NetworkManager/conf.d/wifi-powersave.conf"

	wifiPowerSaveContentsDefault = "[connection]\n# Do not modify existing setting\nwifi.powersave = 1"
	wifiPowerSaveContentsDisable = "[connection]\n# Explicitly disable\nwifi.powersave = 2"
	wifiPowerSaveContentsEnable  = "[connection]\n# Explicitly enable\nwifi.powersave = 3"
)

func init() {
	registry.Register(SubsysName, NewProvisioning)
}

type Provisioning struct {
	monitorWorkers sync.WaitGroup

	// blocks start/stop/etc operations
	opMu     sync.Mutex
	running  bool
	disabled bool
	noNM     bool

	// used to stop main/bg loops
	cancel context.CancelFunc

	// only set during NewProvisioning, no lock
	nm         gnm.NetworkManager
	settings   gnm.Settings
	hostname   string
	logger     logging.Logger
	AppCfgPath string

	// internal locking
	connState *connectionState
	netState  *networkState
	errors    *errorList
	banner    *banner

	mainLoopHealth *health
	bgLoopHealth   *health

	// locking for config updates
	dataMu sync.Mutex
	cfg    *Config

	// portal
	webServer  *http.Server
	grpcServer *grpc.Server
	portalData *portalData

	pb.UnimplementedProvisioningServiceServer
}

func NewProvisioning(ctx context.Context, logger logging.Logger, updateConf *agentpb.DeviceSubsystemConfig) (subsystems.Subsystem, error) {
	cfg, err := LoadConfig(updateConf)
	if err != nil {
		logger.Error(errw.Wrap(err, "loading provisioning config"))
	}
	logger.Debugf("Provisioning Config: %+v", cfg)

	w := &Provisioning{
		disabled:   updateConf.GetDisable(),
		cfg:        cfg,
		AppCfgPath: AppConfigFilePath,
		logger:     logger,

		connState: NewConnectionState(logger),
		netState:  NewNetworkState(logger),

		errors:     &errorList{},
		banner:     &banner{},
		portalData: &portalData{},

		mainLoopHealth: &health{},
		bgLoopHealth:   &health{},
	}
	return w, nil
}

func (w *Provisioning) getNM() (gnm.NetworkManager, error) {
	nmErr := errw.New("NetworkManager does not appear to be responding as expected. " +
		"Please ensure NetworkManger >= v1.42 is installed and enabled. Disabling agent-provisioning until next restart.")
	wifiErr := errw.New("No WiFi devices available. Disabling agent-provisioning until next restart.")

	nm, err := gnm.NewNetworkManager()
	if err != nil {
		w.noNM = true
		w.logger.Error(err)
		return nil, nmErr
	}

	ver, err := nm.GetPropertyVersion()
	if err != nil {
		w.noNM = true
		w.logger.Error(err)
		return nil, nmErr
	}

	w.logger.Infof("Found NetworkManager version: %s", ver)

	sv, err := semver.NewVersion(ver)
	if err != nil {
		w.noNM = true
		w.logger.Error(err)
		return nil, nmErr
	}

	if !sv.GreaterThanEqual(semver.MustParse("1.42.0")) {
		w.noNM = true
		return nil, nmErr
	}

	flags, err := nm.GetPropertyRadioFlags()
	if err != nil {
		w.noNM = true
		w.logger.Error(err)
		return nil, wifiErr
	}

	if flags&gnm.NmRadioFlagsWlanAvailable != gnm.NmRadioFlagsWlanAvailable {
		w.noNM = true
		return nil, wifiErr
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

	w.hostname, err = settings.GetPropertyHostname()
	if err != nil {
		return errw.Wrap(err, "getting hostname from NetworkManager")
	}

	w.updateHotspotSSID(w.cfg)

	if err := w.writeDNSMasq(); err != nil {
		return errw.Wrap(err, "error writing dnsmasq configuration")
	}

	if err := w.testConnCheck(); err != nil {
		return err
	}

	if err := w.enableWifi(ctx); err != nil {
		return err
	}

	if err := w.initDevices(); err != nil {
		return err
	}

	w.checkConfigured()
	if err := w.networkScan(ctx); err != nil {
		w.logger.Error(err)
	}

	w.warnIfMultiplePrimaryNetworks()

	if w.cfg.RoamingMode {
		w.logger.Info("Roaming Mode enabled. Will try all connections for global internet connectivity.")
	} else {
		primarySSID := w.netState.PrimarySSID(w.Config().HotspotInterface)
		w.logger.Infof("Default (Single Network) Mode enabled. Will directly connect only to primary network: %s", primarySSID)
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

	if w.disabled || w.noNM {
		return agent.ErrSubsystemDisabled
	}

	if w.nm == nil || w.settings == nil {
		if err := w.init(ctx); err != nil {
			return err
		}
	}

	if err := w.writeWifiPowerSave(); err != nil {
		w.logger.Error(errw.Wrap(err, "error applying wifi power save configuration"))
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
func (w *Provisioning) Update(ctx context.Context, updateConf *agentpb.DeviceSubsystemConfig) (bool, error) {
	w.opMu.Lock()
	defer w.opMu.Unlock()

	var needRestart bool

	if w.noNM {
		return needRestart, nil
	}

	if w.disabled != updateConf.GetDisable() {
		w.disabled = updateConf.GetDisable()
		if w.disabled {
			w.logger.Infof("agent-provisioning disabled")
		}
		needRestart = true
	}

	if w.disabled {
		return needRestart, nil
	}

	if w.nm == nil || w.settings == nil {
		if err := w.init(ctx); err != nil {
			return true, err
		}
	}

	cfg, err := LoadConfig(updateConf)
	if err != nil {
		return needRestart, err
	}

	w.updateHotspotSSID(cfg)
	if cfg.HotspotInterface == "" {
		cfg.HotspotInterface = w.Config().HotspotInterface
	}

	if reflect.DeepEqual(cfg, w.cfg) {
		return needRestart, nil
	}

	needRestart = true
	w.logger.Debugf("Updated config differs from previous. Previous: %+v New: %+v", w.cfg, cfg)

	w.dataMu.Lock()
	defer w.dataMu.Unlock()
	w.cfg = cfg

	return needRestart, nil
}

// HealthCheck reports if a subsystem is running correctly (it is restarted if not).
func (w *Provisioning) HealthCheck(ctx context.Context) error {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	if w.disabled || w.noNM {
		return nil
	}

	if w.bgLoopHealth.IsHealthy() && w.mainLoopHealth.IsHealthy() {
		return nil
	}

	return errw.New("provisioning not responsive")
}

// Version returns the current version of the subsystem.
func (w *Provisioning) Version() string {
	return agent.GetRevision()
}

func (w *Provisioning) Config() Config {
	w.dataMu.Lock()
	defer w.dataMu.Unlock()
	return *w.cfg
}

func (w *Provisioning) processAdditionalnetworks(ctx context.Context) {
	if !w.cfg.RoamingMode && len(w.cfg.Networks) > 0 {
		w.logger.Warn("Additional networks configured, but Roaming Mode is not enabled. Additional wifi networks will likely be unused.")
	}

	for _, network := range w.cfg.Networks {
		_, err := w.addOrUpdateConnection(network)
		if err != nil {
			w.logger.Error(errw.Wrapf(err, "error adding network %s", network.SSID))
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
func (w *Provisioning) updateHotspotSSID(cfg *Config) {
	cfg.hotspotSSID = cfg.HotspotPrefix + "-" + strings.ToLower(w.hostname)
	if len(cfg.hotspotSSID) > 32 {
		cfg.hotspotSSID = cfg.hotspotSSID[:32]
	}
}

func (w *Provisioning) writeWifiPowerSave() error {
	contents := wifiPowerSaveContentsDefault

	if w.cfg.DisableWifiPowerSave != nil && *w.cfg.DisableWifiPowerSave {
		contents = wifiPowerSaveContentsDisable
	}

	if w.cfg.DisableWifiPowerSave != nil && !*w.cfg.DisableWifiPowerSave {
		contents = wifiPowerSaveContentsEnable
	}

	isNew, err := agent.WriteFileIfNew(wifiPowerSaveFilepath, []byte(contents))
	if err != nil {
		return errw.Wrap(err, "error writing wifi-powersave.conf")
	}

	if isNew {
		w.logger.Infof("Updated %s to: %q", wifiPowerSaveFilepath, contents)
		// Reload NetworkManager to apply changes
		if err := w.nm.Reload(0); err != nil {
			return errw.Wrap(err, "error reloading NetworkManager after wifi-powersave.conf update")
		}
	}

	return nil
}
