// Package provisioning is the subsystem responsible for network/wifi management, and initial device setup via hotspot.
package provisioning

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

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

func init() {
	registry.Register(SubsysName, NewProvisioning)
}

type Provisioning struct {
	monitorWorkers sync.WaitGroup

	// blocks start/stop/etc operations
	// holders of this lock must use HealthySleep to respond to HealthChecks from the parent agent during long operations
	opMu sync.Mutex

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
		return nil, errw.Wrap(err, "loading provisioning config")
	}
	logger.Debugf("Provisioning Config: %+v", cfg)

	nm, err := gnm.NewNetworkManager()
	if err != nil {
		return nil, err
	}

	settings, err := gnm.NewSettings()
	if err != nil {
		return nil, err
	}

	w := &Provisioning{
		cfg:        cfg,
		AppCfgPath: AppConfigFilePath,
		logger:     logger,
		nm:         nm,
		settings:   settings,

		connState: NewConnectionState(logger),
		netState:  NewNetworkState(logger),

		errors:     &errorList{},
		banner:     &banner{},
		portalData: &portalData{},

		mainLoopHealth: &health{},
		bgLoopHealth:   &health{},
	}

	w.hostname, err = settings.GetPropertyHostname()
	if err != nil {
		return nil, errw.Wrap(err, "error getting hostname from NetworkManager, is NetworkManager installed and enabled?")
	}

	w.updateHotspotSSID()

	if err := w.writeDNSMasq(); err != nil {
		return nil, errw.Wrap(err, "error writing dnsmasq configuration")
	}

	if err := w.testConnCheck(); err != nil {
		return nil, err
	}

	if err := w.initDevices(); err != nil {
		return nil, err
	}

	w.checkConfigured()
	if err := w.networkScan(ctx); err != nil {
		return nil, err
	}

	w.warnIfMultiplePrimaryNetworks()

	if w.cfg.RoamingMode {
		w.logger.Info("Roaming Mode enabled. Will try all connections for global internet connectivity.")
	} else {
		w.logger.Infof("Default (Single Network) Mode enabled. Will directly connect only to primary network: %s",
			w.netState.PrimarySSID(w.Config().HotspotInterface))
	}

	if err := w.checkConnections(); err != nil {
		return nil, err
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

	return w, nil
}

func (w *Provisioning) Start(ctx context.Context) error {
	w.opMu.Lock()
	defer w.opMu.Unlock()

	w.processAdditionalnetworks(ctx)

	if err := w.checkOnline(true); err != nil {
		w.logger.Error(err)
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel

	// these will loop indefinitely until context cancellation or serious error
	go w.mainLoop(cancelCtx)

	w.logger.Info("agent-provisioning startup complete")
	return nil
}

func (w *Provisioning) Stop(ctx context.Context) error {
	w.opMu.Lock()
	defer w.opMu.Unlock()

	w.logger.Infof("%s subsystem exiting", SubsysName)
	if w.connState.getProvisioning() {
		err := w.StopProvisioning()
		if err != nil {
			w.logger.Error(err)
		}
	}
	w.cancel()
	w.monitorWorkers.Wait()
	return nil
}

// Update validates and/or updates a subsystem, returns true if subsystem should be restarted.
func (w *Provisioning) Update(ctx context.Context, updateConf *agentpb.DeviceSubsystemConfig) (bool, error) {
	w.opMu.Lock()
	defer w.opMu.Unlock()

	cfg, err := LoadConfig(updateConf)
	if err != nil {
		return false, err
	}

	if reflect.DeepEqual(cfg, w.cfg) {
		return false, nil
	}

	w.dataMu.Lock()
	defer w.dataMu.Unlock()
	w.cfg = cfg
	w.updateHotspotSSID()
	if err := w.initDevices(); err != nil {
		return false, err
	}

	return true, nil
}

// HealthCheck reports if a subsystem is running correctly (it is restarted if not).
func (w *Provisioning) HealthCheck(ctx context.Context) error {
	w.opMu.Lock()
	defer w.opMu.Unlock()

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
		_, err := w.AddOrUpdateConnection(network)
		if err != nil {
			w.logger.Error(errw.Wrapf(err, "error adding network %s", network.SSID))
		}
		if network.Interface != "" && w.Config().HotspotInterface != network.Interface {
			if err := w.ActivateConnection(ctx, network.Interface, network.SSID); err != nil {
				w.logger.Error(err)
			}
		}
	}
}

// must be run inside dataMu lock.
func (w *Provisioning) updateHotspotSSID() {
	w.cfg.hotspotSSID = w.cfg.HotspotPrefix + "-" + strings.ToLower(w.hostname)
	if len(w.cfg.hotspotSSID) > 32 {
		w.cfg.hotspotSSID = w.cfg.hotspotSSID[:32]
	}
}
