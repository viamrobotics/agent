package provisioning

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
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

// SMURF TODO: Register and init
func init() {
	registry.Register(SubsysName, NewProvisioning)
}

// func NewSubsystem(ctx context.Context, logger logging.Logger, updateConf *pb.DeviceSubsystemConfig) (subsystems.Subsystem, error) {
// 	subsys := &NMWrapper{}
// 	return agent.NewAgentSubsystem(ctx, SubsysName, logger, subsys)
// }

type Provisioning struct {
	monitorWorkers      sync.WaitGroup
	provisioningWorkers sync.WaitGroup

	// blocks start/stop/etc operations
	// holders of this lock must use HealthySleep to respond to HealthChecks from the parent agent during long operations
	opMu sync.Mutex

	// only set during NewProvisioning, no lock
	nm          gnm.NetworkManager
	settings    gnm.Settings
	hostname    string
	logger      logging.Logger
	AppCfgPath  string

	// internal locking
	connState *connectionState
	netState  *networkState

	// locking for config updates
	dataMu sync.Mutex
	cfg         Config
	hotspotInterface string // the wifi device used by provisioning and actively managed for connectivity
	hotspotSSID      string


	// SMURF Lock below here...

	errors []error

	// portal
	webServer  *http.Server
	grpcServer *grpc.Server

	input         *UserInput
	inputReceived atomic.Bool
	banner        string
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
		cfg:         *cfg,
		AppCfgPath:  AppConfigFilePath,
		logger:      logger,
		nm:          nm,
		settings:    settings,

		connState:       NewConnectionState(logger),
		netState:       NewNetworkState(logger),
		input:       &UserInput{},
	}

	w.hostname, err = settings.GetPropertyHostname()
	if err != nil {
		return nil, errw.Wrap(err, "error getting hostname from NetworkManager, is NetworkManager installed and enabled?")
	}

	w.hotspotSSID = w.cfg.HotspotPrefix + "-" + strings.ToLower(w.hostname)
	if len(w.hotspotSSID) > 32 {
		w.hotspotSSID = w.hotspotSSID[:32]
	}

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
	if err := w.NetworkScan(ctx); err != nil {
		return nil, err
	}

	w.warnIfMultiplePrimaryNetworks()

	if w.cfg.RoamingMode {
		w.logger.Info("Roaming Mode enabled. Will try all connections for global internet connectivity.")
	} else {
		w.logger.Infof("Default (Single Network) Mode enabled. Will directly connect only to primary network: %s",
			w.netState.PrimarySSID(w.hotspotInterface))
	}

	if err := w.CheckConnections(); err != nil {
		return nil, err
	}

	// Is there a configured wifi network? If so, set last times to now so we use normal timeouts.
	// Otherwise, hotspot will start immediately if not connected, while wifi network might still be booting.
	for _, nw := range w.netState.Networks() {
		if nw.conn != nil && nw.netType == NetworkTypeWifi && (nw.interfaceName == "" || nw.interfaceName == w.hotspotInterface) {
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

	// SMURF background this in a gofunc
	// this will loop indefinitely until context cancellation or serious error
	if err := w.StartMonitoring(ctx); err != nil && !errors.Is(err, context.Canceled) {
		w.logger.Error(err)
	}

	w.logger.Info("agent-provisioning startup complete")
	return nil
}

// SMURF complete these
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
	w.monitorWorkers.Wait()
	return nil
}

// Update validates and/or updates a subsystem, returns true if subsystem should be restarted
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
	w.cfg = *cfg
	return true, nil
}

// HealthCheck reports if a subsystem is running correctly (it is restarted if not)
func (w *Provisioning) HealthCheck(ctx context.Context) error {
	// SMURF implement
	return nil
}

// Version returns the current version of the subsystem
func (w *Provisioning) Version() string {
	return agent.GetRevision()
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
		if network.Interface != "" && w.GetHotspotInterface() != network.Interface {
			if err := w.ActivateConnection(ctx, network.Interface, network.SSID); err != nil {
				w.logger.Error(err)
			}
		}
	}
}