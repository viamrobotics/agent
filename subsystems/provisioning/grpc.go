package provisioning

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	errw "github.com/pkg/errors"
	pb "go.viam.com/api/provisioning/v1"
	"google.golang.org/grpc"
)

func (w *Provisioning) startGRPC() error {
	bind := PortalBindAddr + ":4772"
	lis, err := net.Listen("tcp", bind)
	if err != nil {
		return errw.Wrapf(err, "listening on: %s", bind)
	}

	w.grpcServer = grpc.NewServer(grpc.WaitForHandlers(true))
	pb.RegisterProvisioningServiceServer(w.grpcServer, w)

	w.portalData.workers.Add(1)
	go func() {
		defer w.portalData.workers.Done()
		if err := w.grpcServer.Serve(lis); err != nil {
			w.logger.Error(err)
		}
	}()
	return nil
}

func (w *Provisioning) GetSmartMachineStatus(ctx context.Context,
	req *pb.GetSmartMachineStatusRequest,
) (*pb.GetSmartMachineStatusResponse, error) {
	w.connState.setLastInteraction()

	ret := &pb.GetSmartMachineStatusResponse{
		ProvisioningInfo: &pb.ProvisioningInfo{
			FragmentId:   w.cfg.FragmentID,
			Model:        w.cfg.Model,
			Manufacturer: w.cfg.Manufacturer,
		},
		HasSmartMachineCredentials: w.connState.getConfigured(),
		IsOnline:                   w.connState.getOnline(),
		Errors:                     w.errListAsStrings(),
	}

	lastSSID := w.netState.LastSSID(w.Config().HotspotInterface)
	if lastSSID != "" {
		lastNetwork := w.netState.Network(w.Config().HotspotInterface, lastSSID)
		lastNetworkInfo := lastNetwork.getInfo()
		ret.LatestConnectionAttempt = NetworkInfoToProto(&lastNetworkInfo)
	}

	// reset the errors, as they were now just displayed
	w.errors.Clear()

	return ret, nil
}

func (w *Provisioning) SetNetworkCredentials(ctx context.Context,
	req *pb.SetNetworkCredentialsRequest,
) (*pb.SetNetworkCredentialsResponse, error) {
	w.connState.setLastInteraction()

	if req.GetType() != NetworkTypeWifi {
		return nil, errw.Errorf("unknown network type: %s, only %s currently supported", req.GetType(), NetworkTypeWifi)
	}

	w.portalData.mu.Lock()
	defer w.portalData.mu.Unlock()

	w.portalData.Updated = time.Now()
	w.portalData.input.SSID = req.GetSsid()
	w.portalData.input.PSK = req.GetPsk()

	lastSSID := w.netState.LastSSID(w.Config().HotspotInterface)
	if req.GetSsid() == lastSSID && lastSSID != "" {
		lastNetwork := w.netState.LockingNetwork(w.Config().HotspotInterface, lastSSID)
		lastNetwork.mu.Lock()
		lastNetwork.lastError = nil
		lastNetwork.mu.Unlock()
	}

	w.portalData.sendInput(w.connState)

	return &pb.SetNetworkCredentialsResponse{}, nil
}

func (w *Provisioning) SetSmartMachineCredentials(ctx context.Context,
	req *pb.SetSmartMachineCredentialsRequest,
) (*pb.SetSmartMachineCredentialsResponse, error) {
	w.connState.setLastInteraction()

	cloud := req.GetCloud()
	if cloud == nil {
		return nil, errors.New("request must include a Cloud config section")
	}
	w.portalData.mu.Lock()
	defer w.portalData.mu.Unlock()
	w.portalData.Updated = time.Now()
	w.portalData.input.PartID = cloud.GetId()
	w.portalData.input.Secret = cloud.GetSecret()
	w.portalData.input.AppAddr = cloud.GetAppAddress()

	w.portalData.sendInput(w.connState)

	return &pb.SetSmartMachineCredentialsResponse{}, nil
}

func (w *Provisioning) GetNetworkList(ctx context.Context,
	req *pb.GetNetworkListRequest,
) (*pb.GetNetworkListResponse, error) {
	w.connState.setLastInteraction()

	visibleNetworks := w.getVisibleNetworks()

	networks := make([]*pb.NetworkInfo, len(visibleNetworks))
	for i, net := range visibleNetworks {
		networks[i] = NetworkInfoToProto(&net)
	}

	return &pb.GetNetworkListResponse{Networks: networks}, nil
}

func (w *Provisioning) errListAsStrings() []string {
	errList := []string{}

	lastNetwork := w.netState.Network(w.Config().HotspotInterface, w.netState.LastSSID(w.Config().HotspotInterface))

	if lastNetwork.lastError != nil {
		errList = append(errList, fmt.Sprintf("SSID: %s: %s", lastNetwork.ssid, lastNetwork.lastError))
	}

	for _, err := range w.errors.Errors() {
		errList = append(errList, err.Error())
	}
	return errList
}
