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
		return errw.Wrapf(err, "error listening on: %s", bind)
	}

	w.grpcServer = grpc.NewServer(grpc.WaitForHandlers(true))
	pb.RegisterProvisioningServiceServer(w.grpcServer, w)

	w.provisioningWorkers.Add(1)
	go func() {
		defer w.provisioningWorkers.Done()
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

	lastSSID := w.netState.LastSSID(w.hotspotInterface)
	if lastSSID != "" {
	lastNetwork := w.netState.Network(w.hotspotInterface, lastSSID)
		lastNetworkInfo := lastNetwork.getInfo()
		ret.LatestConnectionAttempt = NetworkInfoToProto(&lastNetworkInfo)
	}

	// reset the errors, as they were now just displayed
	// SMURF need locking func
	w.errors = nil

	return ret, nil
}

func (w *Provisioning) SetNetworkCredentials(ctx context.Context,
	req *pb.SetNetworkCredentialsRequest,
) (*pb.SetNetworkCredentialsResponse, error) {
	w.connState.setLastInteraction()

	if req.GetType() != NetworkTypeWifi {
		return nil, errw.Errorf("unknown network type: %s, only %s currently supported", req.GetType(), NetworkTypeWifi)
	}

	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	// SMURF input locking
	w.input.Updated = time.Now()
	w.input.SSID = req.GetSsid()
	w.input.PSK = req.GetPsk()
	w.inputReceived.Store(true)

	lastSSID := w.netState.LastSSID(w.hotspotInterface)
	if req.GetSsid() == lastSSID && lastSSID != "" {
		lastNetwork := w.netState.LockingNetwork(w.hotspotInterface, lastSSID)
		lastNetwork.mu.Lock()
		lastNetwork.lastError = nil
		lastNetwork.mu.Unlock()
	}

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
	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	w.input.Updated = time.Now()
	w.input.PartID = cloud.GetId()
	w.input.Secret = cloud.GetSecret()
	w.input.AppAddr = cloud.GetAppAddress()
	w.inputReceived.Store(true)

	return &pb.SetSmartMachineCredentialsResponse{}, nil
}

func (w *Provisioning) GetNetworkList(ctx context.Context,
	req *pb.GetNetworkListRequest,
) (*pb.GetNetworkListResponse, error) {
	w.connState.setLastInteraction()

	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	visibleNetworks := w.getVisibleNetworks()

	networks := make([]*pb.NetworkInfo, len(visibleNetworks))
	for i, net := range visibleNetworks {
		networks[i] = NetworkInfoToProto(&net)
	}

	return &pb.GetNetworkListResponse{Networks: networks}, nil
}

func (w *Provisioning) errListAsStrings() []string {
	errList := []string{}

	lastNetwork := w.netState.Network(w.hotspotInterface, w.netState.LastSSID(w.hotspotInterface))

	if lastNetwork.lastError != nil {
		errList = append(errList, fmt.Sprintf("SSID: %s: %s", lastNetwork.ssid, lastNetwork.lastError))
	}

	// SMURF lock errors
	for _, err := range w.errors {
		errList = append(errList, err.Error())
	}
	return errList
}
