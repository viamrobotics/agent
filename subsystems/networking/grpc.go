package networking

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

func (n *Networking) startGRPC() error {
	bind := PortalBindAddr + ":4772"
	lis, err := net.Listen("tcp", bind)
	if err != nil {
		return errw.Wrapf(err, "listening on: %s", bind)
	}

	n.grpcServer = grpc.NewServer(grpc.WaitForHandlers(true))
	pb.RegisterProvisioningServiceServer(n.grpcServer, n)

	n.portalData.workers.Add(1)
	go func() {
		defer n.portalData.workers.Done()
		if err := n.grpcServer.Serve(lis); err != nil {
			n.logger.Error(err)
		}
	}()
	return nil
}

func (n *Networking) GetSmartMachineStatus(ctx context.Context,
	req *pb.GetSmartMachineStatusRequest,
) (*pb.GetSmartMachineStatusResponse, error) {
	n.connState.setLastInteraction()

	ret := &pb.GetSmartMachineStatusResponse{
		ProvisioningInfo: &pb.ProvisioningInfo{
			FragmentId:   n.cfg.FragmentID,
			Model:        n.cfg.Model,
			Manufacturer: n.cfg.Manufacturer,
		},
		HasSmartMachineCredentials: n.connState.getConfigured(),
		IsOnline:                   n.connState.getOnline(),
		Errors:                     n.errListAsStrings(),
	}

	lastSSID := n.netState.LastSSID(n.Config().HotspotInterface)
	if lastSSID != "" {
		lastNetwork := n.netState.Network(n.Config().HotspotInterface, lastSSID)
		lastNetworkInfo := lastNetwork.getInfo()
		ret.LatestConnectionAttempt = NetworkInfoToProto(&lastNetworkInfo)
	}

	// reset the errors, as they were now just displayed
	n.errors.Clear()

	return ret, nil
}

func (n *Networking) SetNetworkCredentials(ctx context.Context,
	req *pb.SetNetworkCredentialsRequest,
) (*pb.SetNetworkCredentialsResponse, error) {
	n.connState.setLastInteraction()

	if req.GetType() != NetworkTypeWifi {
		return nil, errw.Errorf("unknown network type: %s, only %s currently supported", req.GetType(), NetworkTypeWifi)
	}

	n.portalData.mu.Lock()
	defer n.portalData.mu.Unlock()

	n.portalData.Updated = time.Now()
	n.portalData.input.SSID = req.GetSsid()
	n.portalData.input.PSK = req.GetPsk()

	lastSSID := n.netState.LastSSID(n.Config().HotspotInterface)
	if req.GetSsid() == lastSSID && lastSSID != "" {
		lastNetwork := n.netState.LockingNetwork(n.Config().HotspotInterface, lastSSID)
		lastNetwork.mu.Lock()
		lastNetwork.lastError = nil
		lastNetwork.mu.Unlock()
	}

	n.portalData.sendInput(n.connState)

	return &pb.SetNetworkCredentialsResponse{}, nil
}

func (n *Networking) SetSmartMachineCredentials(ctx context.Context,
	req *pb.SetSmartMachineCredentialsRequest,
) (*pb.SetSmartMachineCredentialsResponse, error) {
	n.connState.setLastInteraction()

	cloud := req.GetCloud()
	if cloud == nil {
		return nil, errors.New("request must include a Cloud config section")
	}
	n.portalData.mu.Lock()
	defer n.portalData.mu.Unlock()
	n.portalData.Updated = time.Now()
	n.portalData.input.PartID = cloud.GetId()
	n.portalData.input.Secret = cloud.GetSecret()
	n.portalData.input.AppAddr = cloud.GetAppAddress()

	n.portalData.sendInput(n.connState)

	return &pb.SetSmartMachineCredentialsResponse{}, nil
}

func (n *Networking) GetNetworkList(ctx context.Context,
	req *pb.GetNetworkListRequest,
) (*pb.GetNetworkListResponse, error) {
	n.connState.setLastInteraction()

	visibleNetworks := n.getVisibleNetworks()

	networks := make([]*pb.NetworkInfo, len(visibleNetworks))
	for i, net := range visibleNetworks {
		networks[i] = NetworkInfoToProto(&net)
	}

	return &pb.GetNetworkListResponse{Networks: networks}, nil
}

func (n *Networking) errListAsStrings() []string {
	errList := []string{}

	lastNetwork := n.netState.Network(n.Config().HotspotInterface, n.netState.LastSSID(n.Config().HotspotInterface))

	if lastNetwork.lastError != nil {
		errList = append(errList, fmt.Sprintf("SSID: %s: %s", lastNetwork.ssid, lastNetwork.lastError))
	}

	for _, err := range n.errors.Errors() {
		errList = append(errList, err.Error())
	}
	return errList
}
