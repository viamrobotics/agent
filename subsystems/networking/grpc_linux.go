package networking

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	pb "go.viam.com/api/provisioning/v1"
	"google.golang.org/grpc"
)

func (n *Networking) startGRPC(bindAddr string, bindPort int) error {
	bind := net.JoinHostPort(bindAddr, strconv.Itoa(bindPort))
	lis, err := net.Listen("tcp", bind)
	if err != nil {
		return errw.Wrapf(err, "listening on: %s", bind)
	}

	n.dataMu.Lock()
	n.grpcServer = grpc.NewServer(grpc.WaitForHandlers(true))
	n.dataMu.Unlock()
	pb.RegisterProvisioningServiceServer(n.grpcServer, n)

	n.portalData.workers.Add(1)
	go func() {
		defer utils.Recover(n.logger, func(_ any) {
			if err := n.stopProvisioning(); err != nil {
				n.logger.Warn(err)
			}
		})
		defer n.portalData.workers.Done()
		if err := n.grpcServer.Serve(lis); err != nil {
			n.logger.Warn(err)
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
			FragmentId:   n.Config().FragmentID,
			Model:        n.Config().Model,
			Manufacturer: n.Config().Manufacturer,
		},
		HasSmartMachineCredentials: n.connState.getConfigured(),
		IsOnline:                   n.connState.getOnline(),
		Errors:                     n.errListAsStrings(),
		AgentVersion:               utils.GetVersion(),
	}

	lastSSID := n.netState.LastSSID(n.Config().HotspotInterface)
	if lastSSID != "" {
		lastNetwork := n.netState.Network(n.netState.GenNetKey(NetworkTypeWifi, "", lastSSID))
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

	n.portalData.input.SSID = req.GetSsid()
	n.portalData.input.PSK = req.GetPsk()

	lastSSID := n.netState.LastSSID(n.Config().HotspotInterface)
	if req.GetSsid() == lastSSID && lastSSID != "" {
		lastNetwork := n.netState.LockingNetwork(n.netState.GenNetKey(NetworkTypeWifi, "", lastSSID))
		lastNetwork.mu.Lock()
		lastNetwork.lastError = nil
		lastNetwork.mu.Unlock()
	}

	return &pb.SetNetworkCredentialsResponse{}, nil
}

func (n *Networking) ExitProvisioning(ctx context.Context, req *pb.ExitProvisioningRequest) (*pb.ExitProvisioningResponse, error) {
	n.portalData.sendInput(ctx)
	return &pb.ExitProvisioningResponse{}, nil
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
	n.portalData.input.PartID = cloud.GetId()
	n.portalData.input.Secret = cloud.GetSecret()
	n.portalData.input.AppAddr = cloud.GetAppAddress()

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

	lastNetwork := n.netState.Network(
		n.netState.GenNetKey(NetworkTypeWifi, "", n.netState.LastSSID(n.Config().HotspotInterface)),
	)

	if lastNetwork.lastError != nil {
		errList = append(errList, fmt.Sprintf("SSID: %s: %s", lastNetwork.ssid, lastNetwork.lastError))
	}

	for _, err := range n.errors.Errors() {
		errList = append(errList, err.Error())
	}
	return errList
}
