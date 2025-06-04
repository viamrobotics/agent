package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/viamrobotics/agent/subsystems/networking"
	pb "go.viam.com/api/provisioning/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func grpcClient() error {
	ctx := context.Background()

	conn, err := grpc.NewClient(opts.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println(err)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()

	client := pb.NewProvisioningServiceClient(conn)

	if opts.Status {
		return GetStatus(ctx, client)
	}

	if opts.Networks {
		return GetNetworks(ctx, client)
	}

	if opts.PartID != "" {
		return SetDeviceCreds(ctx, client, opts.PartID, opts.Secret, opts.AppAddr)
	}

	if opts.SSID != "" {
		return SetWifiCreds(ctx, client, opts.SSID, opts.PSK)
	}

	if opts.Exit {
		_, err = client.ExitProvisioning(ctx, &pb.ExitProvisioningRequest{})
		return err
	}

	return nil
}

func GetStatus(ctx context.Context, client pb.ProvisioningServiceClient) error {
	resp, err := client.GetSmartMachineStatus(ctx, &pb.GetSmartMachineStatusRequest{})
	if err != nil {
		return err
	}

	fmt.Printf("Version: %s, Online: %t, Configured: %t, Provisioning: %v, Last: %v, Errors: %s\n",
		resp.GetAgentVersion(),
		resp.GetIsOnline(),
		resp.GetHasSmartMachineCredentials(),
		resp.GetProvisioningInfo(),
		resp.GetLatestConnectionAttempt(),
		strings.Join(resp.GetErrors(), "\n"),
	)
	return nil
}

func GetNetworks(ctx context.Context, client pb.ProvisioningServiceClient) error {
	resp, err := client.GetNetworkList(ctx, &pb.GetNetworkListRequest{})
	if err != nil {
		return err
	}

	for _, network := range resp.GetNetworks() {
		fmt.Printf("SSID: %s, Signal: %d%%, Security: %s\n", network.GetSsid(), network.GetSignal(), network.GetSecurity())
	}
	return nil
}

func SetDeviceCreds(ctx context.Context, client pb.ProvisioningServiceClient, id, secret, appaddr string) error {
	req := &pb.SetSmartMachineCredentialsRequest{
		Cloud: &pb.CloudConfig{
			Id:         id,
			Secret:     secret,
			AppAddress: appaddr,
		},
	}

	_, err := client.SetSmartMachineCredentials(ctx, req)
	return err
}

func SetWifiCreds(ctx context.Context, client pb.ProvisioningServiceClient, ssid, psk string) error {
	req := &pb.SetNetworkCredentialsRequest{
		Type: networking.NetworkTypeWifi,
		Ssid: ssid,
		Psk:  psk,
	}

	_, err := client.SetNetworkCredentials(ctx, req)
	return err
}
