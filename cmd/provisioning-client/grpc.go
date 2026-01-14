package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/viamrobotics/agent/subsystems/networking"
	"github.com/viamrobotics/agent/utils"
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

	if opts.Status || opts.Info {
		if err := GetStatus(ctx, client); err != nil {
			return err
		}
	}

	if opts.Networks {
		if err := GetNetworks(ctx, client); err != nil {
			return err
		}
	}

	if opts.PartID != "" {
		if err := SetDeviceCreds(ctx, client, opts.PartID, opts.Secret, opts.AppAddr, opts.APIKey); err != nil {
			return err
		}
	}

	if opts.WifiSSID != "" {
		if err := SetWifiCreds(ctx, client, opts.WifiSSID, opts.WifiPSK); err != nil {
			return err
		}
	}

	if opts.Exit || opts.WifiSSID != "" || opts.PartID != "" {
		fmt.Println("Sending exit command...")
		_, err = client.ExitProvisioning(ctx, &pb.ExitProvisioningRequest{})
		if err != nil {
			return err
		}
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

func SetDeviceCreds(ctx context.Context, client pb.ProvisioningServiceClient, id, secret, appaddr string, apiKey utils.APIKey) error {
	fmt.Println("Writing device credentials...")
	req := &pb.SetSmartMachineCredentialsRequest{
		Cloud: &pb.CloudConfig{
			Id:         id,
			Secret:     secret,
			AppAddress: appaddr,
		},
	}

	if !apiKey.IsEmpty() {
		req.Cloud.ApiKey = &pb.APIKey{
			Id:  apiKey.ID,
			Key: apiKey.Key,
		}
	}

	_, err := client.SetSmartMachineCredentials(ctx, req)
	return err
}

func SetWifiCreds(ctx context.Context, client pb.ProvisioningServiceClient, ssid, psk string) error {
	fmt.Println("Writing wifi credentials...")
	req := &pb.SetNetworkCredentialsRequest{
		Type: networking.NetworkTypeWifi,
		Ssid: ssid,
		Psk:  psk,
	}

	_, err := client.SetNetworkCredentials(ctx, req)
	return err
}
