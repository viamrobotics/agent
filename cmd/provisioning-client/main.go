package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/jessevdk/go-flags"
	"github.com/viamrobotics/agent/subsystems/provisioning"
	pb "go.viam.com/api/provisioning/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	ctx := context.TODO()

	var opts struct {
		Address string `description:"Address/port to dial (ex: 'localhost:4772')" long:"address" short:"a"`

		SSID string `description:"SSID to set"           long:"ssid"`
		PSK  string `description:"PSK/Password for wifi" long:"psk"`

		AppAddr string `default:"https://app.viam.com:443"              description:"Cloud address to set in viam.json" long:"appaddr"`
		PartID  string `description:"PartID to set in viam.json"        long:"partID"`
		Secret  string `description:"Device secret to set in viam.json" long:"secret"`

		Status   bool `description:"Get device status"      long:"status"   short:"s"`
		Networks bool `description:"List networks"          long:"networks" short:"n"`
		Help     bool `description:"Show this help message" long:"help"     short:"h"`
	}

	parser := flags.NewParser(&opts, flags.IgnoreUnknown)
	parser.Usage = "runs as a background service and manages updates and the process lifecycle for viam-server."

	_, err := parser.Parse()
	if err != nil {
		panic(err)
	}

	if opts.Address == "" || (opts.PartID == "" && opts.SSID == "" && !opts.Networks && !opts.Status) {
		opts.Help = true
	}

	if opts.Help {
		var b bytes.Buffer
		parser.WriteHelp(&b)

		fmt.Println(b.String())
		return
	}

	if opts.PartID != "" || opts.Secret != "" {
		if opts.PartID == "" || opts.Secret == "" || opts.AppAddr == "" {
			fmt.Println("Error: Must set both Secret and PartID (and optionally AppAddr) at the same time!")
			return
		}
	}

	conn, err := grpc.Dial(opts.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
		GetStatus(ctx, client)
	}

	if opts.Networks {
		GetNetworks(ctx, client)
	}

	if opts.PartID != "" {
		SetDeviceCreds(ctx, client, opts.PartID, opts.Secret, opts.AppAddr)
	}

	if opts.SSID != "" {
		SetWifiCreds(ctx, client, opts.SSID, opts.PSK)
	}
}

func GetStatus(ctx context.Context, client pb.ProvisioningServiceClient) {
	resp, err := client.GetSmartMachineStatus(ctx, &pb.GetSmartMachineStatusRequest{})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Online: %t, Configured: %t, Provisioning: %v, Last: %v, Errors: %s\n",
		resp.GetIsOnline(),
		resp.GetHasSmartMachineCredentials(),
		resp.GetProvisioningInfo(),
		resp.GetLatestConnectionAttempt(),
		strings.Join(resp.GetErrors(), "\n"),
	)
}

func GetNetworks(ctx context.Context, client pb.ProvisioningServiceClient) {
	resp, err := client.GetNetworkList(ctx, &pb.GetNetworkListRequest{})
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, network := range resp.GetNetworks() {
		fmt.Printf("SSID: %s, Signal: %d%%, Security: %s\n", network.GetSsid(), network.GetSignal(), network.GetSecurity())
	}
}

func SetDeviceCreds(ctx context.Context, client pb.ProvisioningServiceClient, id, secret, appaddr string) {
	req := &pb.SetSmartMachineCredentialsRequest{
		Cloud: &pb.CloudConfig{
			Id:         id,
			Secret:     secret,
			AppAddress: appaddr,
		},
	}

	_, err := client.SetSmartMachineCredentials(ctx, req)
	if err != nil {
		fmt.Println("Error setting device credentials ", err)
		return
	}
}

func SetWifiCreds(ctx context.Context, client pb.ProvisioningServiceClient, ssid, psk string) {
	req := &pb.SetNetworkCredentialsRequest{
		Type: provisioning.NetworkTypeWifi,
		Ssid: ssid,
		Psk:  psk,
	}

	_, err := client.SetNetworkCredentials(ctx, req)
	if err != nil {
		fmt.Println("Error setting wifi credentials ", err)
		return
	}
}
