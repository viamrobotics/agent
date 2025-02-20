// A simple test client to fetch and print the results of DeviceAgentConfig() for use when testing changes in App.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/jessevdk/go-flags"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/rdk/logging"
	"go.viam.com/utils/rpc"
	"google.golang.org/protobuf/encoding/prototext"
)

func main() {
	ctx := context.TODO()
	logger := logging.NewLogger("agent-test-client")

	var opts struct {
		Config   string `description:"Path to credentials (viam.json)" long:"config"                             required:"true" short:"c"`
		Platform string `default:"linux/arm64"                         description:"Platform to send in request" long:"platform" short:"p"`
		Help     bool   `description:"Show this help message"          long:"help"                               short:"h"`
	}
	parser := flags.NewParser(&opts, flags.IgnoreUnknown)
	parser.Usage = "Makes a DeviceAgentConfigRequest() and prints the return"
	_, err := parser.Parse()
	if err != nil {
		logger.Error(err)
		opts.Help = true
	}

	if opts.Help {
		var b bytes.Buffer
		parser.WriteHelp(&b)

		//nolint:forbidigo
		fmt.Println(b.String())
		return
	}

	cloudConfig, err := loadCredentials(opts.Config)
	if err != nil {
		logger.Fatal(err)
	}

	client, err := dial(ctx, logger, cloudConfig)
	if err != nil {
		logger.Fatal(err)
	}

	err = fetchAgentConfig(ctx, client, cloudConfig, opts.Platform)
	if err != nil {
		logger.Fatal(err)
	}
}

func fetchAgentConfig(ctx context.Context, client pb.AgentDeviceServiceClient, cloudConfig *logging.CloudConfig, platform string) error {
	req := &pb.DeviceAgentConfigRequest{
		Id: cloudConfig.ID,
		HostInfo: &pb.HostInfo{
			Platform: platform,
		},
		VersionInfo: &pb.VersionInfo{
			AgentRunning: "testClient",
		},
	}

	resp, err := client.DeviceAgentConfig(ctx, req)
	if err != nil {
		return err
	}

	text, err := prototext.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(resp)
	if err != nil {
		return err
	}

	//nolint:forbidigo
	fmt.Printf("DeviceAgentConfig() Response:\n%s\n", text)
	return nil
}

func loadCredentials(path string) (*logging.CloudConfig, error) {
	//nolint:gosec
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := make(map[string]map[string]string)
	err = json.Unmarshal(b, &cfg)
	if err != nil {
		return nil, err
	}

	cloud, ok := cfg["cloud"]
	if !ok {
		return nil, fmt.Errorf("no cloud section in file %s", path)
	}

	for _, req := range []string{"app_address", "id", "secret"} {
		field, ok := cloud[req]
		if !ok {
			return nil, fmt.Errorf("no cloud config field for %s", field)
		}
	}

	cloudConfig := &logging.CloudConfig{
		AppAddress: cloud["app_address"],
		ID:         cloud["id"],
		Secret:     cloud["secret"],
	}

	return cloudConfig, nil
}

func dial(ctx context.Context, logger logging.Logger, cloudConfig *logging.CloudConfig) (pb.AgentDeviceServiceClient, error) {
	u, err := url.Parse(cloudConfig.AppAddress)
	if err != nil {
		logger.Fatal(err)
	}

	dialOpts := make([]rpc.DialOption, 0, 2)
	// Only add credentials when secret is set.
	if cloudConfig.Secret != "" {
		dialOpts = append(dialOpts, rpc.WithEntityCredentials(cloudConfig.ID,
			rpc.Credentials{
				Type:    "robot-secret",
				Payload: cloudConfig.Secret,
			},
		))
	}

	if u.Scheme == "http" {
		dialOpts = append(dialOpts, rpc.WithInsecure())
	}

	conn, err := rpc.DialDirectGRPC(ctx, u.Host, logger.AsZap(), dialOpts...)
	if err != nil {
		return nil, err
	}

	return pb.NewAgentDeviceServiceClient(conn), nil
}
