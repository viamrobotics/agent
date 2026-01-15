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
	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
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

	var cfg map[string]interface{}
	err = json.Unmarshal(b, &cfg)
	if err != nil {
		return nil, err
	}

	cloud, ok := cfg["cloud"].(map[string]interface{})
	if !ok {
		return nil, errw.Errorf("no cloud section in file %s", path)
	}

	appAddress, ok := cloud["app_address"].(string)
	if !ok || appAddress == "" {
		return nil, errw.New("field 'app_address' in cloud config must be a non-empty string")
	}

	id, ok := cloud["id"].(string)
	if !ok || id == "" {
		return nil, errw.New("field 'id' in cloud config must be a non-empty string")
	}

	cloudCreds, err := utils.ParseCloudCreds(cloud)
	if err != nil {
		return nil, err
	}

	cloudConfig := &logging.CloudConfig{
		AppAddress: appAddress,
		ID:         id,
		CloudCred:  cloudCreds,
	}

	return cloudConfig, nil
}

func dial(ctx context.Context, logger logging.Logger, cloudConfig *logging.CloudConfig) (pb.AgentDeviceServiceClient, error) {
	u, err := url.Parse(cloudConfig.AppAddress)
	if err != nil {
		logger.Fatal(err)
	}

	dialOpts := make([]rpc.DialOption, 0, 2)

	// Only add credentials when they are set.
	if cloudConfig.CloudCred != nil {
		dialOpts = append(dialOpts, cloudConfig.CloudCred)
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
