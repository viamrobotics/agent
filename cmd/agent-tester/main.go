package main

import (
	"encoding/json/v2"
	"fmt"
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/samber/mo"
	"github.com/viamrobotics/agent/internal/serialcontrol"
	"go.viam.com/rdk/logging"
)

type config struct {
	APIKeyID string `json:"apiKeyID"`
	APIKey   string `json:"apiKey"`
	PartID   string `json:"partID"`
}

func main() {
	// _, cancel := signal.NotifyContext(context.Background())
	// defer cancel()

	logger := logging.NewLogger("agent-tester")

	opts := &options{}
	parser := flags.NewParser(opts, flags.IgnoreUnknown)
	_, err := parser.Parse()
	if err != nil {
		panic(err)
	}
	if opts.Help {
		parser.WriteHelp(os.Stdout)
		return
	}

	cfg := &config{}
	cfgFile, err := os.Open(opts.ConfigPath)
	if err != nil {
		panic(err)
	}
	if err := json.UnmarshalRead(cfgFile, cfg); err != nil {
		panic(err)
	}

	serialClient := serialcontrol.Connect(logger).MustGet()
	//nolint: errcheck
	defer serialClient.Close()

	testAgentInstall(serialClient, cfg.PartID, cfg.APIKeyID, cfg.APIKey)
}

func testAgentInstall(serialClient *serialcontrol.Client, partID, keyID, key string) mo.Result[any] {
	serialClient.Sudo().MustGet()
	serialClient.RemoveViam().MustGet()
	agentStatus := serialClient.GetAgentStatus().MustGet()
	if ls := agentStatus["LoadState"]; ls != "not-found" {
		panic(fmt.Sprintf("Expected systemd load state of not-found but got %s", ls))
	}
	serialClient.InstallViam(partID, keyID, key)
	agentStatus = serialClient.GetAgentStatus().MustGet()
	if ls := agentStatus["LoadState"]; ls != "loaded" {
		panic(fmt.Sprintf("Expected systemd load state of loaded but got %s", ls))
	}
	return mo.Ok[any](nil)
}
