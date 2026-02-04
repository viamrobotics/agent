//go:build serialtests

package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/cucumber/godog"
	"github.com/samber/mo"
	"github.com/viamrobotics/agent/internal/serialcontrol"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

var serialClient *serialcontrol.Client

type config struct {
	APIKeyID   string             `json:"api_key_id"`
	APIKey     string             `json:"api_key"`
	PartID     string             `json:"part_id"`
	SerialPath mo.Option[string]  `json:"serial_path"`
	Wifi       mo.Option[wifiCfg] `json:"wifi"`
}

type wifiCfg struct {
	SSID     string `json:"ssid"`
	Password string `json:"password"`
}

var cfg config

func TestSerialFeatures(t *testing.T) {
	suite := godog.TestSuite{
		TestSuiteInitializer: InitializeSuite(t),
		ScenarioInitializer:  InitializeScenario,
		Options: &godog.Options{
			// Options at time of writing: cucumber, events, junit, pretty, progress
			Format:   "pretty",
			Paths:    []string{"features/serial"},
			TestingT: t,
			Strict:   true,
		},
	}

	if exit := suite.Run(); exit != 0 {
		t.Fatalf("non-zero exit of from serial features test suite %v", exit)
	}
}

func InitializeSuite(t *testing.T) func(*godog.TestSuiteContext) {
	return func(tsc *godog.TestSuiteContext) {
		t.Helper()
		tsc.BeforeSuite(func() {
			// Load config file + store it in global variable. This contains secrets
			// like the app API key as well as parameters that could change between
			// setups like the path to the serial device.
			cfgPath := mo.TupleToOption(os.LookupEnv("AGENT_SERIAL_CFG")).
				OrElse("./agent-test.json")
			cfgData := mo.TupleToResult(os.ReadFile(cfgPath)).MustGet()
			if err := json.Unmarshal(cfgData, &cfg); err != nil {
				panic(err)
			}

			logger := logging.NewTestLogger(t)
			// Set to INFO to see the commands being sent to the terminal, DEBUG to
			// see the commands + any output they produce.
			logger.SetLevel(logging.WARN)
			serialClient = serialcontrol.Connect(logger, cfg.SerialPath.OrElse("/dev/ttyUSB0")).MustGet()
			if err := serialClient.Sudo(); err != nil {
				panic(err)
			}

			wifi := cfg.Wifi.OrEmpty()
			if err := serialClient.EnsureOnline(wifi.SSID, wifi.Password); err != nil {
				// The AfterSuite hook doesn't run if we panic here so try to restore the terminal state manually
				serialClient.Close()
				// Setup failed, panic
				panic(err)
			}
		})
		tsc.AfterSuite(func() {
			if err := serialClient.Close(); err != nil {
				t.Error("closing serial client", err)
			}
		})
	}
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	ctx.Step(`^viam-agent is installed$`, installAgent)
	ctx.Step(`viam-agent is (not |un)installed$`, uninstallAgent)
	ctx.Step(`the viam-agent systemd unit is enabled`, testAgentEnabled)
	ctx.Step(`the viam-agent systemd unit is running`, testAgentRunning)
}

func uninstallAgent(ctx context.Context) (context.Context, error) {
	if err := serialClient.RemoveViam().Error(); err != nil {
		return ctx, err
	}
	return testAgentState(ctx, "LoadState", "not-found")
}

func installAgent(ctx context.Context) (context.Context, error) {
	return ctx, serialClient.InstallViam(
		cfg.PartID,
		cfg.APIKeyID,
		cfg.APIKey,
	).Error()
}

func testAgentEnabled(ctx context.Context) (context.Context, error) {
	return testAgentState(ctx, "UnitFileState", "enabled")
}

func testAgentRunning(ctx context.Context) (context.Context, error) {
	return testAgentState(ctx, "SubState", "running")
}

func testAgentState(ctx context.Context, key, expectedVal string) (context.Context, error) {
	statusRes := serialClient.GetAgentStatus()
	if statusRes.IsError() {
		return ctx, statusRes.Error()
	}
	status := statusRes.MustGet()[key]
	if check := test.ShouldEqual(status, expectedVal); check != "" {
		return ctx, errors.New(check)
	}
	return ctx, nil
}
