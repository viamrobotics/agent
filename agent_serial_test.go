//go:build serialtests

package agent_test

import (
	"context"
	"encoding/json/v2"
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
	APIKeyID   string            `json:"apiKeyID"`
	APIKey     string            `json:"apiKey"`
	PartID     string            `json:"partID"`
	SerialPath mo.Option[string] `json:"serialPath"`
}

var cfg config

func TestSerialFeatures(t *testing.T) {
	suite := godog.TestSuite{
		TestSuiteInitializer: InitializeSuite(t),
		ScenarioInitializer:  InitializeScenario,
		Options: &godog.Options{
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
			cfgFile := mo.TupleToResult(os.Open(cfgPath)).MustGet()
			if err := json.UnmarshalRead(cfgFile, &cfg); err != nil {
				panic(err)
			}

			logger := logging.NewTestLogger(t)
			// Set to INFO to see the commands being sent to the terminal, DEBUG to
			// see the commands + any output they produce.
			logger.SetLevel(logging.WARN)
			serialClient = serialcontrol.Connect(logger, cfg.SerialPath.OrElse("/dev/ttyUSB0")).MustGet()
			serialClient.Sudo().MustGet()
		})
		tsc.AfterSuite(func() {
			if res := serialClient.Close(); res.IsError() {
				t.Error("closing serial client", res.Error())
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

func uninstallAgent(ctx context.Context, prefixMatch string) (context.Context, error) {
	if err := serialClient.RemoveViam().Error(); err != nil {
		return ctx, err
	}
	if prefixMatch == "not " {
		// If the step is phrased as "is not installed" then double check that the
		// uninstallation succeeded.
		return testAgentState(ctx, "LoadState", "not-found")
	}
	return ctx, nil
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
