//go:build serialtests

package agent_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/cucumber/godog"
	"github.com/samber/mo"
	"github.com/viamrobotics/agent/internal/serialcontrol"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

var serialClient *serialcontrol.Client

type config struct {
	APIKeyID   string  `toml:"api_key_id"`
	APIKey     string  `toml:"api_key"`
	PartID     string  `toml:"part_id"`
	SerialPath string  `toml:"serial_path"`
	Wifi       wifiCfg `toml:"wifi"`
	BLE        bleCfg  `toml:"ble"`
}

type bleCfg struct {
	EnvFile string `toml:"env_file"`
}

type wifiCfg struct {
	SSID     string `toml:"ssid"`
	Password string `toml:"password"`
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
			// setups like the path to the serial device. Panic on any error.
			cfgPath := mo.TupleToOption(os.LookupEnv("AGENT_SERIAL_CFG")).
				OrElse("./agent-test.toml")
			mo.TupleToResult(toml.DecodeFile(cfgPath, &cfg)).MustGet()

			logger := logging.NewTestLogger(t)
			// Set to INFO to see the commands being sent to the terminal, DEBUG to
			// see the commands + any output they produce.
			logger.SetLevel(logging.DEBUG)
			serialClient = serialcontrol.Connect(
				logger,
				mo.EmptyableToOption(cfg.SerialPath).OrElse("/dev/ttyUSB0"),
			).MustGet()
			if err := serialClient.Sudo(); err != nil {
				panic(err)
			}

			if err := serialClient.EnsureOnline(cfg.Wifi.SSID, cfg.Wifi.Password); err != nil {
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
	ctx.Step(`viam-agent is (not |un)installed$`, removeViam)
	ctx.Step(`the viam-agent systemd unit is enabled`, testAgentEnabled)
	ctx.Step(`the viam-agent systemd unit is running`, testAgentRunning)
	ctx.Step(`^viam-agent enters provisioning mode$`, agentEntersProvisioningMode)
	ctx.Step(`^a phone provisions the machine via bluetooth$`, provisionViaBluetooth)
	ctx.Step(`^the device is online$`, deviceIsOnline)
}

func removeViam(ctx context.Context) (context.Context, error) {
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

func agentEntersProvisioningMode(ctx context.Context) (context.Context, error) {
	// Only tear down WiFi if the device is currently online.
	if err := serialClient.CheckOnline(); err == nil {
		serialClient.DeleteWifiConnection(cfg.Wifi.SSID)

		if err := serialClient.ForceProvisioning().Error(); err != nil {
			return ctx, fmt.Errorf("failed to force provisioning: %w", err)
		}

		// Wait for the agent's health loop to pick up the force file and start
		// the hotspot + BLE service. The loop runs every ~10s; 90s is generous.
		time.Sleep(90 * time.Second)
	}
	return ctx, nil
}

func provisionViaBluetooth(ctx context.Context) (context.Context, error) {
	if cfg.BLE.EnvFile == "" {
		return ctx, fmt.Errorf("ble.env_file not set in test config")
	}

	//nolint:gosec // Test-only: URL is a known Viam-owned script.
	cmd := exec.Command("bash", "-c",
		fmt.Sprintf(
			`bash <(curl -fsSL https://raw.githubusercontent.com/viamrobotics/viam_flutter_bluetooth_provisioning_widget/main/scripts/ble_test.sh) %s`,
			cfg.BLE.EnvFile,
		),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return ctx, fmt.Errorf("BLE provisioning test failed: %w", err)
	}
	return ctx, nil
}

func deviceIsOnline(ctx context.Context) (context.Context, error) {
	// After BLE provisioning the agent should reconnect on its own.
	// EnsureOnline will also attempt to reconnect WiFi as a fallback.
	// TODO: replace with an app API call (e.g. get robot status) for
	// stronger verification that provisioning actually succeeded.
	return ctx, serialClient.EnsureOnline(cfg.Wifi.SSID, cfg.Wifi.Password)
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
