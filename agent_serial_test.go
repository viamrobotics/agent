//go:build serialtests

package agent_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/cucumber/godog"
	"github.com/samber/mo"
	"github.com/samber/mo/result"
	"github.com/viamrobotics/agent/internal/serialcontrol"
	apppb "go.viam.com/api/app/v1"
	"go.viam.com/rdk/logging"
	rutils "go.viam.com/rdk/utils"
	"go.viam.com/test"
	"go.viam.com/utils/rpc"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	serialClient *serialcontrol.Client
	appClient    apppb.AppServiceClient
)

type config struct {
	APIKeyID   string            `toml:"api_key_id"`
	APIKey     string            `toml:"api_key"`
	RobotID    string            `toml:"robot_id"`
	PartID     string            `toml:"part_id"`
	SerialPath mo.Option[string] `toml:"serial_path"`
	Wifi       wifiCfg           `toml:"wifi"`
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
			logger.SetLevel(logging.WARN)
			serialClient = serialcontrol.Connect(
				logger,
				cfg.SerialPath.OrElse("/dev/ttyUSB0"),
			).MustGet()

			appClient = dialApp(t.Context(), logger, "app.viam.com:443", cfg.APIKeyID, cfg.APIKey).MustGet()

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
			ctx, cancel := context.WithTimeout(context.Background(), time.Second * 10)
			defer cancel()
			applyAgentVersionPin(ctx, "stable")
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
	ctx.Step(`the viam-agent systemd unit started with ([^\s)]+)`, testSystemdAgentStartVersion)
	ctx.Step(`viam-agent is pinned to ([^\s)]+)`, applyAgentVersionPin)
}

func removeViam(ctx context.Context) (context.Context, error) {
	if err := serialClient.RemoveViam().Error(); err != nil {
		return ctx, err
	}
	return testAgentState(ctx, "LoadState", "not-found")
}

func installAgent(ctx context.Context) (context.Context, error) {
	agentStatus := serialClient.GetAgentStatus().MustGet()
	if agentStatus["SubState"] == "running" {
		// Avoid wasting time and network traffic if agent is already running.
		return ctx, nil
	}
	robotKeysResp, err := appClient.GetRobotAPIKeys(ctx, &apppb.GetRobotAPIKeysRequest{
		RobotId: cfg.RobotID,
	})
	if err != nil {
		return ctx, err
	}
	robotKeys := robotKeysResp.ApiKeys[0]
	return ctx, serialClient.InstallViam(
		cfg.PartID,
		robotKeys.ApiKey.Id,
		robotKeys.ApiKey.Key,
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

// setField sets a field nested in an arbitrarily deep tree of
// [*structpb.Struct]s to the provided [*structpb.Value]. Any intermediary
// fields that do not exist or are set to types other than structpb.Struct will
// be overwritten.
func setField(root *structpb.Struct, value *structpb.Value, path ...string) error {
	if len(path) < 1 {
		return nil
	}

	fields := root.Fields
	for _, p := range path[:len(path)-1] {
		next := fields[p].GetStructValue()
		if next == nil {
			var err error
			next, err = structpb.NewStruct(nil)
			if err != nil {
				return err
			}
			fields[p] = structpb.NewStructValue(next)
		}
		fields = next.Fields
	}
	fields[path[len(path)-1]] = value
	return nil
}

func applyAgentVersionPin(ctx context.Context, version string) (context.Context, error) {
	partResp, err := appClient.GetRobotPart(ctx, &apppb.GetRobotPartRequest{
		Id: cfg.PartID,
	})
	if err != nil {
		return ctx, err
	}
	partCfg := partResp.Part.RobotConfig
	err = setField(partCfg, structpb.NewStringValue(version), "agent", "version_control", "agent")
	if err != nil {
		return ctx, err
	}

	_, err = appClient.UpdateRobotPart(ctx, &apppb.UpdateRobotPartRequest{
		Id:          cfg.PartID,
		Name:        partResp.Part.Name,
		RobotConfig: partCfg,
	})

	return ctx, err
}

func testSystemdAgentStartVersion(ctx context.Context, version string) (context.Context, error) {
	var err error
	// Agent needs time to fetch the new config, possibly download the new
	// version, and restart.
	for i := range 30 {
		if i > 0 {
			time.Sleep(time.Second * 2)
		}
		lastAgentVer := serialClient.GetAgentLastStartVersion()
		if lastAgentVer.IsError() {
			return ctx, lastAgentVer.Error()
		}
		if check := test.ShouldEqual(lastAgentVer.MustGet(), version); check != "" {
			err = errors.New(check)
			continue
		}
		return ctx, nil
	}
	return ctx, err
}

func dialApp(ctx context.Context, logger logging.Logger, address string, keyID, key string) mo.Result[apppb.AppServiceClient] {
	dialopts := []rpc.DialOption{
		rpc.WithEntityCredentials(
			keyID,
			rpc.Credentials{Type: rutils.CredentialsTypeAPIKey, Payload: key},
		),
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, time.Second*10)
	defer dialCancel()
	return result.Pipe1(
		mo.TupleToResult(rpc.DialDirectGRPC(dialCtx, address, logger, dialopts...)),
		result.Map(func(conn rpc.ClientConn) apppb.AppServiceClient {
			return apppb.NewAppServiceClient(conn)
		}),
	)
}
