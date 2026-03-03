//go:build serialtests

package agent_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
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
	APIKeyID   string             `toml:"api_key_id"`
	APIKey     string             `toml:"api_key"`
	RobotID    string             `toml:"robot_id"`
	PartID     string             `toml:"part_id"`
	Versions   versionsCfg        `toml:"versions"`
	SerialPath tomlOption[string] `toml:"serial_path"`
	Wifi       wifiCfg            `toml:"wifi"`
}

type versionsCfg struct {
	Stable           string `toml:"viam_agent_stable"`
	StableURL        string `toml:"viam_agent_stable_url"`
	Old              string `toml:"viam_agent_old"`
	OldAgentURL      string `toml:"viam_agent_old_url"`
	ViamServerOld    string `toml:"viam_server_old"`
	OldViamServerURL string `toml:"viam_server_old_url"`
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
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			defer cancel()
			if _, err := applyAgentVersionPin(ctx, "stable"); err != nil {
				t.Logf("error pinning agent back to stable during cleanup: %v", err)
			}
			if _, err := applyViamServerVersionPin(ctx, "stable"); err != nil {
				t.Logf("error pinning viam-server back to stable during cleanup: %v", err)
			}
			if err := serialClient.Close(); err != nil {
				t.Logf("error closing serial client during cleanup: %v", err)
			}
		})
	}
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	ctx.After(func(c context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		if _, resetErr := applyAgentVersionPin(c, "stable"); resetErr != nil {
			return c, resetErr
		}
		if _, resetErr := applyViamServerVersionPin(c, "stable"); resetErr != nil {
			return c, resetErr
		}
		return c, nil
	})

	const versionGroup = `(an old version|dev|stable|version [^\s]+)`
	ctx.Step(`^viam-agent is installed$`, installAgent)
	ctx.Step(`viam-agent is (not |un)installed$`, removeViam)
	ctx.Step(`the viam-agent systemd unit is enabled`, testAgentEnabled)
	ctx.Step(`the viam-agent systemd unit is running$`, testAgentRunning)
	ctx.Step(fmt.Sprintf(`the viam-agent systemd unit is running with %s$`, versionGroup), testAgentRunningWithVersion)
	ctx.Step(fmt.Sprintf(`the viam-agent systemd unit started with %s`, versionGroup), testSystemdAgentStartVersion)
	ctx.Step(fmt.Sprintf(`viam-agent is pinned to %s`, versionGroup), applyAgentVersionPin)

	// Agent URL/file steps (for agent-url.feature)
	ctx.Step(`viam-agent is pinned to a url$`, applyAgentURLPin)
	ctx.Step(`viam-agent is pinned to a file$`, applyAgentFilePin)
	ctx.Step(`viam-agent is pinned to a viam-server binary$`, applyAgentViamServerBinaryPin)
	ctx.Step(`an old viam-agent binary is present on the device$`, downloadOldAgentBinary)

	// Viam-server version steps (for viamserver-version.feature)
	ctx.Step(fmt.Sprintf(`viam-server is pinned to %s`, versionGroup), applyViamServerVersionPin)
	ctx.Step(fmt.Sprintf(`viam-server is running with %s$`, versionGroup), testViamServerRunningWithVersion)
	ctx.Step(`an old viam-server binary is present on the device$`, downloadOldViamServerBinary)
	ctx.Step(`viam-server is pinned to a url$`, applyViamServerURLPin)
	ctx.Step(`viam-server is pinned to a file$`, applyViamServerFilePin)
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

func testAgentRunningWithVersion(ctx context.Context, version string) (context.Context, error) {
	ctx, err := testSystemdAgentStartVersion(ctx, version)
	if err != nil {
		return ctx, err
	}
	return testAgentState(ctx, "SubState", "running")
}

func testSystemdAgentStartVersion(ctx context.Context, version string) (context.Context, error) {
	versionTest := versionStrToMatcher(version)
	var err error
	// Agent needs time to fetch the new config, possibly download the new
	// version, and restart.
	for i := range 60 {
		if i > 0 {
			time.Sleep(time.Second * 2)
		}
		lastAgentVer := serialClient.GetAgentLastStartVersion()
		if lastAgentVer.IsError() {
			err = lastAgentVer.Error()
			continue
		}
		if check := versionTest(lastAgentVer.MustGet()); check != "" {
			err = errors.New(check)
			continue
		}
		return ctx, nil
	}
	return ctx, err
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

	if root.Fields == nil {
		root.Fields = make(map[string]*structpb.Value)
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

func applyVersionPin(ctx context.Context, versionStr string, path ...string) (context.Context, error) {
	partResp, err := appClient.GetRobotPart(ctx, &apppb.GetRobotPartRequest{
		Id: cfg.PartID,
	})
	if err != nil {
		return ctx, err
	}
	partCfg := partResp.Part.RobotConfig
	if err = setField(partCfg, structpb.NewStringValue(versionStr), path...); err != nil {
		return ctx, err
	}
	_, err = appClient.UpdateRobotPart(ctx, &apppb.UpdateRobotPartRequest{
		Id:          cfg.PartID,
		Name:        partResp.Part.Name,
		RobotConfig: partCfg,
	})
	return ctx, err
}

func applyAgentVersionPin(ctx context.Context, version string) (context.Context, error) {
	versionStr := translateVersionApp(version)
	if version == "stable" && cfg.Versions.StableURL != "" {
		versionStr = cfg.Versions.StableURL
	}
	return applyVersionPin(ctx, versionStr, "agent", "version_control", "agent")
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

// Translate version strings into the format app expects, which allows for some
// magic strings such as "stable"
func translateVersionApp(version string) string {
	switch version {
	case "an old version":
		return cfg.Versions.Old
	case "stable":
		return version
	case "dev":
		return version
	}
	if strings.HasPrefix(version, "version ") {
		return strings.SplitN(version, " ", 2)[1]
	}
	panic(fmt.Sprintf(`unrecognized version format "%s"`, version))
}

// Translate version strings into the format that agent expects/reports.
func versionStrToMatcher(version string) func(string) string {
	switch version {
	case "an old version":
		return func(actual string) string {
			if cfg.Versions.Old == "" {
				panic("must set old version in config")
			}
			return test.ShouldEqual(actual, cfg.Versions.Old)
		}
	case "stable":
		return func(actual string) string {
			if cfg.Versions.Stable == "" {
				panic("must set stable version in config")
			}
			return test.ShouldEqual(actual, cfg.Versions.Stable)
		}
	case "dev":
		return func(actual string) string {
			devRegex := regexp.MustCompile(`-dev\.\d+$`)
			if devRegex.MatchString(actual) {
				return ""
			}
			return fmt.Sprintf(`Expected "%s" to match "%s"`, actual, devRegex.String())
		}
	}
	if strings.HasPrefix(version, "version ") {
		return func(actual string) string {
			return test.ShouldEqual(actual, strings.SplitN(version, " ", 2)[1])
		}
	}
	panic(fmt.Sprintf(`unrecongnized version format "%s"`, version))
}

func translateVersionViamServer(version string) string {
	switch version {
	case "an old version":
		if cfg.Versions.ViamServerOld == "" {
			panic("must set viam_server_old in config")
		}
		return cfg.Versions.ViamServerOld
	case "stable":
		return version
	}
	if strings.HasPrefix(version, "version ") {
		return strings.SplitN(version, " ", 2)[1]
	}
	panic(fmt.Sprintf(`unrecognized viam-server version format "%s"`, version))
}

func versionStrToMatcherViamServer(version string) func(string) string {
	switch version {
	case "an old version":
		return func(actual string) string {
			return test.ShouldEqual(actual, cfg.Versions.ViamServerOld)
		}
	}
	panic(fmt.Sprintf(`unrecognized viam-server version format "%s"`, version))
}

func applyViamServerVersionPin(ctx context.Context, version string) (context.Context, error) {
	return applyVersionPin(ctx, translateVersionViamServer(version), "agent", "version_control", "viam-server")
}

func testViamServerRunningWithVersion(ctx context.Context, version string) (context.Context, error) {
	versionTest := versionStrToMatcherViamServer(version)
	var err error
	for i := range 60 {
		if i > 0 {
			time.Sleep(time.Second * 2)
		}
		lastVer := serialClient.GetViamServerLastStartVersion()
		if lastVer.IsError() {
			err = lastVer.Error()
			continue
		}
		if check := versionTest(lastVer.MustGet()); check != "" {
			err = errors.New(check)
			continue
		}
		return ctx, nil
	}
	return ctx, err
}

func applyViamServerURLPin(ctx context.Context) (context.Context, error) {
	if cfg.Versions.OldViamServerURL == "" {
		return ctx, errors.New("must set old_viam_server_url in config")
	}
	return applyVersionPin(ctx, cfg.Versions.OldViamServerURL, "agent", "version_control", "viam-server")
}

func applyViamServerFilePin(ctx context.Context) (context.Context, error) {
	return applyVersionPin(ctx, "file:///tmp/viam-server-old", "agent", "version_control", "viam-server")
}

func downloadOldViamServerBinary(ctx context.Context) (context.Context, error) {
	if cfg.Versions.OldViamServerURL == "" {
		return ctx, errors.New("must set old_viam_server_url in config")
	}
	return ctx, serialClient.DownloadToDevice(cfg.Versions.OldViamServerURL, "/tmp/viam-server-old").Error()
}

func applyAgentURLPin(ctx context.Context) (context.Context, error) {
	if cfg.Versions.OldAgentURL == "" {
		return ctx, errors.New("must set old_agent_url in config")
	}
	return applyVersionPin(ctx, cfg.Versions.OldAgentURL, "agent", "version_control", "agent")
}

func applyAgentFilePin(ctx context.Context) (context.Context, error) {
	return applyVersionPin(ctx, "file:///tmp/viam-agent-old", "agent", "version_control", "agent")
}

func applyAgentViamServerBinaryPin(ctx context.Context) (context.Context, error) {
	if cfg.Versions.OldViamServerURL == "" {
		return ctx, errors.New("must set old_viam_server_url in config")
	}
	return applyVersionPin(ctx, cfg.Versions.OldViamServerURL, "agent", "version_control", "agent")
}

func downloadOldAgentBinary(ctx context.Context) (context.Context, error) {
	if cfg.Versions.OldAgentURL == "" {
		return ctx, errors.New("must set old_agent_url in config")
	}
	return ctx, serialClient.DownloadToDevice(cfg.Versions.OldAgentURL, "/tmp/viam-agent-old").Error()
}

// tomlOption wraps [mo.Option] such that it can unmarshal config values of all
// the types we care about.
type tomlOption[T any] struct {
	mo.Option[T]
}

// UnmarshalTOML implements [toml.Unmarshaler].
func (t *tomlOption[T]) UnmarshalTOML(val any) error {
	switch v := val.(type) {
	case string:
		return t.UnmarshalText([]byte(`"` + v + `"`))
	}
	panic(fmt.Sprintf("don't know how to unmarshall optional toml value %s", val))
}

var _ toml.Unmarshaler = &tomlOption[string]{}
