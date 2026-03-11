//go:build serialtests

package agent_test

import (
	"context"
	_ "embed"
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

//go:embed uninstall.sh
var uninstallScript string

var (
	serialClient *serialcontrol.Client
	appClient    apppb.AppServiceClient
	deviceArch   string
)

type config struct {
	APIKeyID   string             `toml:"api_key_id"`
	APIKey     string             `toml:"api_key"`
	RobotID    string             `toml:"robot_id"`
	PartID     string             `toml:"part_id"`
	Versions   versionsCfg        `toml:"versions"`
	SerialPath tomlOption[string] `toml:"serial_path"`
	SerialUser string             `toml:"serial_user"`
	SerialPass string             `toml:"serial_pass"`
	Wifi       wifiCfg            `toml:"wifi"`
}

type versionsCfg struct {
	Stable           string `toml:"viam_agent_stable"`
	Old              string `toml:"viam_agent_old"`
	ViamServerStable string `toml:"viam_server_stable"`
	ViamServerOld    string `toml:"viam_server_old"`
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

			// Log in
			if err := serialClient.Login(cfg.SerialUser, cfg.SerialPass); err != nil {
				serialClient.Close()
				panic(fmt.Errorf("login failed: %w", err))
			}

			appClient = dialApp(t.Context(), logger, "app.viam.com:443", cfg.APIKeyID, cfg.APIKey).MustGet()

			if err := serialClient.Sudo(); err != nil {
				panic(err)
			}
			deviceArch = serialClient.GetDeviceArch().MustGet()

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
	const versionGroup = `(an old version|dev|stable|version [^\s]+)`

	// Restart viam-agent before each scenario (if it is running) so that every
	// scenario starts with a fresh systemd InvocationID. This ensures that
	// journal-based checks cannot match log lines produced by a previous scenario.
	ctx.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		status := serialClient.GetAgentStatus()
		if status.IsOk() && status.MustGet()["SubState"] == "running" {
			if err := serialClient.RestartAgent().Error(); err != nil {
				return ctx, err
			}
		}
		return ctx, nil
	})

	// Agent utility steps
	ctx.Step(`^viam-agent is installed$`, installAgent)
	ctx.Step(`viam-agent is (not |un)installed$`, removeViam)
	ctx.Step(`the viam-agent systemd unit is enabled`, testAgentEnabled)
	ctx.Step(`the viam-agent systemd unit is running$`, testAgentRunning)

	// Agent upgrade/downgrade steps (version/URL/file)
	ctx.Step(fmt.Sprintf(`the viam-agent systemd unit is running with %s$`, versionGroup), testAgentRunningWithVersion)
	ctx.Step(fmt.Sprintf(`the viam-agent systemd unit started with %s`, versionGroup), testSystemdAgentStartVersion)
	ctx.Step(fmt.Sprintf(`viam-agent is pinned to %s`, versionGroup), applyAgentVersionPin)
	ctx.Step(`viam-agent is pinned to a url$`, applyAgentURLPin)
	ctx.Step(`viam-agent is pinned to a file$`, applyAgentFilePin)
	ctx.Step(`viam-agent is pinned to a viam-server binary$`, applyAgentViamServerBinaryPin)
	ctx.Step(`viam-agent rejected the invalid binary$`, testAgentRejectedInvalidBinary)
	ctx.Step(`an old viam-agent binary is present on the device$`, downloadOldAgentBinary)

	// Viam-server upgrade/down steps (version/URL/file)
	ctx.Step(fmt.Sprintf(`viam-server is running with %s$`, versionGroup), testViamServerRunningWithVersion)
	ctx.Step(fmt.Sprintf(`viam-server is pinned to %s`, versionGroup), applyViamServerVersionPin)
	ctx.Step(`viam-server is pinned to a url$`, applyViamServerURLPin)
	ctx.Step(`viam-server is pinned to a file$`, applyViamServerFilePin)
	ctx.Step(`an old viam-server binary is present on the device$`, downloadOldViamServerBinary)
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

// gcsURL constructs the GCS download URL for a viam binary given its subsystem
// name (e.g. "viam-agent", "viam-server"), version string, and device arch.
func gcsURL(subsystem, version string) string {
	return fmt.Sprintf(
		"https://storage.googleapis.com/packages.viam.com/apps/%s/%s-v%s-%s",
		subsystem, subsystem, version, deviceArch,
	)
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

// translateVersion translates a version string into the format app expects.
// oldVersion is the concrete version string to use for the string "an old version".
func translateVersion(version, oldVersion string) string {
	switch version {
	case "an old version":
		if oldVersion == "" {
			panic("must set old version in config")
		}
		return oldVersion
	case "stable", "dev":
		return version
	}
	if strings.HasPrefix(version, "version ") {
		return strings.SplitN(version, " ", 2)[1]
	}
	panic(fmt.Sprintf(`unrecognized version format "%s"`, version))
}

// versionStrToMatcherBase returns a matcher function for a version string.
// oldVersion and stableVersion are the concrete version strings to compare
// against for "an old version" and "stable" respectively.
func versionStrToMatcherBase(version, oldVersion, stableVersion string) func(string) string {
	switch version {
	case "an old version":
		return func(actual string) string {
			if oldVersion == "" {
				panic("must set old version in config")
			}
			return test.ShouldEqual(actual, oldVersion)
		}
	case "stable":
		return func(actual string) string {
			if stableVersion == "" {
				panic("must set stable version in config")
			}
			return test.ShouldEqual(actual, stableVersion)
		}
	case "dev":
		return func(actual string) string {
			devRegex := regexp.MustCompile(`-dev\.\d+(-[0-9a-f]+)?$`)
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
	panic(fmt.Sprintf(`unrecognized version format "%s"`, version))
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
	ctx.Step(`the viam-agent systemd unit is dead$`, testAgentDead)
	ctx.Step(`the viam-agent systemd unit is not found$`, testAgentNotFound)
	ctx.Step(`the viam files have all been removed`, testViamFilesRemoved)
}

func removeViam(ctx context.Context) (context.Context, error) {
	if err := serialClient.RunScript(uninstallScript, "FORCE=1 sh").Error(); err != nil {
		return ctx, err
	}
	return testAgentState(ctx, "LoadState", "not-found")
}

func testViamFilesRemoved(ctx context.Context) (context.Context, error) {
	// get the list of files to check from the uninstall script itself
	// this keeps us from having to repeat every single file in the test
	var paths []string

	for _, line := range strings.Split(uninstallScript, "\n") {
		trimmed := strings.TrimSpace(line)

		if !strings.HasPrefix(trimmed, "rm ") {
			continue
		}

		for _, part := range strings.Fields(trimmed)[1:] {
			if strings.HasPrefix(part, "#") {
				break
			}
			if strings.HasPrefix(part, "-") {
				continue
			}
			paths = append(paths, part)
		}
	}

	// build a script that checks if any of the paths still exist
	var checkScript strings.Builder
	for _, p := range paths {
		fmt.Fprintf(&checkScript, "test -e %s && echo \"EXISTS: %s\"\n", p, p)
	}

	output := serialClient.RunScript(checkScript.String(), "sh")
	if output.IsError() {
		return ctx, output.Error()
	}

	for _, line := range output.MustGet() {
		if strings.HasPrefix(line, "EXISTS: ") {
			return ctx, fmt.Errorf("expected file to be removed but it still exists: %s", strings.TrimPrefix(line, "EXISTS: "))
		}
	}

	return ctx, nil
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

func testAgentDead(ctx context.Context) (context.Context, error) {
	return testAgentState(ctx, "SubState", "dead")
}

func testAgentNotFound(ctx context.Context) (context.Context, error) {
	return testAgentState(ctx, "LoadState", "not-found")
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

func translateToAppVersion(version string) string {
	return translateVersion(version, cfg.Versions.Old)
}

func versionStrToMatcher(version string) func(string) string {
	return versionStrToMatcherBase(version, cfg.Versions.Old, cfg.Versions.Stable)
}

func applyAgentVersionPin(ctx context.Context, version string) (context.Context, error) {
	return applyVersionPin(ctx, translateToAppVersion(version), "agent", "version_control", "agent")
}

func applyAgentURLPin(ctx context.Context) (context.Context, error) {
	if cfg.Versions.Old == "" {
		return ctx, errors.New("must set viam_agent_old in config")
	}
	return applyVersionPin(ctx, gcsURL("viam-agent", cfg.Versions.Old), "agent", "version_control", "agent")
}

func applyAgentFilePin(ctx context.Context) (context.Context, error) {
	return applyVersionPin(ctx, "file:///tmp/viam-agent-old", "agent", "version_control", "agent")
}

func applyAgentViamServerBinaryPin(ctx context.Context) (context.Context, error) {
	if cfg.Versions.ViamServerOld == "" {
		return ctx, errors.New("must set viam_server_old in config")
	}
	return applyVersionPin(ctx, gcsURL("viam-server", cfg.Versions.ViamServerOld), "agent", "version_control", "agent")
}

func testAgentRejectedInvalidBinary(ctx context.Context) (context.Context, error) {
	return ctx, serialClient.WaitForAgentBinaryRejection()
}

func downloadOldAgentBinary(ctx context.Context) (context.Context, error) {
	if cfg.Versions.Old == "" {
		return ctx, errors.New("must set viam_agent_old in config")
	}
	return ctx, serialClient.DownloadToDevice(gcsURL("viam-agent", cfg.Versions.Old), "/tmp/viam-agent-old").Error()
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

func translateVersionViamServer(version string) string {
	return translateVersion(version, cfg.Versions.ViamServerOld)
}

func versionStrToMatcherViamServer(version string) func(string) string {
	return versionStrToMatcherBase(version, cfg.Versions.ViamServerOld, cfg.Versions.ViamServerStable)
}

func applyViamServerVersionPin(ctx context.Context, version string) (context.Context, error) {
	return applyVersionPin(ctx, translateVersionViamServer(version), "agent", "version_control", "viam-server")
}

func applyViamServerURLPin(ctx context.Context) (context.Context, error) {
	if cfg.Versions.ViamServerOld == "" {
		return ctx, errors.New("must set viam_server_old in config")
	}
	return applyVersionPin(ctx, gcsURL("viam-server", cfg.Versions.ViamServerOld), "agent", "version_control", "viam-server")
}

func applyViamServerFilePin(ctx context.Context) (context.Context, error) {
	return applyVersionPin(ctx, "file:///tmp/viam-server-old", "agent", "version_control", "viam-server")
}

func downloadOldViamServerBinary(ctx context.Context) (context.Context, error) {
	if cfg.Versions.ViamServerOld == "" {
		return ctx, errors.New("must set viam_server_old in config")
	}
	return ctx, serialClient.DownloadToDevice(gcsURL("viam-server", cfg.Versions.ViamServerOld), "/tmp/viam-server-old").Error()
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
