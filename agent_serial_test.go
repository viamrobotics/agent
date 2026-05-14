//go:build serialtests

package agent_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/cucumber/godog"
	"github.com/samber/mo"
	"github.com/samber/mo/result"
	"github.com/viamrobotics/agent/internal/serialcontrol"
	"github.com/viamrobotics/agent/subsystems/networking"
	apppb "go.viam.com/api/app/v1"
	pb "go.viam.com/api/provisioning/v1"
	"go.viam.com/rdk/logging"
	rutils "go.viam.com/rdk/utils"
	"go.viam.com/test"
	"go.viam.com/utils/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

//go:embed uninstall.sh
var uninstallScript string

//go:embed install.sh
var installScript string

var (
	serialClient        *serialcontrol.Client
	appClient           apppb.AppServiceClient
	logger              logging.Logger
	deviceArch          string
	hostName            string
	concreteTestVersion string
)

type config struct {
	APIKeyID string      `toml:"api_key_id"`
	APIKey   string      `toml:"api_key"`
	RobotID  string      `toml:"robot_id"`
	PartID   string      `toml:"part_id"`
	Serial   serialCfg   `toml:"serial"`
	Versions versionsCfg `toml:"versions"`
	Wifi     wifiCfg     `toml:"wifi"`
}

type versionsCfg struct {
	Test             string `toml:"viam_agent_test"`
	Stable           string `toml:"viam_agent_stable"`
	Old              string `toml:"viam_agent_old"`
	ViamServerTest   string `toml:"viam_server_test"`
	ViamServerStable string `toml:"viam_server_stable"`
	ViamServerOld    string `toml:"viam_server_old"`
}

type serialCfg struct {
	Path tomlOption[string] `toml:"serial_path"`
	User string             `toml:"serial_user"`
	Pass string             `toml:"serial_pass"`
}

type wifiCfg struct {
	SSID         string `toml:"ssid"`
	Password     string `toml:"password"`
	SSIDInsecure string `toml:"ssid_insecure"`
}

// expected agent Bluetooth Low Energy characteristics
var agentBleChars = []string{
	"61eba4df-b901-502c-b278-fadf9d52802b (networks)",
	"37a720ee-86e5-55a8-b876-d200fb7e4f72 (ssid)",
	"10cd57f1-01bb-5937-89fb-64cc40be53d2 (exit_provisioning)",
	"49d34f00-cf76-55fa-9f8d-23f6836136ab (manufacturer)",
	"ea8a8689-548f-5941-829b-82aeff8095b7 (status)",
	"96a4bebb-a361-5c73-9d76-45a0faa9d4a0 (unlock_pairing)",
	"c2be234e-1975-5e85-b97b-bb30c3bf43d2 (id)",
	"444ee2b0-b3fa-5d74-bb35-f194642188b3 (app_address)",
	"cd5b8fb9-4006-56e5-a78b-044cf6ae48cb (psk)",
	"70bc8310-68ca-5011-9282-72f201293dfb (pub_key)",
	"f30e26d6-155c-5a24-bd7f-6b1a40e463da (api_key)",
	"d2eae9e8-30bc-5fdf-bd9f-bd4e8a4017d2 (fragment_id)",
	"d0029d11-a8c2-5231-8fcc-83de66952f01 (secret)",
	"6e164616-ee96-5835-b199-115ddbcd885f (agent_version)",
	"e7e1ac15-fb59-54ab-8538-72008ad4ee43 (model)",
	"75f64044-b604-5547-a723-7f8618255ddc (errors)",
}

var cfg config

// cache the last BLE status because performing BLE scans with the provisioning client is slow
var lastBleStatus []string

func TestSerialFeatures(t *testing.T) {
	suite := godog.TestSuite{
		TestSuiteInitializer: InitializeSuite(t),
		ScenarioInitializer:  InitializeScenario,
		Options: &godog.Options{
			// Options at time of writing: cucumber, events, junit, pretty, progress
			Format:   "pretty",
			Paths:    []string{"features/serial"},
			Tags:     serialTestTags(),
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

			logger = logging.NewTestLogger(t)
			// Set to INFO to see the commands being sent to the terminal, DEBUG to
			// see the commands + any output they produce.
			logger.SetLevel(logging.WARN)
			serialClient = serialcontrol.Connect(
				logger,
				cfg.Serial.Path.OrElse("/dev/ttyUSB0"),
			).MustGet()

			// Log in
			if err := serialClient.Login(cfg.Serial.User, cfg.Serial.Pass); err != nil {
				serialClient.Close()
				panic(fmt.Errorf("login failed: %w", err))
			}

			appClientRes := dialApp(t.Context(), logger, "app.viam.com:443", cfg.APIKeyID, cfg.APIKey)
			if appClientRes.IsError() {
				panic(fmt.Errorf("failed to dial app (is the test runner online?): %w", appClientRes.Error()))
			}
			appClient = appClientRes.MustGet()

			if err := serialClient.Sudo(); err != nil {
				panic(err)
			}
			deviceArch = serialClient.GetDeviceArch().MustGet()
			hostName = serialClient.GetHostName().MustGet()

			if err := serialClient.EnsureOnline(cfg.Wifi.SSID, cfg.Wifi.Password); err != nil {
				// The AfterSuite hook doesn't run if we panic here so try to restore the terminal state manually
				serialClient.Close()
				// Setup failed, panic
				panic(err)
			}
		})
		tsc.AfterSuite(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
			defer cancel()
			if runtime.GOOS == "darwin" {
				if _, err := hostEnsureOnline(ctx); err != nil {
					t.Logf("error restoring host connection to internet during cleanup: %v", err)
				}
			}
			// Just wait after reconnecting everything to make sure all the connections are back
			time.Sleep(time.Second * 3)
			// Pin back to the version under test
			if _, err := applyAgentVersionPin(ctx, "the version under test"); err != nil {
				t.Logf("error pinning agent back to \"%s\" during cleanup: %v", cfg.Versions.ViamServerTest, err)
			}
			if _, err := applyViamServerVersionPin(ctx, "the version under test"); err != nil {
				t.Logf("error pinning viam-server back to \"%s\" during cleanup: %v", cfg.Versions.ViamServerTest, err)
			}
			if err := serialClient.Close(); err != nil {
				t.Logf("error closing serial client during cleanup: %v", err)
			}
		})
	}
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	const versionGroup = `(an old version|dev|stable|the version under test|version [^\s]+)`

	// Restart viam-agent before each scenario (if it is running) so that every
	// scenario starts with a fresh systemd InvocationID. This ensures that
	// journal-based checks cannot match log lines produced by a previous scenario.
	ctx.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		if cfg.Versions.Test != "" {
			concrete, err := resolveVersionSpec(ctx, cfg.Versions.Test)
			concreteTestVersion = concrete
			logger.Infof("Version under test: %s\n", concreteTestVersion)
			if err != nil {
				panic(fmt.Errorf("resolving install version %q: %w", cfg.Versions.Test, err))
			}
		} else {
			panic(fmt.Errorf("viam_agent_test in agent-test.toml cannot be empty string"))
		}
		status := serialClient.GetAgentStatus()
		if status.IsOk() && status.MustGet()["SubState"] == "running" {
			if err := serialClient.RestartAgent().Error(); err != nil {
				return ctx, err
			}
		}

		centerPrint := func(msg string, width int) {
			padLenTotal := width - len(msg)
			padLeft := padLenTotal / 2
			padRight := padLenTotal - padLeft

			fmt.Printf("%s%s%s\n", strings.Repeat(" ", padLeft), msg, strings.Repeat(" ", padRight))
		}

		testMsgs := []string{
			fmt.Sprintf("Testing Agent Version: %s (%s)", cfg.Versions.Test, concreteTestVersion),
			fmt.Sprintf("Stable Agent Version: %s", cfg.Versions.Stable),
			fmt.Sprintf("Testing Server Version: %s", cfg.Versions.ViamServerTest),
			fmt.Sprintf("Stable Server Version: %s", cfg.Versions.ViamServerStable),
		}
		consoleWidth := len(slices.MaxFunc(testMsgs, func(a, b string) int { return len(a) - len(b) })) + 8
		fmt.Println(strings.Repeat("=", consoleWidth))
		fmt.Println(strings.Repeat("=", consoleWidth))
		centerPrint(testMsgs[0], consoleWidth)
		fmt.Println()
		for _, m := range testMsgs[1:] {
			centerPrint(m, consoleWidth)
		}
		fmt.Println(strings.Repeat("=", consoleWidth))
		fmt.Println(strings.Repeat("=", consoleWidth))
		return ctx, nil
	})

	// Agent utility steps
	ctx.Step(fmt.Sprintf(`^viam-agent is installed at %s$`, versionGroup), installAgent)
	ctx.Step(`viam-agent is (not |un)installed$`, uninstallAgent)
	ctx.Step(`the viam-agent systemd unit is enabled`, testAgentEnabled)
	ctx.Step(`the viam-agent systemd unit is running$`, testAgentRunning)
	ctx.Step(`the viam-agent systemd unit is dead$`, testAgentDead)
	ctx.Step(`the viam-agent systemd unit is not found$`, testAgentNotFound)
	ctx.Step(`the viam files have all been removed`, testViamFilesRemoved)
	ctx.Step(`the journald config is live$`, testJournaldConfigLoaded)
	ctx.Step(`the wifi power save config is live$`, testWifiPowerSaveConfigLoaded)

	// Wifi provisioning
	ctx.Step(`there are no available wifi networks`, testClearWifiConnections)
	ctx.Step(`viam-agent is connected to a network`, testEnsureOnline)
	ctx.Step(`viam-agent is in forced provisioning mode`, testForceProvisioningMode)
	ctx.Step(`the provisioning hotspot (is|comes) up`, testProvisioningHotspotEnablesWithinTimeout)
	ctx.Step(`the host shares a secure wifi network via the hotspot`, testSendSecureConnectionInfo)
	ctx.Step(`the host shares an insecure wifi network via the hotspot`, testSendInsecureConnectionInfo)
	ctx.Step(`the host shares an invalid wifi network via the hotspot`, testSendInvalidConnectionInfo)
	ctx.Step(`the provisioning hotspot (goes away|is not up)`, testProvisioningHotspotDisables)
	ctx.Step(`viam-agent can reach the app`, testAgentCanReachApp)
	ctx.Step(`viam-agent cannot reach the app`, testAgentCannotReachApp)

	// Bluetooth provisioning
	ctx.Step(`the viam-agent bluetooth device (is|becomes) discoverable`, testBleIsDiscoverable)
	ctx.Step(`the host shares an insecure wifi network via bluetooth`, testBleSendInsecureConnectionInfo)
	ctx.Step(`the host shares a secure wifi network via bluetooth`, testBleSendSecureConnectionInfo)
	ctx.Step(`the host shares invalid wifi credentials for a valid SSID via bluetooth`, testBleSendInvalidPasswordConnectionInfo)
	ctx.Step(`the host shares an invalid SSID via bluetooth`, testBleSendInvalidSSIDConnectionInfo)
	ctx.Step(`viam-agent surfaces an invalid SSID error via bluetooth`, testBleSurfacesInvalidSSIDError)
	ctx.Step(`viam-agent surfaces an invalid credentials error via bluetooth`, testBleSurfacesInvalidCredentialsErr)

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

	ctx.After(func(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		if runtime.GOOS == "darwin" {
			if _, err := hostEnsureOnline(ctx); err != nil {
				return ctx, err
			}
		}
		return ctx, nil
	})
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

func hostEnsureOnline(ctx context.Context) (context.Context, error) {
	cmd := exec.CommandContext(ctx, "bash", "cmd/test-client/test_provisioning_connect_host.sh")
	cmd.Env = append(os.Environ(), "SSID="+cfg.Wifi.SSID, "PASSWORD="+cfg.Wifi.Password)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ctx, fmt.Errorf("failed to reconnect host: %w\n%s", err, out)
	}
	return ctx, nil
}

// Concrete-version shapes that gcsURL recognizes:
//   - prVersionRe:  "<base>-pr.<N>.<sha>"   (PR dev-release; lives in prerelease/pr-<N>/)
//   - devVersionRe: "<base>-dev.<N>"        (main-branch dev build; lives in prerelease/)
//   - anything else is treated as a stable release at the top of apps/<subsystem>/.
var (
	prVersionRe  = regexp.MustCompile(`^[^-]+-pr\.(\d+)\.[a-f0-9]{40}$`)
	devVersionRe = regexp.MustCompile(`^[^-]+-dev\.\d+$`)
)

// gcsURL constructs the GCS download URL for a viam binary given its subsystem
// name (e.g. "viam-agent", "viam-server") and a concrete version string. It
// routes PR and dev versions to the prerelease subdirectories.
func gcsURL(subsystem, version string) string {
	if m := prVersionRe.FindStringSubmatch(version); m != nil {
		return fmt.Sprintf(
			"https://storage.googleapis.com/packages.viam.com/apps/%s/prerelease/pr-%s/%s-v%s-%s",
			subsystem, m[1], subsystem, version, deviceArch,
		)
	}
	if devVersionRe.MatchString(version) {
		return fmt.Sprintf(
			"https://storage.googleapis.com/packages.viam.com/apps/%s/prerelease/%s-v%s-%s",
			subsystem, subsystem, version, deviceArch,
		)
	}
	return fmt.Sprintf(
		"https://storage.googleapis.com/packages.viam.com/apps/%s/%s-v%s-%s",
		subsystem, subsystem, version, deviceArch,
	)
}

// resolveVersionSpec turns a TOML version specifier into a concrete version
// string. Recognized forms:
//   - "stable"  -> latest stable release       (e.g. "0.27.3")
//   - "dev"     -> latest main-branch dev build (e.g. "0.27.3-dev.5")
//   - "pr.<N>"  -> latest dev-release for PR N  (e.g. "0.27.3-pr.227.<sha>")
//   - anything else is assumed to already be concrete and returned as-is.
//
// Only viam-agent specifiers are supported today; viam-server has different
// upload paths and would need its own resolver.
func resolveVersionSpec(ctx context.Context, spec string) (string, error) {
	switch {
	case spec == "stable":
		return latestStableRelease(ctx)
	case spec == "dev":
		b, err := latestDevBuild(ctx)
		if err != nil {
			return "", err
		}
		return b, nil
	case strings.HasPrefix(spec, "pr."):
		n, err := strconv.Atoi(strings.TrimPrefix(spec, "pr."))
		if err != nil {
			return "", fmt.Errorf("invalid pr specifier %q: %w", spec, err)
		}
		base, sha, err := latestPRBuild(ctx, n)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s-pr.%d.%s", base, n, sha), nil
	default:
		return spec, nil
	}
}

// gcsListItem is the trimmed shape of a GCS JSON list response entry.
type gcsListItem struct {
	Name        string    `json:"name"`
	TimeCreated time.Time `json:"timeCreated"`
}

// listGCS lists viam-agent objects under prefix in the public packages bucket,
// sorted newest-first by upload time.
func listGCS(ctx context.Context, prefix string) ([]gcsListItem, error) {
	listURL := "https://storage.googleapis.com/storage/v1/b/packages.viam.com/o" +
		"?prefix=" + prefix +
		"&fields=items(name,timeCreated)"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GCS list %q returned %s", prefix, resp.Status)
	}
	var body struct {
		Items []gcsListItem `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	sort.Slice(body.Items, func(i, j int) bool {
		return body.Items[i].TimeCreated.After(body.Items[j].TimeCreated)
	})
	return body.Items, nil
}

// latestStableRelease returns the most recently uploaded stable viam-agent
// release version (bare semver, e.g. "0.27.3").
func latestStableRelease(ctx context.Context) (string, error) {
	items, err := listGCS(ctx, "apps/viam-agent/viam-agent-v")
	if err != nil {
		return "", err
	}
	// Stable filenames are exactly "viam-agent-v<MAJOR>.<MINOR>.<PATCH>-<arch>".
	pat := regexp.MustCompile(`/viam-agent-v(\d+\.\d+\.\d+)-[^/]+$`)
	for _, it := range items {
		if m := pat.FindStringSubmatch(it.Name); m != nil {
			return m[1], nil
		}
	}
	return "", errors.New("no stable releases found")
}

// latestDevBuild returns the most recently uploaded main-branch dev build
// version (e.g. "0.27.3-dev.5").
func latestDevBuild(ctx context.Context) (string, error) {
	items, err := listGCS(ctx, "apps/viam-agent/prerelease/viam-agent-v")
	if err != nil {
		return "", err
	}
	pat := regexp.MustCompile(`/viam-agent-v([^-]+-dev\.\d+)-[^/]+$`)
	for _, it := range items {
		if m := pat.FindStringSubmatch(it.Name); m != nil {
			return m[1], nil
		}
	}
	return "", errors.New("no dev builds found")
}

// latestPRBuild returns the base version and 40-char head SHA of the most
// recently uploaded dev-release build for the given PR number.
func latestPRBuild(ctx context.Context, prNum int) (base, sha string, err error) {
	items, err := listGCS(ctx, fmt.Sprintf("apps/viam-agent/prerelease/pr-%d/", prNum))
	if err != nil {
		return "", "", err
	}
	if len(items) == 0 {
		return "", "", fmt.Errorf("no dev-release artifacts found for PR %d", prNum)
	}
	pat := regexp.MustCompile(
		fmt.Sprintf(`/viam-agent-v([^-]+)-pr\.%d\.([a-f0-9]{40})-`, prNum),
	)
	for _, it := range items {
		if m := pat.FindStringSubmatch(it.Name); m != nil {
			return m[1], m[2], nil
		}
	}
	return "", "", fmt.Errorf("no parsable binary names found for PR %d", prNum)
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
		if next.Fields == nil {
			next.Fields = make(map[string]*structpb.Value)
		}
		fields = next.Fields
	}
	fields[path[len(path)-1]] = value
	return nil
}

// translateVersion translates a "version string" into the format app expects.
// A "version string" here is the string used to vaguely specify a version in the godog test
// and is not an actual version specification like the one used in a viam robot config.

// oldVersion is the concrete version string to use for the string "an old version".
// testVersion is the concrete version string to use for the string "test".
func translateVersion(version, oldVersion, testVersion string) string {
	switch version {
	case "an old version":
		if oldVersion == "" {
			panic("must set old version in config")
		}
		return oldVersion
	case "stable", "dev":
		return version
	case "the version under test":
		if testVersion == "" {
			panic("must set test version in config")
		}
		return testVersion
	}
	if strings.HasPrefix(version, "version ") {
		return strings.SplitN(version, " ", 2)[1]
	}
	panic(fmt.Sprintf(`unrecognized version format "%s"`, version))
}

// versionStrToMatcherBase returns a matcher function for a version string.
// oldVersion and stableVersion are the concrete version strings to compare
// against for "an old version" and "stable" respectively.
func versionStrToMatcherBase(version, oldVersion, stableVersion, testVersion string) func(string) string {
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
	case "the version under test":
		if strings.HasPrefix(concreteTestVersion, "file://") {
			return func(actual string) string {
				if testVersion == "" {
					panic("must set test version in config")
				}
				return test.ShouldEqual(actual, "custom")
			}
		} else {
			return func(actual string) string {
				if testVersion == "" {
					panic("must set test version in config")
				}
				return test.ShouldEqual(actual, concreteTestVersion)
			}
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
	logger.Infof("Pinning agent to version: %s\n", versionStr)
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

func uninstallAgent(ctx context.Context) (context.Context, error) {
	if err := serialClient.RunScript(uninstallScript, "FORCE=1 sh").Error(); err != nil {
		return ctx, err
	}
	return testAgentState(ctx, "LoadState", "not-found")
}

func testViamFilesRemoved(ctx context.Context) (context.Context, error) {
	// get the list of files to check from the uninstall script itself
	// this keeps us from having to repeat every single file in the test
	paths := []string{
		"/etc/systemd/system/viam-agent.service",
		"/usr/local/lib/systemd/system/viam-agent.service",
		"/etc/systemd/system/viam-server.service",
		"/usr/local/bin/viam-server",
		"/etc/NetworkManager/conf.d/80-viam.conf",
		"/etc/NetworkManager/dnsmasq-shared.d/80-viam.conf",
		"/etc/systemd/journald.conf.d/90-viam.conf",
		"/etc/viam-provisioning.json",
		"/etc/viam-defaults.json",
		"/root/.viam/",
		"/etc/viam.json",
		"/opt/viam/",
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

func testJournaldConfigLoaded(ctx context.Context) (context.Context, error) {
	var err error
	for i := range 10 {
		if i > 0 {
			time.Sleep(time.Second * 1)
		}
		// get the PID of the actively running journald process
		pidRes := serialClient.RunCmd(`systemctl show systemd-journald --property=MainPID`)
		if pidRes.IsError() {
			err = pidRes.Error()
			continue
		}
		pidString := strings.Join(pidRes.MustGet(), " ")
		journalPid := strings.SplitN(pidString, "=", 2)[1]

		// Check the journald logs for log lines from this actively running systemd-journald process.
		// The lines contain the path and the max allowed storage
		res := serialClient.RunScript(
			fmt.Sprintf(`journalctl --no-pager -u systemd-journald --output=short-monotonic 2>&1 | grep %s | grep "System Journal"`, journalPid),
			"sh",
		)
		if res.IsError() {
			err = res.Error()
			continue
		}
		output := strings.Join(res.MustGet(), "\n")
		if !strings.Contains(output, "/var/log/journal/") {
			err = fmt.Errorf("journald not using persistent storage, got: %s", output)
			continue
		}
		if !strings.Contains(output, "max 512") {
			err = fmt.Errorf("journald not using expected max size, got: %s", output)
			continue
		}
		return ctx, nil
	}
	return ctx, fmt.Errorf("journald config not loaded after timeout: %w", err)
}

func testWifiPowerSaveConfigLoaded(ctx context.Context) (context.Context, error) {
	const wifiPowerSaveFilepath = "/etc/NetworkManager/conf.d/81-viam-wifi-powersave.conf"
	var err error
	for i := range 30 {
		if i > 0 {
			time.Sleep(time.Second * 2)
		}
		res := serialClient.RunScript(
			fmt.Sprintf("test -f %s && echo EXISTS", wifiPowerSaveFilepath),
			"sh",
		)
		if res.IsError() {
			err = res.Error()
			continue
		}
		output := strings.Join(res.MustGet(), "")
		if !strings.Contains(output, "EXISTS") {
			err = fmt.Errorf("wifi power save config not found at %s", wifiPowerSaveFilepath)
			continue
		}
		return ctx, nil
	}
	return ctx, fmt.Errorf("wifi power save config not loaded after timeout: %w", err)
}

func testClearWifiConnections(ctx context.Context) (context.Context, error) {
	clearRes := serialClient.ClearWifiConnections()
	if clearRes.Error() != nil {
		return ctx, clearRes.Error()
	}
	// just sleep a bit after deleting the networks to give network manager time to settle
	time.Sleep(time.Second * 3)
	output := serialClient.ListWifiConnections()
	return ctx, output.Error()
}

func testEnsureOnline(ctx context.Context) (context.Context, error) {
	if err := serialClient.EnsureOnline(cfg.Wifi.SSID, cfg.Wifi.Password); err != nil {
		return ctx, err
	}
	return ctx, nil
}

func testForceProvisioningMode(ctx context.Context) (context.Context, error) {
	output := serialClient.ForceProvisioning()
	return ctx, output.Error()
}

func testProvisioningHotspotEnablesWithinTimeout(ctx context.Context) (context.Context, error) {
	// Try to connect to the provisioning hotspot in a retry loop, return success if joined successfully.
	startTime := time.Now()

	provTimeout := 150 * time.Second

	hotspotName := fmt.Sprintf("viam-setup-%s", hostName)

	var lastOut string
	for time.Now().Before(startTime.Add(provTimeout)) {
		cmd := exec.Command("networksetup", "-setairportnetwork", "en0", hotspotName, "viamsetup")

		out, err := cmd.CombinedOutput()
		outStr := string(out)
		// this rarely happens, err is only non-nil when the cmd fails to run at all
		if err != nil {
			return ctx, fmt.Errorf("joining provisioning hotspot failed: %w\n%s", err, out)
		}
		// we can't check return codes because networksetup always returns 0, even when it fails to join
		if outStr == "" {
			// if the network is joined, the output is just an empty string
			// sleep for a bit before going on to give the connection time to settle
			time.Sleep(3 * time.Second)
			return ctx, nil
		}
		lastOut = outStr
		// sleep for a bit between attempts
		time.Sleep(1 * time.Second)
	}
	return ctx, fmt.Errorf("joining provisioning hotspot failed: timeout after %v seconds: %s", provTimeout, lastOut)
}

func testProvisioningHotspotDisables(ctx context.Context) (context.Context, error) {
	// Try to connect to the provisioning hotspot in a retry loop, return success if it's not found
	startTime := time.Now()

	provTimeout := 150 * time.Second

	hotspotName := fmt.Sprintf("viam-setup-%s", hostName)

	var lastOut string
	for time.Now().Before(startTime.Add(provTimeout)) {
		cmd := exec.Command("networksetup", "-setairportnetwork", "en0", hotspotName, "viamsetup")

		out, err := cmd.CombinedOutput()
		outStr := string(out)
		if err != nil {
			return ctx, fmt.Errorf("joining provisioning hotspot failed: %w\n%s", err, out)
		}
		if strings.Contains(outStr, "Could not find network") {
			// success is an empty return
			return ctx, nil
		} else if outStr == "" {
			// This means we joined the hotspot, so disconnect from it by toggling the adapter
			// and removing it as a preferred network.
			cmdOff := exec.Command("networksetup", "-setairportpower", "en0", "off")
			if outOff, errOff := cmdOff.CombinedOutput(); errOff != nil {
				return ctx, fmt.Errorf("joining provisioning hotspot failed while turning off adapter: %w\n%s", errOff, outOff)
			}
			time.Sleep(100 * time.Millisecond)
			cmdRm := exec.Command("networksetup", "-removepreferredwirelessnetwork", "en0", hotspotName)
			if outRm, errRm := cmdRm.CombinedOutput(); errRm != nil {
				return ctx, fmt.Errorf("joining provisioning hotspot failed while removing preferred network: %w\n%s", errRm, outRm)
			}
			time.Sleep(100 * time.Millisecond)
			cmdOn := exec.Command("networksetup", "-setairportpower", "en0", "on")
			if outOn, errOn := cmdOn.CombinedOutput(); errOn != nil {
				return ctx, fmt.Errorf("joining provisioning hotspot failed while turning on adapter: %w\n%s", errOn, outOn)
			}
		}
		lastOut = outStr
		// sleep for a bit between attempts
		time.Sleep(1 * time.Second)
	}
	return ctx, fmt.Errorf("failure: provisioning hotspot is still present after %v seconds: %s", provTimeout, lastOut)
}

func testAgentCanReachApp(ctx context.Context) (context.Context, error) {
	var lastErr error
	for range 30 {
		res := serialClient.GetPingPacketLoss()
		if res.IsError() {
			lastErr = res.Error()
			continue
		}
		resGet := res.MustGet()
		if resGet == 0 {
			return ctx, nil
		} else if resGet > 0 {
			lastErr = fmt.Errorf("Bad connection, or no connection: %d%% packet loss", resGet)
		}
		time.Sleep(1 * time.Second)
	}
	return ctx, fmt.Errorf("viam-agent did not come online within timeout: %w", lastErr)
}

func testAgentCannotReachApp(ctx context.Context) (context.Context, error) {
	var lastErr error
	for range 30 {
		res := serialClient.GetPingPacketLoss()
		if res.IsError() {
			lastErr = res.Error()
			continue
		}
		if res.MustGet() > 0 {
			return ctx, nil
		}
		time.Sleep(1 * time.Second)
	}
	return ctx, fmt.Errorf("viam-agent did not go offline within timeout: %w", lastErr)
}

func sendNetworkCredentials(ctx context.Context, ssid, psk string) error {
	var lastErr error
	for range 5 {
		conn, err := grpc.NewClient("10.42.0.1:4772",
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return err
		}
		defer conn.Close()

		client := pb.NewProvisioningServiceClient(conn)

		if lastErr != nil {
			time.Sleep(2 * time.Second)
		}
		if _, lastErr = client.SetNetworkCredentials(ctx, &pb.SetNetworkCredentialsRequest{
			Type: networking.NetworkTypeWifi,
			Ssid: ssid,
			Psk:  psk,
		}); lastErr != nil {
			continue
		}
		if _, lastErr = client.ExitProvisioning(ctx, &pb.ExitProvisioningRequest{}); lastErr != nil {
			continue
		}
		return nil
	}
	return lastErr
}

func sendNetworkCredentialsBle(ctx context.Context, ssid, psk string) error {
	robotKeysResp, err := appClient.GetRobotAPIKeys(ctx, &apppb.GetRobotAPIKeysRequest{
		RobotId: cfg.RobotID,
	})
	if err != nil {
		return fmt.Errorf("getting robot API keys: %w", err)
	}
	robotKeys := robotKeysResp.ApiKeys[0]

	args := []string{"run", "./cmd/provisioning-client",
		"-b",
		"--filter", fmt.Sprintf("viam-setup-%s", hostName),
		"--psk", "viamsetup",
		"--wifi-ssid", ssid,
		"--wifi-psk", psk,
		"--part-id", cfg.PartID,
		"--api-key-id", robotKeys.ApiKey.Id,
		"--api-key-key", robotKeys.ApiKey.Key}
	cmdString := strings.Join([]string{"go", strings.Join(args, " ")}, " ")
	logger.Infow("Running command", "cmd", cmdString)
	cmd := exec.CommandContext(ctx, "go", args...)
	out, err := cmd.CombinedOutput()
	logger.Debugf("Command output:", "output", out)
	if err != nil {
		return fmt.Errorf("BLE provisioning failed: %w\n%s", err, out)
	}
	return nil
}

func testSendInsecureConnectionInfo(ctx context.Context) (context.Context, error) {
	return ctx, sendNetworkCredentials(ctx, cfg.Wifi.SSIDInsecure, "")
}

func testSendSecureConnectionInfo(ctx context.Context) (context.Context, error) {
	return ctx, sendNetworkCredentials(ctx, cfg.Wifi.SSID, cfg.Wifi.Password)
}

func testBleIsDiscoverable(ctx context.Context) (context.Context, error) {
	filter := fmt.Sprintf("viam-setup-%s", hostName)

	var lastErr error
	// each try is 30 seconds so 4 tries is 120 seconds
	for range 4 {
		lastBleStatus = []string{}
		args := []string{"run", "./cmd/provisioning-client",
			"-b",
			"--status",
			"--info",
			"--filter", filter}
		cmdString := strings.Join([]string{"go", strings.Join(args, " ")}, " ")
		logger.Infow("Running command", "cmd", cmdString)
		cmd := exec.CommandContext(ctx, "go", args...)
		out, err := cmd.CombinedOutput()
		// the command failed to run at all, try again
		if err != nil {
			lastErr = err
			continue
		}
		outString := string(out)
		logger.Debugf("Command output:", "output", outString)
		outStringSplit := strings.Split(outString, "\n")
		// cache the last BLE status here so it can be used to check for errors in future steps
		lastBleStatus = outStringSplit
		// failed to find the device, try again
		if !strings.Contains(outString, "Found device:") {
			lastErr = fmt.Errorf("BLE device was not discoverable")
			continue
		}
		if strings.Contains(outString, "timeout on Connect") {
			lastErr = fmt.Errorf("BLE device found, but connection timed out")
			continue
		}
		if strings.Contains(outString, "did not find all requested services") {
			lastErr = fmt.Errorf("BLE device connected, but could not find all requested services")
			continue
		}
		// check for all the expected BLE characteristics
		for _, char := range agentBleChars {
			charFound := false
			for _, line := range outStringSplit {
				if strings.Contains(line, char) {
					charFound = true
				}
			}
			// if we find a device but it's missing an expected characteristic, bail
			if !charFound {
				return ctx, fmt.Errorf("discovered BLE device missing characteristic: %s", char)
			}
		}
		return ctx, nil
	}
	return ctx, lastErr
}

func testBleSendSecureConnectionInfo(ctx context.Context) (context.Context, error) {
	return ctx, sendNetworkCredentialsBle(ctx, cfg.Wifi.SSID, cfg.Wifi.Password)
}

func testBleSendInsecureConnectionInfo(ctx context.Context) (context.Context, error) {
	return ctx, sendNetworkCredentialsBle(ctx, cfg.Wifi.SSIDInsecure, "")
}

func testSendInvalidConnectionInfo(ctx context.Context) (context.Context, error) {
	return ctx, sendNetworkCredentials(ctx, "thisnetwork", "doesnotexist")
}

func testBleSendInvalidPasswordConnectionInfo(ctx context.Context) (context.Context, error) {
	return ctx, sendNetworkCredentialsBle(ctx, cfg.Wifi.SSID, "itdoesnotexist")
}

func testBleSendInvalidSSIDConnectionInfo(ctx context.Context) (context.Context, error) {
	return ctx, sendNetworkCredentialsBle(ctx, "thisnetworkisfake", "itdoesnotexist")
}

func testBleSurfacesInvalidSSIDError(ctx context.Context) (context.Context, error) {
	return ctx, bleSurfacesExpectedError("NmDeviceStateReasonSsidNotFound")
}

func testBleSurfacesInvalidCredentialsErr(ctx context.Context) (context.Context, error) {
	return ctx, bleSurfacesExpectedError("bad or missing password")
}

func bleSurfacesExpectedError(expectedErr string) error {
	for _, line := range lastBleStatus {
		if strings.Contains(line, "Errors:") && !strings.Contains(line, "Errors: []") {
			if strings.Contains(line, expectedErr) {
				return nil
			}
			return fmt.Errorf("found error, but not expected error (%s): %s", expectedErr, line)
		}
	}
	return fmt.Errorf("did not find any error (expected %s) in BLE info: %s", expectedErr, strings.Join(lastBleStatus, "\n"))
}

// installAgentVersion runs install.sh on the device. If version is empty, the script
// downloads the stable release; otherwise version is treated as a specifier
// (concrete, "stable", "dev", or "pr.N"), resolved to a concrete GCS URL, and
// injected into the script via AGENT_CUSTOM_URL.
func installAgent(ctx context.Context, version string) (context.Context, error) {
	agentStatus := serialClient.GetAgentStatus().MustGet()
	// Avoid wasting time and network traffic if agent is already running at the desired version

	// First check, if agent is running, and running on the correct version
	if agentStatus["SubState"] == "running" {
		_, err := testAgentRunningWithVersion(ctx, version)
		if err == nil {
			return ctx, nil
		}
	}

	// Then install
	robotKeysResp, err := appClient.GetRobotAPIKeys(ctx, &apppb.GetRobotAPIKeysRequest{
		RobotId: cfg.RobotID,
	})
	if err != nil {
		return ctx, err
	}
	robotKeys := robotKeysResp.ApiKeys[0]
	cmd := fmt.Sprintf(
		"FORCE=1 VIAM_API_KEY_ID=%s VIAM_API_KEY=%s VIAM_PART_ID=%s",
		robotKeys.ApiKey.Id, robotKeys.ApiKey.Key, cfg.PartID,
	)
	logger.Infof("Install version: %s\n", concreteTestVersion)
	// Don't use the concrete test version if it's a file pin, because gcsURL can't handle file pins
	if !strings.HasPrefix(concreteTestVersion, "file://") {
		cmd += fmt.Sprintf(" AGENT_CUSTOM_URL=%s", gcsURL("viam-agent", concreteTestVersion))
	}
	cmd += " sh"
	err = serialClient.RunScript(installScript, cmd).Error()

	// After install, if the version under test is a file pin, pin to the file
	// assuming the binary is present on the device

	// problem: binaries print their version as "custom Git Revision: sha"
	if strings.HasPrefix(concreteTestVersion, "file://") {
		logger.Infof("Version under test is a file pin: %s", concreteTestVersion)
		ctx, err := applyVersionPin(ctx, concreteTestVersion, "agent", "version_control", "agent")
		return ctx, err
	}
	return ctx, err
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
	logger.Infof("Check for version %s with matcher %s\n", version, versionTest)
	var err error
	// Agent needs time to fetch the new config, possibly download the new
	// version, and restart.
	for i := range 60 {
		if i > 0 {
			time.Sleep(time.Second * 2)
		}
		lastAgentVer := serialClient.GetAgentLastStartVersion()
		// if we failed to get a version, keep trying
		if lastAgentVer.IsError() {
			err = lastAgentVer.Error()
			continue
		}
		// if we got a version, but it's not what's expected, don't keep waiting
		if check := versionTest(lastAgentVer.MustGet()); check != "" {
			return ctx, errors.New(check)
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
	return translateVersion(version, cfg.Versions.Old, cfg.Versions.Test)
}

func versionStrToMatcher(version string) func(string) string {
	return versionStrToMatcherBase(version, cfg.Versions.Old, cfg.Versions.Stable, cfg.Versions.Test)
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
	return translateVersion(version, cfg.Versions.ViamServerOld, cfg.Versions.ViamServerTest)
}

func versionStrToMatcherViamServer(version string) func(string) string {
	return versionStrToMatcherBase(version, cfg.Versions.ViamServerOld, cfg.Versions.ViamServerStable, cfg.Versions.ViamServerTest)
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

// serialTestTags returns the godog tag expression for serial tests. On
// non-darwin hosts, scenarios tagged @darwin (e.g. wifi provisioning) are
// excluded because they depend on macOS-specific tooling (networksetup).
func serialTestTags() string {
	tags := os.Getenv("GODOG_TAGS")
	if runtime.GOOS != "darwin" {
		if tags != "" {
			tags += " && "
		}
		tags += "~@darwin"
	}
	return tags
}
