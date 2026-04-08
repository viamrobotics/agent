//go:build serialtests

package agent_test

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
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

var (
	serialClient *serialcontrol.Client
	appClient    apppb.AppServiceClient
	deviceArch   string
	hostName     string
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
	Stable           string `toml:"viam_agent_stable"`
	Old              string `toml:"viam_agent_old"`
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

var cfg config

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

			logger := logging.NewTestLogger(t)
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
			if err := serialClient.EnsureOnline(cfg.Wifi.SSID, cfg.Wifi.Password); err != nil {
				t.Logf("error reconnecting to wifi during cleanup: %v", err)
			}
			if runtime.GOOS == "darwin" {
				if _, err := hostEnsureOnline(ctx); err != nil {
					t.Logf("error restoring host connection to internet during cleanup: %v", err)
				}
			}
			// Just wait after reconnecting everything to make sure all the connections are back
			time.Sleep(time.Second * 3)
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
	ctx.Step(`the viam-agent systemd unit is dead$`, testAgentDead)
	ctx.Step(`the viam-agent systemd unit is not found$`, testAgentNotFound)
	ctx.Step(`the viam files have all been removed`, testViamFilesRemoved)
	ctx.Step(`the journald config is live$`, testJournaldConfigLoaded)
	ctx.Step(`the wifi power save config is live$`, testWifiPowerSaveConfigLoaded)

	// Wifi provisioning
	ctx.Step(`there are no available wifi networks`, testClearWifiConnections)
	ctx.Step(`viam-agent is in forced provisioning mode`, testForceProvisioningMode)
	ctx.Step(`the provisioning hotspot (is|comes) up`, testProvisioningHotspotEnablesWithinTimeout)
	ctx.Step(`the tester shares a secure wifi network`, testSendSecureConnectionInfo)
	ctx.Step(`the tester shares an insecure wifi network`, testSendInsecureConnectionInfo)
	ctx.Step(`the tester shares an invalid wifi network`, testSendInvalidConnectionInfo)
	ctx.Step(`the provisioning hotspot (goes away|is not up)`, testProvisioningHotspotDisables)
	ctx.Step(`viam-agent can reach the app`, testAgentCanReachApp)
	ctx.Step(`viam-agent cannot reach the app`, testAgentCannotReachApp)

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
		if err := serialClient.EnsureOnline(cfg.Wifi.SSID, cfg.Wifi.Password); err != nil {
			return ctx, err
		}
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
		if next.Fields == nil {
			next.Fields = make(map[string]*structpb.Value)
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
	for i := range 30 {
		if i > 0 {
			time.Sleep(time.Second * 2)
		}
		// Check the most recent journald startup log line which reports the
		// live max size and journal path. Persistent storage uses
		// /var/log/journal/ (volatile would be /run/log/journal/).
		res := serialClient.RunScript(
			`journalctl --no-pager -u systemd-journald -n 5 --output=short-monotonic 2>&1 | grep "System Journal"`,
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
	output := serialClient.ListWifiConnections()
	return ctx, output.Error()
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
			return ctx, nil
		}
		lastOut = outStr
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
			cmdRm := exec.Command("networksetup", "-removepreferredwirelessnetwork", "en0", hotspotName)
			if outRm, errRm := cmdRm.CombinedOutput(); errRm != nil {
				return ctx, fmt.Errorf("joining provisioning hotspot failed while removing preferred network: %w\n%s", errRm, outRm)
			}
			cmdOn := exec.Command("networksetup", "-setairportpower", "en0", "on")
			if outOn, errOn := cmdOn.CombinedOutput(); errOn != nil {
				return ctx, fmt.Errorf("joining provisioning hotspot failed while turning on adapter: %w\n%s", errOn, outOn)
			}
		}
		lastOut = outStr
	}
	return ctx, fmt.Errorf("failure: provisioning hotspot is still present after %v seconds: %s", provTimeout, lastOut)
}

func testAgentCanReachApp(ctx context.Context) (context.Context, error) {
	for range 30 {
		res := serialClient.GetPingPacketLoss()
		if res.IsError() {
			return ctx, fmt.Errorf("canPing failed: %w", res.Error())
		}
		if res.MustGet() == 0 {
			return ctx, nil
		}
		time.Sleep(1 * time.Second)
	}
	return ctx, fmt.Errorf("viam-agent did not come online within timeout")
}

func testAgentCannotReachApp(ctx context.Context) (context.Context, error) {
	for range 30 {
		res := serialClient.GetPingPacketLoss()
		if res.IsError() {
			return ctx, fmt.Errorf("canPing failed: %w", res.Error())
		}
		if res.MustGet() > 0 {
			return ctx, nil
		}
		time.Sleep(1 * time.Second)
	}
	return ctx, fmt.Errorf("viam-agent did not go offline within timeout")
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

func testSendInsecureConnectionInfo(ctx context.Context) (context.Context, error) {
	return ctx, sendNetworkCredentials(ctx, cfg.Wifi.SSIDInsecure, "")
}

func testSendSecureConnectionInfo(ctx context.Context) (context.Context, error) {
	return ctx, sendNetworkCredentials(ctx, cfg.Wifi.SSID, cfg.Wifi.Password)
}

func testSendInvalidConnectionInfo(ctx context.Context) (context.Context, error) {
	return ctx, sendNetworkCredentials(ctx, "thisnetwork", "doesnotexist")
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
