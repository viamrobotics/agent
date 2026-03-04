// Package serialcontrol provides utilities to control a Linux machine,
// probably a Raspberry Pi running Rasbian, via a serial terminal.
package serialcontrol

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jmatth/loz"
	lom "github.com/jmatth/loz/mapping"
	errw "github.com/pkg/errors"
	"github.com/samber/lo/it"
	"github.com/samber/mo"
	"go.bug.st/serial"
	"go.viam.com/rdk/logging"
)

// Control sequence for xterm's bracketed paste mode:
// https://invisible-island.net/xterm/ctlseqs/ctlseqs.html#h2-Bracketed-Paste-Mode.
var (
	startPrompt = []byte("\x1B[?2004h")
	startOutput = []byte("\x1B[?2004l")
)

// Client is used to control a raspberry pi over a serial console.
type Client struct {
	port             serial.Port
	logger           logging.Logger
	terminalLogger   logging.Logger
	extraShellLevels int
}

// Copied from bufio.
func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[0 : len(data)-1]
	}
	return data
}

// splitTerminal is a bufio.SplitFunc that splits terminal output into lines,
// then terminates when a new prompt is rendered. It looks for ANSI escape
// sequences to find the next prompt. Mostly copied from [bufio.ScanLines].
func splitTerminal(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	// Skip over end bracket paste control sequence
	if bytes.HasPrefix(data, startOutput) {
		return len(startOutput) + 1, []byte{}, nil
	}

	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		if bytes.Equal(data, []byte(strings.TrimSpace(string(startOutput)))) {
			// Found end of bracketed paste mode, which should appear right before the
			// command output. Translate it to an empty string and keep going.
			return i + 1, []byte{}, nil
		}
		// Found a newline, presumably as part of ongoing command output. Return the
		// line with the trailing newline removed + keep scanning.
		return i + 1, dropCR(data[0:i]), nil
	}

	promptStartIndex := bytes.Index(data, startPrompt)
	if promptStartIndex >= 0 {
		// Found the next prompt and no newlines precede it; return whatever output
		// remains and terminate scanning.
		return promptStartIndex + len(startPrompt), data[0:promptStartIndex], bufio.ErrFinalToken
	}

	if atEOF {
		return len(data), data, nil
	}

	// Request more data.
	return 0, nil, nil
}

// Connect opens a serial connection and establishes basic IO. Further setup
// such as calling [Client.Sudo] is necessary before the Client is fully
// usable.
func Connect(logger logging.Logger, serialPortPath string) mo.Result[*Client] {
	clientLogger := logger.Sublogger("serialClient")
	terminalLogger := clientLogger.Sublogger("terminal")
	serialPortRes := mo.TupleToResult(serial.Open(serialPortPath, &serial.Mode{
		BaudRate: 115200,
		DataBits: 8,
		Parity:   serial.NoParity,
	}))
	if serialPortRes.IsError() {
		return mo.Err[*Client](
			errw.Wrapf(serialPortRes.Error(), "failed to open serial port at %s", serialPortPath),
		)
	}
	return mo.Ok(&Client{
		port:           serialPortRes.MustGet(),
		logger:         clientLogger,
		terminalLogger: terminalLogger,
	})
}

// Close attempts to reset the serial terminal to the state it was in before
// the Client was attached, then closes the underlying connection.
func (c *Client) Close() error {
	for range c.extraShellLevels {
		if _, err := c.port.Write([]byte("exit\r")); err != nil {
			return errw.Wrap(err, "failed to exit shell")
		}
	}
	if err := c.port.Close(); err != nil {
		return errw.Wrap(err, "failed to close serial port")
	}
	return nil
}

func (c *Client) runCmd(cmd string) mo.Result[[]string] {
	if c.extraShellLevels < 1 {
		// Sudo() does more setup than just elevating privileges to make the serial
		// console output easier to parse, so we require it to be called first.
		return mo.Errf[[]string]("must call Sudo() before running any commands")
	}
	c.logger.Infow("Running command", "cmd", cmd)

	// Scan the output by lines until we reach the next prompt.
	scanner := bufio.NewScanner(c.port)
	scanner.Split(splitTerminal)

	// Clear the serial output (this method has a confusing name) to avoid any
	// lingering bytes from the prompt rendering. All we should see after this is
	// the command output followed by the next prompt.
	// NOTE: on macOS this actually resets both the input and output buffers, so
	// this call must come before we send the command.
	if err := c.port.ResetInputBuffer(); err != nil {
		return mo.Err[[]string](err)
	}

	if _, err := c.port.Write([]byte(cmd + "\r")); err != nil {
		return mo.Err[[]string](err)
	}

	res := scannerToStrSeq(scanner).
		Map(strings.TrimSpace).
		FilterMap(func(output string) (string, bool) {
			// Ignore blank lines. Does any command output have significant
			// whitespace such that we'll need to remove this?
			if len(output) < 1 {
				return "", false
			}
			c.terminalLogger.Debug(output)
			return output, true
		}).
		CollectSlice()
	return mo.Ok(res)
}

func scannerToStrSeq(scanner *bufio.Scanner) loz.Seq[string] {
	return func(yield func(string) bool) {
		for scanner.Scan() {
			if !yield(scanner.Text()) {
				break
			}
		}
	}
}

// Sudo elevates the privileges on the client and performs some environment
// setup in the newly elevated shell. It's actions will be automatically
// reversed by [Client.Close]. This method assumes that it is possible to sudo
// without a password.
func (c *Client) Sudo() error {
	if _, err := c.port.Write([]byte("sudo -s\r")); err != nil {
		return errw.Wrap(err, `failed to execute "sudo -s"`)
	}
	c.extraShellLevels++

	// Disable echo in the terminal so we don't have to deal with ignoring the
	// text of the commands we send in the output.
	if _, err := c.port.Write([]byte("stty -echo\r")); err != nil {
		return errw.Wrap(err, `failed to execute "stty -echo"`)
	}

	time.Sleep(time.Second * 2)
	return nil
}

// RemoveViam stops the viam-agent process and removes all viam-agent +
// viam-server files from the disk using the official uninstall.sh script. Since
// this script is fetched from the internet, the device must be online when this
// is called.
//
// TODO: send the script contents over the serial connection using heredoc or
//
//	some other means? I tried this and it seemed to break the next prompt
//	detection.
func (c *Client) RemoveViam() mo.Result[[]string] {
	return c.runCmd("curl https://storage.googleapis.com/packages.viam.com/apps/viam-agent/uninstall.sh | FORCE=1 sh")
}

// InstallViam installs viam-agent using the process presented to the user in
// the setup flow on app.viam.com.
func (c *Client) InstallViam(partID, keyID, key string) mo.Result[[]string] {
	cmd := fmt.Sprintf(
		//nolint: lll
		`yes | /bin/sh -c "FORCE=1 VIAM_API_KEY_ID=%s VIAM_API_KEY=%s VIAM_PART_ID=%s; $(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/install.sh)"`,
		keyID, key, partID,
	)
	// TODO: this will log the command being run, including the API key in
	// plaintext. This should change if we ever plan to run this anywhere other
	// than local environments.
	return c.runCmd(cmd)
}

// StartAgent starts the viam-agent systemd unit.
func (c *Client) StartAgent() mo.Result[[]string] {
	return c.runCmd("systemctl start viam-agent")
}

// StartAgent stops the viam-agent systemd unit.
func (c *Client) StopAgent() mo.Result[[]string] {
	return c.runCmd("systemctl stop viam-agent")
}

// RFKill enables a soft block on Bluetooth on the target device. It is used to
// test that the agent correctly removes the lock when enabling bluetooth.
func (c *Client) RFKill() mo.Result[[]string] {
	return c.runCmd("rfkill block bluetooth")
}

// GetAgentStatus retrieves the status of the viam-agent systemd unit via the
// `systemctl show` command and converts the output into a Go map.
func (c *Client) GetAgentStatus() mo.Result[map[string]string] {
	cmdRes := c.runCmd("systemctl show viam-agent -l --no-pager")
	if cmdRes.IsError() {
		return mo.Err[map[string]string](cmdRes.Error())
	}
	// Collect output in key=value format into a map
	return mo.Ok(it.FilterSeqToMap(
		slices.Values(cmdRes.MustGet()),
		func(item string) (string, string, bool) {
			c.logger.Infof("systemctl show output: %s", item)
			kv := strings.SplitN(item, "=", 2)
			if len(kv) != 2 {
				// Probably just a blank line, ignore.
				return "", "", false
			}
			return kv[0], kv[1], true
		},
	))
}

var agentVersionRegex = regexp.MustCompile(`Viam Agent Version: ([^\s]+) Git Revision: ([^\s]+)`)

func (c *Client) GetAgentLastStartVersion() mo.Result[string] {
	cmdRes := c.runCmd(
		`journalctl _SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value viam-agent)" -l --no-pager | ` +
			`head -n5 | grep 'Viam Agent Version'`,
	)
	if cmdRes.IsError() {
		return mo.Err[string](cmdRes.Error())
	}
	cmdOutput := cmdRes.MustGet()
	if len(cmdOutput) != 1 {
		return mo.Errf[string]("expected single matching journalctl line but got %d", len(cmdOutput))
	}
	matches := agentVersionRegex.FindStringSubmatch(cmdOutput[0])
	return mo.Ok(matches[1])
}

// viamServerVersionRegex matches the version from viam-server's startup log line, e.g.:
// INFO rdk server/entrypoint.go:104 Viam RDK {"version":"0.95.0","git_rev":"..."}.
var viamServerVersionRegex = regexp.MustCompile(`"version":"([^"]+)"`)

// GetViamServerLastStartVersion returns the viam-server version from the most
// recent startup log entry in the viam-agent systemd journal. viam-server runs
// as a subprocess of viam-agent (not its own systemd unit), so its logs appear
// in the viam-agent journal.
func (c *Client) GetViamServerLastStartVersion() mo.Result[string] {
	cmdRes := c.runCmd(
		`journalctl _SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value viam-agent)" -l --no-pager | ` +
			`grep 'Viam RDK' | tail -n1`,
	)
	if cmdRes.IsError() {
		return mo.Err[string](cmdRes.Error())
	}
	cmdOutput := cmdRes.MustGet()
	if len(cmdOutput) != 1 {
		return mo.Errf[string]("expected single matching journalctl line but got %d", len(cmdOutput))
	}
	matches := viamServerVersionRegex.FindStringSubmatch(cmdOutput[0])
	if len(matches) < 2 {
		return mo.Errf[string]("could not parse viam-server version from line: %s", cmdOutput[0])
	}
	return mo.Ok(matches[1])
}

// DownloadToDevice downloads a file from the given URL to the specified path on
// the device and marks it executable.
func (c *Client) DownloadToDevice(url, destPath string) mo.Result[[]string] {
	return c.runCmd(fmt.Sprintf("curl -fsSL -o %s %s && chmod +x %s", destPath, url, destPath))
}

// GetDeviceArch returns the machine hardware name of the device (e.g., "aarch64", "x86_64").
func (c *Client) GetDeviceArch() mo.Result[string] {
	cmdRes := c.runCmd("uname -m")
	if cmdRes.IsError() {
		return mo.Err[string](cmdRes.Error())
	}
	output := cmdRes.MustGet()
	if len(output) != 1 {
		return mo.Errf[string]("expected single line from uname -m but got %d", len(output))
	}
	return mo.Ok(output[0])
}

// EnsureOnline verifies that the device has an internet connection and attempts
// to connect to the specified WiFi network if it is not.
func (c *Client) EnsureOnline(ssid, password string) error {
	packetLossRes := c.getPingPacketLoss()
	if packetLossRes.IsError() {
		return packetLossRes.Error()
	}
	if packetLossRes.MustGet() == 0 {
		// If we're already online then don't meddle with the internet connection.
		return nil
	}

	if ssid == "" || password == "" {
		return fmt.Errorf(
			"device offline with packet loss of %d%% but no wifi credentials provided, cannot continue",
			packetLossRes.MustGet(),
		)
	}

	// If we're offline try connecting to the specified wifi network.
	connectWifiRes := c.runCmd(fmt.Sprintf(`nmcli device wifi connect "%s" password "%s"`, ssid, password))
	if connectWifiRes.IsError() {
		return errw.Wrap(connectWifiRes.Error(), "failed to connect to wifi network")
	}

	// Rerun the ping test. If this fails we have no way to recover
	return c.getPingPacketLoss().FlatMap(func(value int) mo.Result[int] {
		if value != 0 {
			return mo.Err[int](fmt.Errorf("internet connection unstable with packet loss of %d%%", value))
		}
		return mo.Ok(value)
	}).Error()
}

// getPingPacketLoss attempts to ping app.viam.com and returns the packet loss
// percentage. A successful result does not mean that the internet on the
// device is working, only that we were able to run ping and parse its output.
func (c *Client) getPingPacketLoss() mo.Result[int] {
	pingRegex := regexp.MustCompile(`\d+ packets transmitted, \d+ received, (\d+)% packet loss, time \d+\w+$`)
	const pingCmd = "ping -c 2 -w 10 -q app.viam.com"
	pingRes := c.runCmd(pingCmd)
	if pingRes.IsError() {
		return mo.Err[int](errw.Wrap(pingRes.Error(), "failed to ping app.viam.com"))
	}

	packetLoss, err := lom.Map1[string, int](loz.IterSlice(pingRes.MustGet())).
		FilterMap(func(line string) (int, bool) {
			matches := pingRegex.FindStringSubmatch(line)
			if len(matches) < 2 {
				return 0, false
			}
			packetLoss, err := strconv.Atoi(matches[1])
			if err != nil {
				loz.PanicHaltIteration(errw.Wrapf(err, `expected match in "%s"`, line))
			}
			return packetLoss, true
		}).
		TryFirst()
	if err != nil {
		return mo.Err[int](errw.Wrap(err, "failed to extract packet loss percentage from ping output"))
	}
	return mo.Ok(packetLoss)
}

// ForceProvisioning forces the agent into provisioning mode.
func (c *Client) ForceProvisioning() mo.Result[[]string] {
	return c.runCmd("touch /opt/viam/etc/force_provisioning_mode")
}
