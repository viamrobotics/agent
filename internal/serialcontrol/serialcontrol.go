// Package serialcontrol provides utilities to control a Linux machine,
// probably a Raspberry Pi running Rasbian, via a serial terminal.
package serialcontrol

import (
	"bufio"
	"bytes"
	"fmt"
	"slices"
	"strings"
	"time"

	errw "github.com/pkg/errors"
	"github.com/samber/lo/it"
	"github.com/samber/mo"
	"github.com/samber/mo/result"
	"go.bug.st/serial"
	"go.viam.com/rdk/logging"
)

// Control sequence for xterm's bracketed paste mode:
// https://invisible-island.net/xterm/ctlseqs/ctlseqs.html#h2-Bracketed-Paste-Mode.
var startPrompt = []byte("\x1B[?2004h")

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

	if i := bytes.IndexByte(data, '\n'); i >= 0 {
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
	return result.Pipe1(
		mo.TupleToResult(serial.Open(serialPortPath, &serial.Mode{
			BaudRate: 115200,
			DataBits: 8,
			Parity:   serial.NoParity,
		})).MapErr(func(err error) (serial.Port, error) {
			return nil, errw.Wrapf(err, "failed to open serial port at %s", serialPortPath)
		}),
		result.Map(func(port serial.Port) *Client {
			return &Client{
				port:           port,
				logger:         clientLogger,
				terminalLogger: terminalLogger,
			}
		}),
	)
}

// Close attempts to reset the serial terminal to the state it was in before
// the Client was attached, then closes the underlying connection.
func (c *Client) Close() mo.Result[any] {
	for range c.extraShellLevels {
		res := mo.TupleToResult(c.port.Write([]byte("exit\r")))
		if res.IsError() {
			return mo.Err[any](res.Error())
		}
	}
	if err := c.port.Close(); err != nil {
		return mo.Err[any](err)
	}
	return mo.Ok[any](nil)
}

func (c *Client) runCmd(cmd string) mo.Result[[]string] {
	if c.extraShellLevels < 1 {
		// Sudo() does more setup than just elevating privileges to make the serial
		// console output easier to parse, so we require it to be called first.
		panic("Must call Sudo() first")
	}
	c.logger.Infow("Running command", "cmd", cmd)
	// Clear the serial output (this method has a confusing name) to avoid any
	// lingering bytes from the prompt rendering. All we should see after this
	// the command output followed by the next prompt.
	if err := c.port.ResetInputBuffer(); err != nil {
		return mo.Err[[]string](err)
	}

	// Scan the output by lines until we reach the next prompt.
	scanner := bufio.NewScanner(c.port)
	scanner.Split(splitTerminal)

	if _, err := c.port.Write([]byte(cmd + "\r")); err != nil {
		return mo.Err[[]string](err)
	}
	res := []string{}
	for scanner.Scan() {
		output := strings.TrimSpace(scanner.Text())
		// Ignore blank lines. Does any command output have significant
		// whitespace such that we'll need to remove this?
		if len(output) < 1 {
			continue
		}
		c.terminalLogger.Debug(output)
		res = append(res, output)
	}
	return mo.Ok(res)
}

// Sudo elevates the privileges on the client and performs some environment
// setup in the newly elevated shell. It's actions will be automatically
// reversed by [Client.Close]. This method assumes that it is possible to sudo
// without a password.
func (c *Client) Sudo() mo.Result[any] {
	if _, err := c.port.Write([]byte("sudo -s\r")); err != nil {
		return mo.Err[any](err)
	}
	c.extraShellLevels++
	time.Sleep(time.Second * 2)

	// Disable echo in the terminal so we don't have to deal with ignoring the
	// text of the commands we send in the output.
	if _, err := c.port.Write([]byte("stty -echo\r")); err != nil {
		return mo.Err[any](err)
	}

	return mo.Ok[any](nil)
}

// joinOutputs is a helper to concatenate chained [mo.Result]s that
// all contain string slices from [Client.runCmd] calls.
func joinOutputs(prev []string) func([]string) []string {
	return func(curr []string) []string {
		return append(prev, curr...)
	}
}

// RemoveViam stops the viam-agent process and removes all viam-agent +
// viam-server files from the disk.
func (c *Client) RemoveViam() mo.Result[[]string] {
	return c.StopAgent().
		FlatMap(func(prevOutput []string) mo.Result[[]string] {
			toDelete := strings.Join([]string{
				"/opt/viam",
				"/etc/viam.json",
				"/etc/systemd/system/viam-agent.service",
				"/usr/local/lib/systemd/system/viam-agent.service",
				"/etc/systemd/system/viam-server.service",
			}, " ")
			return c.runCmd("rm -rf " + toDelete).MapValue(joinOutputs(prevOutput))
		}).
		FlatMap(func(prevOutput []string) mo.Result[[]string] {
			return c.runCmd("systemctl daemon-reload").MapValue(joinOutputs(prevOutput))
		})
}

// InstallViam installs viam-agent using the process presented to the user in
// the setup flow on app.viam.com.
func (c *Client) InstallViam(partID, keyID, key string) mo.Result[[]string] {
	cmd := fmt.Sprintf(
		//nolint: lll
		`/bin/sh -c "VIAM_API_KEY_ID=%s VIAM_API_KEY=%s VIAM_PART_ID=%s; $(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/install.sh)"`,
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
	return result.Pipe1(
		c.runCmd("systemctl show viam-agent -l --no-pager"),
		// Collect output in key=value format into a map
		result.Map(func(s []string) map[string]string {
			return it.FilterSeqToMap(
				slices.Values(s),
				func(item string) (string, string, bool) {
					kv := strings.SplitN(item, "=", 2)
					if len(kv) != 2 {
						// Probably just a blank line, ignore.
						return "", "", false
					}
					return kv[0], kv[1], true
				},
			)
		}),
	)
}

// ForceProvisioning forces the agent into provisioning mode.
func (c *Client) ForceProvisioning() mo.Result[[]string] {
	return c.runCmd("touch /opt/viam/etc/force_provisioning_mode")
}
