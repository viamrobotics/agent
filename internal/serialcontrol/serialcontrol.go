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

var (
	startCommandOutput = []byte("\x1B[?2004l")
	startPrompt        = []byte("\x1B[?2004h")
)

// Client is used to control a raspberry pi over a serial console.
type Client struct {
	port             serial.Port
	logger           logging.Logger
	terminalLogger   logging.Logger
	extraShellLevels int
}

func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[0 : len(data)-1]
	}
	return data
}

// splitTerminal is a bufio.SplitFunc that splits terminal output into lines,
// then terminates when a new prompt is rendered. It looks for ANSI escape
// sequences to find the next prompt.
func splitTerminal(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, dropCR(data[0:i]), nil
	}

	cmdStartIndex := bytes.Index(data, startCommandOutput)
	promptStartIndex := bytes.Index(data, startPrompt)
	if cmdStartIndex >= 0 && (promptStartIndex < 0 || cmdStartIndex < promptStartIndex) {
		return cmdStartIndex + len(startCommandOutput), data[0:cmdStartIndex], nil
	}

	if promptStartIndex >= 0 && (cmdStartIndex < 0 || promptStartIndex < cmdStartIndex) {
		return promptStartIndex + len(startPrompt), data[0:promptStartIndex], bufio.ErrFinalToken
	}

	if atEOF {
		return len(data), data, nil
	}

	// Request more data.
	return 0, nil, nil
}

// Connect opens a serial connection and establishes basic IO. Further setup
// such as calling [Client.Sudo] is likely necessary before the Client is fully
// usable.
func Connect(logger logging.Logger) mo.Result[*Client] {
	const serialPortPath = "/dev/ttyUSB0"
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
func (c *Client) Close() error {
	for range c.extraShellLevels {
		_, err := c.port.Write([]byte("exit\r"))
		if err != nil {
			return err
		}
	}
	return c.port.Close()
}

func (c *Client) runCmd(cmd string) mo.Result[string] {
	if c.extraShellLevels < 1 {
		// Sudo() does more setup than just elevating privileges to make the serial
		// console output easier to parse, so we require it to be called first.
		panic("Must call Sudo() first")
	}
	c.logger.Infow("Running command", "cmd", cmd)
	// Clear the serial output (this method has a confusing name) to avoid any
	// lingering bytes from the prompt rendering or something.
	if err := c.port.ResetInputBuffer(); err != nil {
		return mo.Err[string](err)
	}

	// Scan the output by lines until we reach the next prompt.
	scanner := bufio.NewScanner(c.port)
	scanner.Split(splitTerminal)

	return result.Pipe1(
		mo.TupleToResult(c.port.Write([]byte(cmd+"\r"))),
		result.FlatMap(func(int) mo.Result[string] {
			// Kinda gross but we want to log by line but return the entire output as
			// one string. Maybe we drop the single string requirement and just return
			// a []string instead?
			res := strings.Builder{}
			for scanner.Scan() {
				output := strings.TrimSpace(scanner.Text())
				// Ignore blank lines. Does any command output have significant
				// whitespace such that we'll need to remove this?
				if len(output) < 1 {
					continue
				}
				c.terminalLogger.Info(output)
				res.WriteString(output)
				res.WriteByte('\n')
			}
			return mo.Ok(res.String())
		}),
	)
}

// Sudo elevates the privileges on the client and performs some environment
// setup in the newly elevated shell. It's actions will be automatically
// reversed by [Client.Close]. This method assumes that it is possible to sudo
// without a password.
func (c *Client) Sudo() mo.Result[string] {
	return result.Pipe1(
		mo.TupleToResult(c.port.Write([]byte("sudo -s\r"))).
			MapValue(func(value int) int {
				c.extraShellLevels++
				time.Sleep(time.Second * 2)
				return 0
			}).
			Map(func(value int) (int, error) {
				return c.port.Write([]byte("stty -echo\r"))
			}).
			MapValue(func(value int) int {
				time.Sleep(time.Second * 2)
				return 0
			}),
		result.Map(func(int) string {
			return ""
		}),
	)
}

// joinOutputs is a helper to concatenate chained [mo.Result]s that
// all contain strings.
func joinOutputs(prev string) func(string) string {
	return func(curr string) string {
		return prev + "\n" + curr
	}
}

// RemoveViam stops the viam-agent process and removes all viam-agent +
// viam-server files from the disk.
func (c *Client) RemoveViam() mo.Result[string] {
	return c.StopAgent().
		FlatMap(func(prevOutput string) mo.Result[string] {
			toDelete := strings.Join([]string{
				"/opt/viam",
				"/etc/viam.json",
				"/etc/systemd/system/viam-agent.service",
				"/usr/local/lib/systemd/system/viam-agent.service",
				"/etc/systemd/system/viam-server.service",
			}, " ")
			return c.runCmd("rm -rf " + toDelete).MapValue(joinOutputs(prevOutput))
		}).
		FlatMap(func(prevOutput string) mo.Result[string] {
			return c.runCmd("systemctl daemon-reload").MapValue(joinOutputs(prevOutput))
		})
}

// InstallViam installs viam-agent using the process presented to the user in
// the setup flow on app.viam.com.
func (c *Client) InstallViam(partID, keyID, key string) mo.Result[string] {
	cmd := fmt.Sprintf(
		//nolint: lll
		`/bin/sh -c "VIAM_API_KEY_ID=%s VIAM_API_KEY=%s VIAM_PART_ID=%s; $(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/install.sh)"`,
		keyID, key, partID,
	)
	return c.runCmd(cmd)
}

// StartAgent starts the viam-agent systemd unit.
func (c *Client) StartAgent() mo.Result[string] {
	return c.runCmd("systemctl start viam-agent")
}

// StartAgent stops the viam-agent systemd unit.
func (c *Client) StopAgent() mo.Result[string] {
	return c.runCmd("systemctl stop viam-agent")
}

// RFKill enables a soft block on Bluetooth on the target device. It is used to
// test that the agent correctly removes the lock when enabling bluetooth.
func (c *Client) RFKill() mo.Result[string] {
	return c.runCmd("rfkill block bluetooth")
}

// GetAgentStatus retrieves the status of the viam-agent systemd unit via the
// `systemctl show` command.
func (c *Client) GetAgentStatus() mo.Result[map[string]string] {
	return result.Pipe1(
		c.runCmd("systemctl show viam-agent -l --no-pager"),
		// Collect output in key=value format into a map
		result.Map(func(s string) map[string]string {
			return it.FilterSeqToMap(
				slices.Values(strings.Split(s, "\n")),
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
func (c *Client) ForceProvisioning() mo.Result[string] {
	return c.runCmd("touch /opt/viam/etc/force_provisioning_mode")
}
