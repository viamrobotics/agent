package syscfg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.uber.org/zap/zapcore"
)

const journalctlNAWarningMessage = "journalctl not available, log forwarding disabled"

// Forwards all systemd logs related to shutdown from the last viam-agent instance and
// startup from this viam-agent instance. These logs will contain information like whether
// the last viam-agent instance was OOM killed. e.g., the following can make it up to app after
// the part is restarted via the UI:
//
// 1/14/2026, 4:38:58 PM info viam-agent.systemd    Started viam-agent.service - Viam Services Agent.
// 1/14/2026, 4:38:58 PM info viam-agent.systemd    Starting viam-agent.service - Viam Services Agent...
// 1/14/2026, 4:38:58 PM info viam-agent.systemd    viam-agent.service: Consumed 55.548s CPU time.
// 1/14/2026, 4:38:58 PM info viam-agent.systemd    Stopped viam-agent.service - Viam Services Agent.
// 1/14/2026, 4:38:58 PM info viam-agent.systemd    viam-agent.service: Scheduled restart job, restart counter is at 2.
// 1/14/2026, 4:38:52 PM info viam-agent.systemd    viam-agent.service: Consumed 55.548s CPU time.
// 1/14/2026, 4:38:52 PM info viam-agent.systemd    viam-agent.service: Deactivated successfully.
func (s *syscfg) forwardRecentSystemdAgentLogs(ctx context.Context) error {
	s.logMu.Lock()
	defer s.logMu.Unlock()

	// A nil lastShutdown value means none was saved in the cache. Bail in this case. We
	// _could_ attempt to upload all historical systemd agent logs if we do not know when
	// the agent last shutdown, but there may be quite a few of these logs, and doing so
	// could slow startup.
	if s.lastShutdown == nil {
		s.logger.Debug("unknown last shutdown time; will not forward recent systemd agent logs until next startup")
		return nil
	}

	if s.noJournald {
		s.logger.Warn(journalctlNAWarningMessage)
		return nil
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		s.logger.Warn(journalctlNAWarningMessage)
		s.noJournald = true
		return nil
	}

	appender := s.appender()
	if appender == nil {
		return errors.New("net appender not yet available to forward recent systemd agent logs")
	}

	// `journalctl -u viam-agent -t systemd -S [lastShutdown.Format(...)] -o json` gets logs
	// from the viam-agent systemd service (-u viam-agent), from systemd itself (-t
	// systemd), as JSON (-o JSON), and from only the last shutdown time (-S
	// [lastShutdown.Format()]).
	//nolint:gosec
	out, err := exec.CommandContext(ctx, "journalctl", "-u", "viam-agent", "-t", "systemd", "-o", "json",
		"-S", s.lastShutdown.Format("2006-01-02 15:04:05" /* systemd time format */)).CombinedOutput()
	if err != nil {
		return errw.Wrap(err, "running journalctl to forward recent systemd agent logs")
	}

	decoder := json.NewDecoder(bytes.NewBuffer(out))
	for decoder.More() {
		var recentAgentJournaldEntry journaldEntry
		if err := decoder.Decode(&recentAgentJournaldEntry); err != nil {
			if err == io.EOF {
				break
			}
			return errw.Wrap(err, "parsing recent systemd agent logs")
		}

		logEntry := zapcore.Entry{
			Level: recentAgentJournaldEntry.getLevel(),
			Time:  recentAgentJournaldEntry.getTime(),
			// Hardcode logger name instead of using recentAgentJournaldEntry.getName() which
			// would be "systemd[1]".
			LoggerName: "viam-agent.systemd",
			Message:    recentAgentJournaldEntry.getMessage(),
		}
		if err := appender.Write(logEntry, nil); err != nil {
			s.logger.Warn(err)
		}
	}

	return nil
}

func (s *syscfg) startLogForwarding() error {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	s.logHealth.MarkGood()

	// If forwarding is disabled or we already have a running command, do nothing
	if s.cfg.ForwardSystemLogs == "" || s.journalCmd != nil {
		return nil
	}

	if s.noJournald {
		s.logger.Warn(journalctlNAWarningMessage)
		return nil
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		s.logger.Warn(journalctlNAWarningMessage)
		s.noJournald = true
		return nil
	}

	ctx, cancelFunc := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, "journalctl", "-f", "-o", "json")
	cmd.Cancel = func() error {
		// will send a signal to do this the "nice way"
		return errw.Wrap(s.journalCmd.Process.Signal(syscall.SIGTERM), "sending SIGTERM to journalctl")
	}
	// if the nice way above fails for more than ten seconds, it'll more forcibly kill the process
	cmd.WaitDelay = time.Second * 10

	// use custom buffers so we can watch for data
	var stdout, stderr utils.SafeBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		cancelFunc()
		return errw.Wrap(err, "starting journalctl for log forwarding")
	}

	s.journalCmd = cmd
	s.cancelFunc = cancelFunc

	// this will let us only log services we're interested in
	filter := newFilter(s.cfg.ForwardSystemLogs)

	// Start a goroutine to read and process the output
	s.logWorkers.Add(1)
	go func() {
		defer utils.Recover(s.logger, nil)
		defer s.logWorkers.Done()
		defer func() {
			s.cancelFunc()
			if err := s.journalCmd.Wait(); err != nil {
				if !strings.Contains(err.Error(), "signal: terminated") {
					s.logger.Info("stopped journalctl")
				} else {
					s.logger.Warn(errw.Wrap(err, "stopping journalctl"))
				}
			}
			s.logMu.Lock()
			defer s.logMu.Unlock()
			s.cancelFunc = nil
			s.journalCmd = nil
		}()
		decoder := json.NewDecoder(&stdout)

		for {
			// speed limit ourselves to a max of ~100 entries per second
			if !s.logHealth.Sleep(ctx, time.Millisecond*10) {
				return
			}

			// if we don't have an appender, we can't do anything, so sleep and try again later
			appender := s.appender()
			if appender == nil {
				if !s.logHealth.Sleep(ctx, time.Second*10) {
					return
				}
				continue
			}

			if stderr.Len() > 0 {
				// sleep one second in case a write is taking a while, so we get a more complete message
				if !s.logHealth.Sleep(ctx, time.Second) {
					return
				}
				s.logger.Warnf("unexpected error output from journalctl: %s", stderr.String())
			}

			if decoder.More() {
				var entry journaldEntry
				if err := decoder.Decode(&entry); err != nil {
					// let other stuff process in the outer loop if we're caught up
					if err == io.EOF {
						continue
					}
					s.logger.Warn(errw.Wrap(err, "decoding journalctl output"))
					continue
				}

				if !filter.shouldLog(entry) {
					continue
				}

				logEntry := zapcore.Entry{
					Level:      entry.getLevel(),
					Time:       entry.getTime(),
					LoggerName: entry.getName(),
					Message:    entry.getMessage(),
				}

				if err := appender.Write(logEntry, nil); err != nil {
					s.logger.Warn(err)
				}
			}
		}
	}()

	s.logger.Info("Started system log forwarding")
	return nil
}

func (s *syscfg) stopLogForwarding() error {
	if s.journalCmd == nil {
		return nil
	}

	// Cancel the context to signal the reader goroutine to stop
	if s.cancelFunc == nil {
		return errors.New("log forwarding cancel function is nil")
	}
	s.cancelFunc()

	// Wait for the reader goroutine to finish
	s.logWorkers.Wait()

	s.logger.Info("Stopped system log forwarding")
	return nil
}

type journaldEntry struct {
	Message          string `json:"MESSAGE"`
	Priority         string `json:"PRIORITY"`
	RealtimeTS       string `json:"__REALTIME_TIMESTAMP"`
	SyslogIdentifier string `json:"SYSLOG_IDENTIFIER"`
	PID              string `json:"_PID"`
}

// getLevel converts a systemd priority to zapcore.Level.
func (e journaldEntry) getLevel() zapcore.Level {
	switch e.Priority {
	case "0", "1", "2", "3": // emerg, alert, crit, err
		return zapcore.ErrorLevel
	case "4": // warning
		return zapcore.WarnLevel
	case "5": // notice
		return zapcore.InfoLevel
	case "6": // info
		return zapcore.InfoLevel
	case "7": // debug
		return zapcore.DebugLevel
	default:
		return zapcore.InfoLevel
	}
}

// more closely mimic journalctl's normal output by including the PID, when available.
func (e journaldEntry) getName() string {
	if e.PID != "" {
		return fmt.Sprintf("%s[%s]", e.SyslogIdentifier, e.PID)
	}
	return e.SyslogIdentifier
}

func (e journaldEntry) getTime() time.Time {
	timeAsInt, err := strconv.ParseInt(e.RealtimeTS, 10, 64)
	if err != nil {
		return time.Now()
	}
	return time.UnixMicro(timeAsInt)
}

func (e journaldEntry) getMessage() string {
	return e.Message
}

type logFilter struct {
	all    bool
	filter map[string]bool
}

func newFilter(cfg string) *logFilter {
	self := &logFilter{filter: make(map[string]bool)}
	if cfg != "" {
		opts := strings.Split(cfg, ",")
		for _, opt := range opts {
			if opt == "all" {
				self.all = true
				continue
			}
			if strings.HasPrefix(opt, "-") {
				self.filter[opt[1:]] = false
				continue
			}
			self.filter[opt] = true
		}
	}

	// never forward our own logs
	self.filter["viam-agent"] = false

	return self
}

func (f *logFilter) shouldLog(entry journaldEntry) bool {
	shouldLog, ok := f.filter[entry.SyslogIdentifier]
	if !ok {
		return f.all
	}
	return shouldLog
}
