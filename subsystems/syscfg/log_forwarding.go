package syscfg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	errw "github.com/pkg/errors"
	"go.uber.org/zap/zapcore"
	"go.viam.com/rdk/logging"
)

// cleanup stops the kernel log forwarding process.
func (s *syscfg) stopLogForwarding(ctx context.Context) error {
	if s.journalCmd == nil {
		return nil
	}

	// Cancel the context to signal the reader goroutine to stop
	s.cancelFunc()

	// Create a fresh context for the cleanup operation
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Interrupt the process first for a clean shutdown
	if err := s.journalCmd.Process.Signal(os.Interrupt); err != nil {
		s.logger.Warn("Failed to interrupt kernel log process:", err)
	}

	// Wait for the process to exit with a timeout
	done := make(chan error, 1)
	go func() {
		done <- s.journalCmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil && !strings.Contains(err.Error(), "signal:") {
			s.logger.Warn("Process exited with error:", err)
		}
	case <-cleanupCtx.Done():
		// Process didn't exit gracefully, force kill
		if err := s.journalCmd.Process.Kill(); err != nil {
			s.logger.Warn("Failed to kill process:", err)
		}
		<-done // Drain channel
	}

	// Wait for the reader goroutine to finish
	s.logWorkers.Wait()

	// Reset state
	s.journalCmd = nil
	s.logger.Info("Stopped Kernel logs forwarding")

	return nil
}

// Start begins forwarding kernel logs if enabled.
func (s *syscfg) startLogForwarding(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If forwarding is disabled or we already have a running command, do nothing
	if s.cfg.ForwardSystemLogs == "" || s.journalCmd != nil {
		return nil
	}

	if _, err := exec.LookPath("journalctl"); err != nil {
		s.logger.Error("journalctl not available, kernel log forwarding disabled")
		s.noJournald = true
		return nil
	}

	cancelCtx, cancelFunc := context.WithCancel(context.Background())

	cmd := exec.CommandContext(cancelCtx, "journalctl", "-f", "-o", "json")
	cmd.Cancel = func() error {
		// will send a signal to do this the "nice way"
		return errw.Wrap(s.journalCmd.Process.Signal(syscall.SIGTERM), "sending SIGTERM to journalctl")
	}
	// if the nice way above fails for more than ten seconds, it'll more forcibly kill the process
	cmd.WaitDelay = time.Second * 10

	// use custom buffers so we can watch for data
	var stdout, stderr *bytes.Buffer
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return errw.Wrap(err, "starting journalctl for log forwarding")
	}

	s.journalCmd = cmd
	s.cancelFunc = cancelFunc

	// this will let us only log services we're interested in
	filter := newFilter(s.cfg.ForwardSystemLogs)


	// Start a goroutine to read and process the output
	s.logWorkers.Add(1)
	go func() {
		defer s.logWorkers.Done()
		defer func() {
			s.cancelFunc()
			if err := s.journalCmd.Wait(); err != nil {
				s.logger.Error(errw.Wrap(err, "stopping journalctl"))
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			s.cancelFunc = nil
			s.journalCmd = nil
		}()
		decoder := json.NewDecoder(stdout)

		for {
			if ctx.Err() != nil {
				return
			}

			s.logHealth.MarkGood()

			if stderr.Available() > 0 {
				// sleep one second in case a write is taking a while, so we get a more complete message
				if !s.logHealth.Sleep(cancelCtx, time.Second) {
					return
				}
				s.logger.Errorf("unexpected error output from journalctl: %s", stderr.String())
			}

			if stdout.Available() > 0 {
				var entry journaldEntry
				if err := decoder.Decode(&entry); err != nil {
					// Ignore EOF errors as they're expected when the stream ends
					if err != io.EOF {
						s.logger.Error(errw.Wrap(err, "decoding journalctl output"))
					}
					return
				}

				if !filter.shouldLog(entry) {
					continue
				}

				logEntry := &logging.LogEntry{
					Entry: zapcore.Entry{
						Level:      entry.getLevel(),
						Time:       entry.getTime(),
						LoggerName: entry.getName(),
						Message:    entry.getMessage(),
						//Caller:     zapcore.EntryCaller{Defined: false},
					},
				}

				s.logger.Write(logEntry)
			}
		}
	}()

	s.logger.Info("Started Kernel logs forwarding")
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

// more closely mimic journalctl's normal output by including the PID, when available
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
	return time.Unix(0, timeAsInt)
}

func (e journaldEntry) getMessage() string {
	return e.Message
}

func (e journaldEntry) shouldLog() bool {
	return false
}

type logFilter struct {
	all bool
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

	return self
}

func (f *logFilter) shouldLog(entry journaldEntry) bool {
	shouldLog, ok := f.filter[entry.SyslogIdentifier]
	if !ok {
		return f.all
	}
	return shouldLog
}
