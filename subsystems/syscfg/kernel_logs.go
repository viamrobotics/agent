package syscfg

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.uber.org/zap/zapcore"
	"go.viam.com/rdk/logging"
)

// KernelLogForwarder handles forwarding kernel logs to the cloud.
type KernelLogForwarder struct {
	logger logging.Logger
	cfg    utils.SystemConfiguration
	cmd    *exec.Cmd
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup // waitgroup to track the reader goroutine

	// mu protects access to cmd and cfg
	mu sync.RWMutex
}

// NewKernelLogForwarder creates a new kernel log forwarder.
func NewKernelLogForwarder(ctx context.Context, logger logging.Logger, cfg utils.SystemConfiguration) *KernelLogForwarder {
	ctx, cancel := context.WithCancel(ctx)
	return &KernelLogForwarder{
		logger: logger,
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

// cleanup stops the kernel log forwarding process.
func (k *KernelLogForwarder) cleanup() error {
	if k.cmd == nil {
		return nil
	}

	// Cancel the context to signal the reader goroutine to stop
	k.cancel()

	// Create a fresh context for the cleanup operation
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Interrupt the process first for a clean shutdown
	if err := k.cmd.Process.Signal(os.Interrupt); err != nil {
		k.logger.Warn("Failed to interrupt kernel log process:", err)
	}

	// Wait for the process to exit with a timeout
	done := make(chan error, 1)
	go func() {
		done <- k.cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil && !strings.Contains(err.Error(), "signal:") {
			k.logger.Warn("Process exited with error:", err)
		}
	case <-cleanupCtx.Done():
		// Process didn't exit gracefully, force kill
		if err := k.cmd.Process.Kill(); err != nil {
			k.logger.Warn("Failed to kill process:", err)
		}
		<-done // Drain channel
	}

	// Wait for the reader goroutine to finish
	k.wg.Wait()

	// Reset state
	k.cmd = nil
	k.logger.Info("Stopped Kernel logs forwarding")

	// Create a new context for future starts
	k.ctx, k.cancel = context.WithCancel(context.Background())

	return nil
}

// Start begins forwarding kernel logs if enabled.
func (k *KernelLogForwarder) Start() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// If forwarding is disabled and we have a running command, stop it
	if !k.cfg.ForwardKernelLogs && k.cmd != nil {
		return k.cleanup()
	}

	// If forwarding is disabled or we already have a running command, do nothing
	if !k.cfg.ForwardKernelLogs || k.cmd != nil {
		return nil
	}

	if _, err := exec.LookPath("journalctl"); err != nil {
		k.logger.Error("journalctl not available, kernel log forwarding disabled")
		return nil
	}

	cmd := exec.Command("journalctl", "-f", "-k", "-o", "json")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return errw.Wrap(err, "creating stdout pipe")
	}

	if err := cmd.Start(); err != nil {
		return errw.Wrap(err, "starting kernel log forwarding")
	}

	// Start a goroutine to read and process the output
	k.wg.Add(1)
	go func() {
		defer k.wg.Done()
		defer func() {
			if err := stdout.Close(); err != nil {
				k.logger.Error(errw.Wrap(err, "closing stdout"))
			}
		}()
		decoder := json.NewDecoder(stdout)
		for {
			select {
			case <-k.ctx.Done():
				return
			default:
				var entry struct {
					Message          string `json:"MESSAGE"`
					Priority         string `json:"PRIORITY"`
					SyslogIdentifier string `json:"SYSLOG_IDENTIFIER"`
					BootID           string `json:"_BOOT_ID"`
					RealtimeTS       string `json:"__REALTIME_TIMESTAMP"`
					MonotonicTS      string `json:"__MONOTONIC_TIMESTAMP"`
				}
				if err := decoder.Decode(&entry); err != nil {
					// Ignore EOF errors as they're expected when the stream ends
					if err != io.EOF {
						k.logger.Error(errw.Wrap(err, "decoding journalctl output"))
					}
					return // Exit goroutine on any error to prevent tight loops
				}

				// Use the shared levels map from utils/logger.go
				level := getLevel(entry.Priority)

				// Convert timestamps to readable format
				realtime := "unknown"
				if ts, err := strconv.ParseInt(entry.RealtimeTS, 10, 64); err == nil {
					realtime = time.Unix(0, ts*1000).UTC().Format(time.RFC3339Nano)
				}

				monotonic := "unknown"
				if ts, err := strconv.ParseInt(entry.MonotonicTS, 10, 64); err == nil {
					monotonic = fmt.Sprintf("%s since boot", time.Duration(ts).String())
				}

				// Format message with additional context
				message := entry.Message
				context := []string{}
				context = append(context, fmt.Sprintf("syslog_id=%s", entry.SyslogIdentifier))
				context = append(context, fmt.Sprintf("boot_id=%s", entry.BootID))
				context = append(context, fmt.Sprintf("realtime=%s", realtime))
				context = append(context, fmt.Sprintf("monotonic=%s", monotonic))
				message = fmt.Sprintf("[%s] %s", strings.Join(context, " "), message)

				logEntry := &logging.LogEntry{
					Entry: zapcore.Entry{
						Level:      level,
						Time:       time.Now().UTC(),
						LoggerName: k.logger.Desugar().Name(),
						Message:    message,
						Caller:     zapcore.EntryCaller{Defined: false},
					},
				}

				k.logger.Write(logEntry)
			}
		}
	}()

	k.logger.Info("Started Kernel logs forwarding")
	k.cmd = cmd
	return nil
}

// Stop stops the kernel log forwarding.
func (k *KernelLogForwarder) Stop() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	return k.cleanup()
}

// Update updates the kernel log forwarding configuration.
func (k *KernelLogForwarder) Update(cfg utils.SystemConfiguration) error {
	k.mu.Lock()
	k.cfg = cfg
	k.mu.Unlock()
	return nil
}

// getLevel converts a systemd priority to zapcore.Level.
func getLevel(priority string) zapcore.Level {
	switch priority {
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
