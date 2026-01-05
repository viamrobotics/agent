package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	goutils "go.viam.com/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

var (
	elog debug.Log
	_    svc.Handler = (*agentService)(nil)
)

const serviceName = "viam-agent"

type agentService struct{}

// Execute is the control loop for a windows service.
// This implements svc.Handler and gets called by svc.Run in main().
func (*agentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		c := <-r
		if c.Cmd == svc.Stop || c.Cmd == svc.Shutdown {
			goutils.UncheckedError(elog.Info(1, fmt.Sprintf("%s service stopping", serviceName)))
			changes <- svc.Status{State: svc.StopPending}
			globalCancel()
			break
		} else {
			goutils.UncheckedError(elog.Error(1, fmt.Sprintf("unexpected control request #%d", c)))
		}
	}
	return
}

func main() {
	if inService, err := svc.IsWindowsService(); err != nil {
		panic(err)
	} else if !inService {
		globalLogger.Info("no service detected -- running as normal process")
		utils.IsRunningLocally = true
		commonMain()
		return
	}

	// in service mode we have to alloc our own console to be able to send interrupts
	if r, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("AllocConsole").Call(); r == 0 {
		panic(err)
	}

	var err error
	elog, err = eventlog.Open(serviceName)
	if err != nil {
		return
	}
	defer func() {
		goutils.UncheckedError(elog.Close())
	}()

	goutils.UncheckedError(elog.Info(1, fmt.Sprintf("starting %s service", serviceName)))

	go func() {
		// note: svc.Run() hangs until windows terminates the service via Execute()
		if err := svc.Run(serviceName, &agentService{}); err != nil {
			goutils.UncheckedError(elog.Error(1, fmt.Sprintf("%s service failed: %v", serviceName, err)))
		}
	}()

	commonMain()
	if err := zapChildren(); err != nil {
		goutils.UncheckedError(elog.Error(1, fmt.Sprintf("error killing subtree %s", err)))
	}
	goutils.UncheckedError(elog.Info(1, fmt.Sprintf("%s service stopped", serviceName)))
}

func ignoredSignal(_ os.Signal) bool {
	return false
}

func waitOnline(logger logging.Logger, _ context.Context) {
	logger.Debug("WaitOnline not available on windows yet")
}

func runPlatformProvisioning(_ context.Context, _ utils.AgentConfig, _ *agent.Manager, _ error) bool {
	return false
}

// zapChildren kills any stray processes we might have upon exit.
func zapChildren() error {
	elog, err := eventlog.Open("viam-agent")
	if err != nil {
		// Check error but continue since we want this to work
		elog = nil
	}

	pid := os.Getpid()

	// Use a fixed command string to prevent injection
	//nolint:gosec // WMIC.exe is a fixed command
	cmd := exec.Command("WMIC.exe", "process", "where", fmt.Sprintf("ParentProcessId=%d", pid), "get", "ProcessId")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	lines := strings.Split(string(output), "\r\n")
	if elog != nil {
		goutils.UncheckedError(elog.Info(1, fmt.Sprintf("KillTree stopping %d children of pid %d", len(lines), pid)))
	}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if _, err := strconv.Atoi(line); err != nil {
			continue
		}
		var childPID int
		_, err := fmt.Sscan(line, &childPID)
		if err != nil {
			if elog != nil {
				goutils.UncheckedError(elog.Error(1, fmt.Sprintf("not a valid childProcess line %q, #%s", line, err)))
			}
			continue
		}

		//nolint:gosec // taskkill is a fixed command
		cmd = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(childPID))
		err = cmd.Run()
		if elog != nil {
			if err != nil {
				goutils.UncheckedError(elog.Error(1, fmt.Sprintf("error running taskkill pid %d: #%s", childPID, err)))
			} else {
				goutils.UncheckedError(elog.Info(1, fmt.Sprintf("killed pid %d", childPID)))
			}
		}
	}
	if elog != nil {
		goutils.UncheckedError(elog.Info(1, "KillTree finished"))
	}
	return nil
}
