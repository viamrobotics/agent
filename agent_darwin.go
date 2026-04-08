package agent

import (
	"context"
	_ "embed"
	"errors"
	"os/exec"
	"path/filepath"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	rutils "go.viam.com/rdk/utils"
)

const (
	serviceName = "com.viam.agent"
)

//go:embed com.viam.agent.plist
var serviceFileContents []byte

// InstallNewVersion runs the newly downloaded binary's Install() for installation of launchd service files and the like.
func InstallNewVersion(ctx context.Context, logger logging.Logger) (bool, error) {
	expectedPath := filepath.Join(utils.ViamDirs.Bin, SubsystemName)

	// Run the newly updated version to install launchd service files.
	logger.Info("running viam-agent --install for new version")
	// On macOS, --install may triggers a launchd bootout which kills the running agent's
	// process group before the subprocess can finish bootstrapping and kickstarting the
	// new agent. So start the subprocess in its own process group.
	//nolint:gosec
	cleanup := rutils.SlowLogger(
		ctx,
		"Waiting for new version of viam-agent to finish installing", "", "",
		logger,
	)
	defer cleanup()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()

	cmd := exec.Command(expectedPath, "--install")
	utils.PlatformProcSettings(cmd)

	if err := cmd.Start(); err != nil {
		return false, errw.Wrap(err, "error running install step")
	}

	// We intentionally start the Wait() in a goroutine. It is expected that if the plist file
	// is updated, the installer will trigger a bootout, which will kill this agent process before the
	// installer process exits. In that case, this goroutine will be leaked but will exit when the installer completes.
	//
	// If the plist file is unchanged, this goroutine will wait for the installer to exit and then return cleanly.
	doneCh := make(chan struct{})
	go func() {
		if err := cmd.Wait(); err != nil {
			logger.Warnw("error while waiting for --install subprocess to complete", "err", err)
		}
		close(doneCh)
	}()

	select {
	case <-ctx.Done():
		switch {
		case errors.Is(ctx.Err(), context.Canceled):
			// The common case is that the installer will bootstrap and kickstart the new version of agent after this agent process
			// exits.
			//
			// Technically this could also happen if the subprocess had just kicked off and a user/process SIGTERMs the agent, but barring
			// something very wrong, the agent will still be restarted by launchd and re-attempt the update.
			logger.Info("viam-agent shutdown requested, will be restarted by the installer or launchd")
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			logger.Warn("viam-agent timed out while updating, will exit and be restarted by launchd")
		default:
			logger.Warnw("unexpected context error while updating, viam-agent will exit and be restarted by launchd", "error", ctx.Err())
		}
	case <-doneCh:
		logger.Info("viam-agent update completed, will be restarted by launchd")
	}
	return true, nil
}
