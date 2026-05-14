package syscfg

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	errw "github.com/pkg/errors"
	"go.viam.com/rdk/logging"
)

type rpmPackageManager struct {
	logger logging.Logger
	useDnf bool
}

// String implements [packageManager].
func (r rpmPackageManager) String() string {
	manager := "yum"
	if r.useDnf {
		manager = "dnf"
	}
	return fmt.Sprintf("rpm(%s)", manager)
}

func (r rpmPackageManager) needsReboot(ctx context.Context) bool {
	if err := r.ensureNeedsRestarting(ctx); err != nil {
		r.logger.Errorw(
			"Could not verify needs-restarting installation to check for reboot status",
			"err", err,
		)
		return false
	}
	// needs-restarting -r exits 1 when a reboot is required, 0 otherwise.
	// Any other non-zero exit is treated as "not required".
	cmd := exec.CommandContext(ctx, "needs-restarting", "-r")
	if err := cmd.Run(); err != nil {
		if err, ok := errors.AsType[*exec.ExitError](err); ok {
			return err.ExitCode() == 1
		}
	}
	return false
}

func (r rpmPackageManager) getProgram() string {
	program := "yum"
	if r.useDnf {
		program = "dnf"
	}
	return program
}

func (r rpmPackageManager) ensureNeedsRestarting(ctx context.Context) error {
	if _, err := exec.LookPath("needs-restarting"); err == nil {
		return nil
	}
	return pkgCmd(ctx, r.logger, r.getProgram(), "install", "-y", "yum-utils")
}

func (r rpmPackageManager) runUpgrade(ctx context.Context, securityOnly bool) error {
	if err := r.ensureNeedsRestarting(ctx); err != nil {
		return errw.Wrap(err, "failed to locate or install needs-restarting")
	}
	args := []string{"upgrade", "-y"}
	if securityOnly {
		args = append(args, "--security")
	}
	return pkgCmd(ctx, r.logger, r.getProgram(), args...)
}
