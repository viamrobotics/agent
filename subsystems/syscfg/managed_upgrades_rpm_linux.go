package syscfg

import (
	"context"
	"errors"
	"os/exec"

	errw "github.com/pkg/errors"
)

type rpmPackageManager struct {
	useDnf bool
}

func (r rpmPackageManager) needsReboot(ctx context.Context) bool {
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
	return pkgCmd(ctx, r.getProgram(), "install", "-y", "needs-restarting")
}

func (r rpmPackageManager) runUpgrade(ctx context.Context, securityOnly bool) error {
	if err := r.ensureNeedsRestarting(ctx); err != nil {
		return errw.Wrap(err, "failed to locate or install needs-restarting")
	}
	args := []string{"upgrade", "-y"}
	if securityOnly {
		args = append(args, "--security")
	}
	return pkgCmd(ctx, r.getProgram(), args...)
}
