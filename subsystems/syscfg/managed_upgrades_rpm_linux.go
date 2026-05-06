package syscfg

import (
	"context"
	"errors"
	"os/exec"
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

func (r rpmPackageManager) runUpgrade(ctx context.Context, securityOnly bool) error {
	args := []string{"upgrade", "-y"}
	if securityOnly {
		args = append(args, "--security")
	}
	program := "yum"
	if r.useDnf {
		program = "dnf"
	}
	return pkgCmd(ctx, program, args...)
}
