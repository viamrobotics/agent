package syscfg

import "context"

type rpmPackageManager struct {
	useDnf bool
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
