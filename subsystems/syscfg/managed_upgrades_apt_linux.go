package syscfg

import (
	"context"
	"os"
	"os/exec"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
)

const rebootRequiredPath = "/var/run/reboot-required"

type aptPackageManager struct{}

func (a aptPackageManager) needsReboot(ctx context.Context) bool {
	_, err := os.Stat(rebootRequiredPath)
	return err == nil
}

func (a aptPackageManager) runUpgrade(ctx context.Context, securityOnly bool) error {
	// Refresh package lists.
	if err := pkgCmd(ctx, "apt-get", "update"); err != nil {
		return err
	}

	if securityOnly {
		return a.runSecurityUpgrade(ctx)
	}
	return a.runFullUpgrade(ctx)
}

func (a aptPackageManager) runFullUpgrade(ctx context.Context) error {
	return pkgCmd(ctx, "apt-get", "upgrade", "-y",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Options::=--force-confdef",
	)
}

func (a aptPackageManager) ensureUnattendedUpgrades(ctx context.Context) error {
	if err := verifyUnattendedUpgrade(ctx); err != nil {
		if installErr := doInstall(ctx); installErr != nil {
			return errw.Wrap(installErr, "installing unattended-upgrades package")
		}
	}
	return nil
}

func (a aptPackageManager) runSecurityUpgrade(ctx context.Context) error {
	// Ensure the unattended-upgrades binary is available, which is used to
	// filter available updates to just security updates.
	if err := a.ensureUnattendedUpgrades(ctx); err != nil {
		return err
	}

	// Generate and write origins config scoped to security repos only.
	confContents, err := generateOrigins(ctx, true)
	if err != nil {
		return errw.Wrap(err, "generating security origins")
	}

	if _, err := utils.WriteFileIfNew(unattendedUpgradesPath, []byte(confContents)); err != nil {
		return errw.Wrap(err, "writing unattended-upgrades config")
	}

	if _, err := utils.WriteFileIfNew(autoUpgradesPath, []byte(autoUpgradesContentsEnabled)); err != nil {
		return errw.Wrap(err, "writing auto-upgrades config")
	}

	cmd := exec.CommandContext(ctx, "unattended-upgrade", "--verbose")
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"APT_LISTCHANGES_FRONTEND=none",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "unattended-upgrade: %s", output)
	}
	return nil
}
