package syscfg

// This file contains tweaks for enabling/disabling unattended upgrades.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
)

const (
	autoUpgradesPath             = "/etc/apt/apt.conf.d/20auto-upgrades"
	autoUpgradesContentsEnabled  = `APT::Periodic::Update-Package-Lists "1";` + "\n" + `APT::Periodic::Unattended-Upgrade "1";` + "\n"
	autoUpgradesContentsDisabled = `APT::Periodic::Update-Package-Lists "1";` + "\n" + `APT::Periodic::Unattended-Upgrade "0";` + "\n"

	unattendedUpgradesPath = "/etc/apt/apt.conf.d/50unattended-upgrades"
)

var supportedCodenames = [...]string{"bookworm", "bullseye", "trixie"}

func isDisabled(mode string) bool {
	return mode == "disable" || mode == "disabled"
}

// runs inside s.mu.Lock().
func (s *Subsystem) EnforceUpgrades(ctx context.Context) error {
	cfg := s.cfg.OSAutoUpgradeType
	if cfg == "" {
		return nil
	}

	// Disabled and managed modes only turn apt's own unattended upgrades off,
	// which works on any apt-based distro. They must not sit behind the codename
	// gate below (which exists for the origins generation the enable path
	// needs): otherwise a managed mode on a distro outside supportedCodenames
	// would run the agent's upgrade loop while the OS's apt-daily-upgrade.timer
	// stays enabled, leaving two upgraders contending for the dpkg lock.
	if isDisabled(cfg) || isManaged(cfg) {
		if _, err := exec.LookPath("apt-get"); err != nil {
			s.logger.Infow("Skipping unattended upgrades configuration", "reason", "no apt-get binary found")
			//nolint:nilerr
			return nil
		}
		err := setTimer(ctx, false)
		if err != nil {
			// Might just be that the package isn't installed yet so systemd reported
			// an error trying to disable a timer that doesn't exist. Log the error
			// just in case but continue.
			s.logger.Warnw("Error disabling unattended upgrades systemd timer", "err", err)
		}
		isNew, err := utils.WriteFileIfNew(autoUpgradesPath, []byte(autoUpgradesContentsDisabled))
		if err != nil {
			return err
		}
		if isNew {
			if isManaged(cfg) {
				s.logger.Infow(
					"Disabled apt unattended-upgrades, OS upgrades are now run by viam-agent instead",
					"os_auto_upgrade_type", cfg,
				)
			} else {
				s.logger.Info("Disabled apt unattended-upgrades, no OS upgrades will be installed automatically.")
			}
		}
		return nil
	}

	unsupportedReason, err := checkSupportedDistro()
	if err != nil {
		return err
	}
	if unsupportedReason != "" {
		s.logger.Warnw("Skipping unattended upgrades configuration", "reason", unsupportedReason)
		return nil
	}

	err = verifyUnattendedUpgrade(ctx)
	if err != nil {
		err = doInstall(ctx)
		if err != nil {
			return err
		}
	}

	securityOnly := cfg == "security"
	confContents, err := generateOrigins(ctx, securityOnly)
	if err != nil {
		return err
	}

	isNew1, err := utils.WriteFileIfNew(autoUpgradesPath, []byte(autoUpgradesContentsEnabled))
	if err != nil {
		return err
	}

	isNew2, err := utils.WriteFileIfNew(unattendedUpgradesPath, []byte(confContents))
	if err != nil {
		return err
	}

	if isNew1 || isNew2 {
		if securityOnly {
			s.logger.Info("Enabled OS auto-upgrades (security only.)")
		} else {
			s.logger.Info("Enabled OS auto-upgrades (full.)")
		}
	}

	err = setTimer(ctx, true)
	if err != nil {
		s.logger.Error(err)
	}
	return nil
}

// checkSupportedDistro checks if the current system supports unattended
// upgrades. It returns a empty string on supported systems, and a string
// explaining why there is no support otherwise. If it is unable to gather the
// required information to check for support an error is returned.
func checkSupportedDistro() (string, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", err
	}

	dataStr := string(data)
	for _, codename := range supportedCodenames {
		if strings.Contains(dataStr, "VERSION_CODENAME="+codename) {
			return "", nil
		}
	}

	return fmt.Sprintf("cannot enable automatic upgrades for unknown distro, only support for Debian %v is available", supportedCodenames), nil
}

// make sure the needed package is installed.
func verifyUnattendedUpgrade(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "unattended-upgrade", "-h")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "executing 'unattended-upgrade -h' %s", output)
	}
	return nil
}

func setTimer(ctx context.Context, enabled bool) error {
	verb := "disable"
	if enabled {
		verb = "enable"
	}
	cmd := exec.CommandContext(ctx, "systemctl", verb, "apt-daily-upgrade.timer")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "executing 'systemctl enable apt-daily-upgrade.timer' %s", output)
	}
	return nil
}

func doInstall(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "apt", "update")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "executing 'apt update' %s", output)
	}

	cmd = exec.CommandContext(ctx, "apt", "install", "-y", "unattended-upgrades")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "executing 'apt install -y unattended-upgrades' %s", output)
	}

	return nil
}

// generates the "Origins-Pattern" section of 50unattended-upgrades file.
func generateOrigins(ctx context.Context, securityOnly bool) (string, error) {
	cmd := exec.CommandContext(ctx, "apt-cache", "policy")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", errw.Wrapf(err, "executing 'apt-cache policy' %s", output)
	}

	releases := generateOriginsInner(securityOnly, output)

	// generate actual file contents
	origins := "Unattended-Upgrade::Origins-Pattern {"
	for release := range releases {
		origins = fmt.Sprintf("%s\n    %s", origins, release)
	}
	origins = fmt.Sprintf("%s\n};\n", origins)
	return origins, nil
}

// inner transformation logic of generateOrigins for testing.
func generateOriginsInner(securityOnly bool, output []byte) map[string]bool {
	// Match the archive (a=) rather than the codename (n=): Ubuntu keeps the
	// "-security" suffix there (a=jammy-security, n=jammy) while Debian carries
	// it in both, so Suite is the one field that identifies security repos on
	// both.
	releaseRegex := regexp.MustCompile(`release.*o=([^,]+).*a=([^,]+).*`)
	matches := releaseRegex.FindAllStringSubmatch(string(output), -1)

	// use map to reduce to unique set
	releases := map[string]bool{}
	for _, release := range matches {
		// we expect at least an origin and an archive from each line
		if len(release) != 3 {
			continue
		}
		if securityOnly && !strings.Contains(release[2], "security") {
			continue
		}
		releases[fmt.Sprintf(`"origin=%s,archive=%s";`, release[1], release[2])] = true
	}
	return releases
}
