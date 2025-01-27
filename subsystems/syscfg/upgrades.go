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

func (s *syscfg) EnforceUpgrades(ctx context.Context) error {
	s.mu.RLock()
	cfg := s.cfg.OSAutoUpgradeType
	s.mu.RUnlock()

	if cfg == "" {
		return nil
	}

	err := checkSupportedDistro()
	if err != nil {
		return err
	}

	if cfg == "disable" || cfg == "disabled" {
		isNew, err := utils.WriteFileIfNew(autoUpgradesPath, []byte(autoUpgradesContentsDisabled))
		if err != nil {
			return err
		}
		if isNew {
			s.logger.Info("Disabled OS auto-upgrades.")
		}
		return nil
	}

	err = verifyInstall()
	if err != nil {
		err = doInstall(ctx)
		if err != nil {
			return err
		}
	}

	securityOnly := cfg == "security"
	confContents, err := generateOrigins(securityOnly)
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

	err = enableTimer()
	if err != nil {
		s.logger.Error(err)
	}
	return nil
}

func checkSupportedDistro() error {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return err
	}

	if strings.Contains(string(data), "VERSION_CODENAME=bookworm") || strings.Contains(string(data), "VERSION_CODENAME=bullseye") {
		return nil
	}

	return errw.New("cannot enable automatic upgrades for unknown distro, only support for Debian bullseye and bookworm is available")
}

// make sure the needed package is installed.
func verifyInstall() error {
	cmd := exec.Command("unattended-upgrade", "-h")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "executing 'unattended-upgrade -h' %s", output)
	}
	return nil
}

func enableTimer() error {
	// enable here
	cmd := exec.Command("systemctl", "enable", "apt-daily-upgrade.timer")
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
func generateOrigins(securityOnly bool) (string, error) {
	cmd := exec.Command("apt-cache", "policy")
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
	releaseRegex := regexp.MustCompile(`release.*o=([^,]+).*n=([^,]+).*`)
	matches := releaseRegex.FindAllStringSubmatch(string(output), -1)

	// use map to reduce to unique set
	releases := map[string]bool{}
	for _, release := range matches {
		// we expect at least an origin and a codename from each line
		if len(release) != 3 {
			continue
		}
		if securityOnly && !strings.Contains(release[2], "security") {
			continue
		}
		releases[fmt.Sprintf(`"origin=%s,codename=%s";`, release[1], release[2])] = true
	}
	return releases
}
