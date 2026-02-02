package networking

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	semver "github.com/Masterminds/semver/v3"
	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
)

func (n *Subsystem) checkBluetoothdVersion(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*15)
	defer cancel()
	cmd := exec.CommandContext(timeoutCtx, "bluetoothctl", "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "running 'bluetoothctl version' failed and returned: %s", string(output))
	}

	matches := regexp.MustCompile(`Version\s+([0-9]+\.[0-9]+)`).FindSubmatch(output)

	if len(matches) != 2 {
		n.logger.Warnf("cannot parse output (%s) returned from 'bluetoothctl version'", output)
		return nil
	}

	sv, err := semver.NewVersion(string(matches[1]))
	if err != nil {
		n.logger.Warn(err)
		return nil
	}

	if !sv.GreaterThanEqual(semver.MustParse("5.50")) {
		n.logger.Warnf("bluetooth version %s is less than 5.50, functionality may be limited", string(matches[1]))
	}
	return nil
}

func getSectionName(line string) (string, bool) {
	sectionRegex := regexp.MustCompile(`(#|//)?\s*\[(\w+)\]`)
	matches := sectionRegex.FindStringSubmatch(line)
	var isCommented bool
	if len(matches) != 3 {
		return "", isCommented
	}
	if matches[1] != "" {
		isCommented = true
	}
	return matches[2], isCommented
}

func getKeyValue(line string) (string, string, bool) {
	// submatches for comment, key, and value
	kvRegex := regexp.MustCompile(`(#|//)?\s*(\w+)\s*=\s*(\w+)`)
	matches := kvRegex.FindStringSubmatch(line)
	var isCommented bool
	if len(matches) != 4 {
		return "", "", isCommented
	}
	if matches[1] != "" {
		isCommented = true
	}
	return matches[2], matches[3], isCommented
}

func (n *Subsystem) ensureBluetoothConfiguration(ctx context.Context) error {
	// Read the entire config file
	content, err := os.ReadFile(BluezConfigPath)
	if err != nil {
		return errw.Wrapf(err, "reading %s", BluezConfigPath)
	}

	lines := strings.Split(string(content), "\n")
	var updatedLines []string

	// track what we've parsed so far
	var inGeneralSection, reverseDiscoveryFound, repairingFound bool

	for _, line := range lines {
		name, comment := getSectionName(line)
		if !comment && name == "General" {
			inGeneralSection = true
			updatedLines = append(updatedLines, line)
			continue
		}

		// we were in the general section and are about to leave it
		if inGeneralSection && !comment && name != "" {
			if !reverseDiscoveryFound || !repairingFound {
				updatedLines = append(updatedLines, "")
				updatedLines = append(updatedLines, "# Viam Agent requirements for bluetooth provisioning and tethering")

				if !reverseDiscoveryFound {
					updatedLines = append(updatedLines, "ReverseServiceDiscovery = false")
				}
				if !repairingFound {
					updatedLines = append(updatedLines, "JustWorksRepairing = always")
				}

				updatedLines = append(updatedLines, "")
			}

			updatedLines = append(updatedLines, line)
			inGeneralSection = false
			continue
		}

		if inGeneralSection {
			key, value, comment := getKeyValue(line)
			if comment {
				updatedLines = append(updatedLines, line)
				continue
			}
			if key == "ReverseServiceDiscovery" {
				reverseDiscoveryFound = true
				if value != "false" {
					updatedLines = append(updatedLines, "ReverseServiceDiscovery = false")
					continue
				}
			}
			if key == "JustWorksRepairing" {
				repairingFound = true
				if value != "always" {
					updatedLines = append(updatedLines, "JustWorksRepairing = always")
					continue
				}
			}
		}

		updatedLines = append(updatedLines, line)
	}

	// Only write the file if changes were made
	isNew, err := utils.WriteFileIfNew(BluezConfigPath, []byte(strings.Join(updatedLines, "\n")))
	if err != nil {
		return errw.Wrapf(err, "writing updated configuration to %s", BluezConfigPath)
	}

	if isNew {
		n.logger.Infof("Updated bluetooth configuration %s", BluezConfigPath)
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*15)
		defer cancel()
		cmd := exec.CommandContext(timeoutCtx, "systemctl", "restart", "bluetooth")
		if output, err := cmd.CombinedOutput(); err != nil {
			return errw.Wrapf(err, "restarting bluetooth: %s", string(output))
		}
		n.logger.Info("Restarted bluetooth service")
	} else {
		n.logger.Debug("no changes to bluetooth configuration needed")
	}
	return nil
}
