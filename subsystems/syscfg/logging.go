package syscfg

// This file contains tweaks for logging/journald, such as max size limits.

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"regexp"

	errw "github.com/pkg/errors"
	sysd "github.com/sergeymakinen/go-systemdconf/v2"
	"github.com/sergeymakinen/go-systemdconf/v2/conf"
	"github.com/viamrobotics/agent"
)

var (
	journaldConfPath = "/etc/systemd/journald.conf.d/90-viam.conf"
	defaultLogLimit  = "512M"
)

type LogConfig struct {
	Disable       bool   `json:"disable"`
	SystemMaxUse  string `json:"system_max_use"`
	RuntimeMaxUse string `json:"runtime_max_use"`
}

func (s *syscfg) EnforceLogging() error {
	s.mu.RLock()
	cfg := s.cfg.Logging
	s.mu.RUnlock()
	if cfg.Disable {
		if err := os.Remove(journaldConfPath); err != nil {
			if errw.Is(err, fs.ErrNotExist) {
				return nil
			}
			return errw.Wrapf(err, "deleting %s", journaldConfPath)
		}

		// if journald is NOT enabled, simply return
		//nolint:nilerr
		if err := checkJournaldEnabled(); err != nil {
			return nil
		}

		if err := restartJournald(); err != nil {
			return err
		}
		s.logger.Infof("Logging config disabled. Removing customized %s", journaldConfPath)
		return nil
	}

	if err := checkJournaldEnabled(); err != nil {
		s.logger.Warn("systemd-journald is not enabled, cannot configure logging limits")
		return err
	}

	persistSize := cfg.SystemMaxUse
	tempSize := cfg.RuntimeMaxUse

	if persistSize == "" {
		persistSize = defaultLogLimit
	}

	if tempSize == "" {
		tempSize = defaultLogLimit
	}

	sizeRegEx := regexp.MustCompile(`^[0-9]+[KMGTPE]$`)
	if !(sizeRegEx.MatchString(persistSize) && sizeRegEx.MatchString(tempSize)) {
		return errw.New("logfile size limits must be specificed in bytes, with one optional suffix character [KMGTPE]")
	}

	journalConf := &conf.JournaldFile{
		Journal: conf.JournaldJournalSection{
			SystemMaxUse:  sysd.Value{persistSize},
			RuntimeMaxUse: sysd.Value{tempSize},
		},
	}

	newFileBytes, err := sysd.Marshal(journalConf)
	if err != nil {
		return errw.Wrapf(err, "marshaling new file for %s", journaldConfPath)
	}

	isNew, err1 := agent.WriteFileIfNew(journaldConfPath, newFileBytes)
	if err1 != nil {
		// We may have written a corrupt file, try to remove to salvage at least default behavior.
		if err := os.RemoveAll(journaldConfPath); err != nil {
			return errors.Join(err1, errw.Wrapf(err, "deleting %s", journaldConfPath))
		}
		return err1
	}

	if isNew {
		if err := restartJournald(); err != nil {
			return err
		}
		s.logger.Infof("Updated %s, setting SystemMaxUse=%s and RuntimeMaxUse=%s", journaldConfPath, persistSize, tempSize)
	}
	return nil
}

func restartJournald() error {
	cmd := exec.Command("systemctl", "restart", "systemd-journald")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "executing 'systemctl restart systemd-journald' %s", output)
	}
	return nil
}

func checkJournaldEnabled() error {
	cmd := exec.Command("systemctl", "is-enabled", "systemd-journald")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "executing 'systemctl is-enabled systemd-journald' %s", output)
	}
	return nil
}
