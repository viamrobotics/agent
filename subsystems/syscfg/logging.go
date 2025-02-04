package syscfg

// This file contains tweaks for logging/journald, such as max size limits.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"

	errw "github.com/pkg/errors"
	sysd "github.com/sergeymakinen/go-systemdconf/v2"
	"github.com/sergeymakinen/go-systemdconf/v2/conf"
	"github.com/viamrobotics/agent/utils"
)

var (
	journaldConfPath = "/etc/systemd/journald.conf.d/90-viam.conf"
	defaultLogLimit  = "512M"
)

func (s *syscfg) EnforceLogging() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg.LoggingJournaldRuntimeMaxUseMegabytes < 0 && s.cfg.LoggingJournaldSystemMaxUseMegabytes < 0 {
		if err := os.Remove(journaldConfPath); err != nil {
			if errw.Is(err, fs.ErrNotExist) {
				return nil
			}
			return errw.Wrapf(err, "deleting %s", journaldConfPath)
		}

		// if journald is NOT enabled, simply return
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

	journalConf := &conf.JournaldFile{
		Journal: conf.JournaldJournalSection{},
	}

	persistSize := fmt.Sprintf("%dM", s.cfg.LoggingJournaldSystemMaxUseMegabytes)
	tempSize := fmt.Sprintf("%dM", s.cfg.LoggingJournaldRuntimeMaxUseMegabytes)

	if persistSize == "0M" {
		persistSize = defaultLogLimit
	}

	if tempSize == "0M" {
		tempSize = defaultLogLimit
	}

	if s.cfg.LoggingJournaldSystemMaxUseMegabytes >= 0 {
		journalConf.Journal.SystemMaxUse = sysd.Value{persistSize}
	}

	if s.cfg.LoggingJournaldRuntimeMaxUseMegabytes >= 0 {
		journalConf.Journal.RuntimeMaxUse = sysd.Value{tempSize}
	}

	newFileBytes, err := sysd.Marshal(journalConf)
	if err != nil {
		return errw.Wrapf(err, "marshaling new file for %s", journaldConfPath)
	}

	isNew, err1 := utils.WriteFileIfNew(journaldConfPath, newFileBytes)
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
