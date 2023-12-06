package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	errw "github.com/pkg/errors"
	"go.uber.org/zap"
	pb "go.viam.com/api/app/agent/v1"
)

const (
	ShortFailTime = time.Second * 30
)

// BasicSubsystem is the minimal interface.
type BasicSubsystem interface {
	// Start runs the subsystem
	Start(ctx context.Context) error

	// Stop signals the subsystem to shutdown
	Stop(ctx context.Context) error

	// HealthCheck reports if a subsystem is running correctly (it is restarted if not)
	HealthCheck(ctx context.Context) error
}

// updatable is if a wrapped subsystem has it's own (additional) update code to run.
type updatable interface {
	Update(ctx context.Context, cfg *pb.DeviceSubsystemConfig) (bool, error)
}

// AgentSubsystem is a wrapper for the real subsystems, mostly allowing sharing of download/update code.
type AgentSubsystem struct {
	mu        sync.Mutex
	CacheData *CacheData
	startTime *time.Time
	disable   bool

	name   string
	logger *zap.SugaredLogger
	inner  BasicSubsystem
}

// CacheData stores VersionInfo and the current/previous versions for (TODO) rollback.
type CacheData struct {
	CurrentVersion  string                  `json:"current_version"`
	PreviousVersion string                  `json:"previous_version"`
	Versions        map[string]*VersionInfo `json:"versions"`
}

// VersionInfo records details about each version of a subsystem.
type VersionInfo struct {
	Version        string
	URL            string
	DlPath         string
	DlSHA          []byte
	UnpackedPath   string
	UnpackedSHA    []byte
	SymlinkPath    string
	Installed      time.Time
	StartCount     uint
	LongFailCount  uint
	ShortFailCount uint
}

// Version returns the running version.
func (s *AgentSubsystem) Version() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CacheData != nil {
		return s.CacheData.CurrentVersion
	}
	return ""
}

// Start starts the subsystem.
func (s *AgentSubsystem) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.disable {
		return nil
	}

	info, ok := s.CacheData.Versions[s.CacheData.CurrentVersion]
	if !ok {
		return errw.Errorf("cache info not found for %s, version: %s", s.name, s.CacheData.CurrentVersion)
	}
	info.StartCount++
	start := time.Now()
	s.startTime = &start
	err := s.saveCache()
	if err != nil {
		return err
	}
	return s.inner.Start(ctx)
}

// Stop stops the subsystem.
func (s *AgentSubsystem) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startTime = nil
	return s.inner.Stop(ctx)
}

// HealthCheck calls the inner subsystem's HealthCheck() to verify, and logs failures/successes.
func (s *AgentSubsystem) HealthCheck(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.inner.HealthCheck(ctx)
	if err != nil {
		if s.startTime == nil {
			return err
		}
		failTime := time.Since(*s.startTime)

		info, ok := s.CacheData.Versions[s.CacheData.CurrentVersion]
		if !ok {
			return errors.Join(err, errw.Errorf("cache info not found for %s, version: %s", s.name, s.CacheData.CurrentVersion))
		}

		if failTime <= ShortFailTime {
			info.ShortFailCount++
		} else {
			info.LongFailCount++
		}
		s.startTime = nil

		// TODO if shortfails exceed a threshold, revert to previous version.

		return errors.Join(err, s.saveCache())
	}

	return nil
}

// NewAgentSubsystem returns a new wrapped subsystem.
func NewAgentSubsystem(
	ctx context.Context,
	name string,
	logger *zap.SugaredLogger,
	subsys BasicSubsystem,
) (*AgentSubsystem, error) {
	sub := &AgentSubsystem{name: name, logger: logger, inner: subsys}
	err := sub.LoadCache()
	if err != nil {
		return nil, err
	}
	return sub, nil
}

// LoadCache loads the cached data for the subsystem from disk.
func (s *AgentSubsystem) LoadCache() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cacheFilePath := filepath.Join(ViamDirs["cache"], fmt.Sprintf("%s.json", s.name))
	cacheBytes, err := os.ReadFile(cacheFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	s.CacheData = &CacheData{
		Versions: make(map[string]*VersionInfo),
	}

	if err == nil {
		return json.Unmarshal(cacheBytes, s.CacheData)
	}

	return nil
}

// saveCache should only be run when protected by mutex locks. Use SaveCache() for normal use.
func (s *AgentSubsystem) saveCache() error {
	cacheFilePath := filepath.Join(ViamDirs["cache"], fmt.Sprintf("%s.json", s.name))

	cacheData, err := json.Marshal(s.CacheData)
	if err != nil {
		return err
	}

	return os.WriteFile(cacheFilePath, cacheData, 0o644)
}

// SaveCache saves the cached data to disk.
func (s *AgentSubsystem) SaveCache() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.saveCache()
}

// Update is the main function of the AgentSubsystem wrapper, as it's shared between subsystems. Returns true if a restart is needed.
//
//nolint:gocognit
func (s *AgentSubsystem) Update(ctx context.Context, cfg *pb.DeviceSubsystemConfig) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var needRestart bool

	if s.disable != cfg.GetDisable() {
		s.disable = cfg.GetDisable()
		needRestart = true
		action := "enabled"
		if s.disable {
			action = "disabled"
		}
		s.logger.Infof("%s %s", s.name, action)
	}

	updateInfo := cfg.GetUpdateInfo()

	// check if we already have the version given by the cloud
	verData, ok := s.CacheData.Versions[updateInfo.GetVersion()]
	//nolint:nestif
	if ok && s.CacheData.CurrentVersion == updateInfo.GetVersion() {
		// if a known version, make sure the symlink is correct
		same, err := CheckIfSame(verData.DlPath, verData.SymlinkPath)
		if err != nil {
			return needRestart, err
		}
		if !same {
			if err := ForceSymlink(verData.UnpackedPath, verData.SymlinkPath); err != nil {
				return needRestart, err
			}
		}

		// check for matching shasum, which won't be available for pin_url
		checkSum := updateInfo.GetSha256()

		// with pin_url, no SHA is available from the cloud, so we check the local copy for corruption and matching url.
		if len(updateInfo.GetSha256()) <= 1 && verData.URL == updateInfo.GetUrl() {
			checkSum = verData.UnpackedSHA
		}

		shasum, err := GetFileSum(verData.UnpackedPath)
		if err == nil && bytes.Equal(shasum, checkSum) {
			return needRestart, nil
		}
	}

	// this is a new version, so instantiate the basics
	if !ok {
		verData = &VersionInfo{Version: updateInfo.GetVersion()}
		s.CacheData.Versions[updateInfo.GetVersion()] = verData
		s.logger.Infof("new version (%s) found for %s", verData.Version, s.name)
	}
	// always record the URL, it may be updated for "customURL" versions
	verData.URL = updateInfo.GetUrl()

	// download and record the sha of the download itself
	var err error
	verData.DlPath, err = DownloadFile(ctx, updateInfo.GetUrl())
	if err != nil {
		return needRestart, errw.Wrapf(err, "downloading %s subsystem", s.name)
	}
	verData.DlSHA, err = GetFileSum(verData.DlPath)
	if err != nil {
		return needRestart, errw.Wrap(err, "getting file shasum")
	}

	// extract and verify sha of contents if it's a compressed file
	if updateInfo.GetFormat() == pb.PackageFormat_PACKAGE_FORMAT_XZ ||
		updateInfo.GetFormat() == pb.PackageFormat_PACKAGE_FORMAT_XZ_EXECUTABLE {
		verData.UnpackedPath, err = DecompressFile(verData.DlPath)
		if err != nil {
			return needRestart, errw.Wrapf(err, "decompressing %s subsystem", s.name)
		}
	} else {
		verData.UnpackedPath = verData.DlPath
	}

	shasum, err := GetFileSum(verData.UnpackedPath)
	if err != nil {
		return needRestart, errw.Wrap(err, "getting file shasum")
	}
	verData.UnpackedSHA = shasum
	if len(updateInfo.GetSha256()) > 1 && !bytes.Equal(shasum, updateInfo.GetSha256()) {
		//nolint:goerr113
		return needRestart, fmt.Errorf(
			"sha256 (%s) of downloaded file (%s) does not match config (%s)",
			base64.StdEncoding.EncodeToString(shasum),
			verData.UnpackedPath,
			base64.StdEncoding.EncodeToString(updateInfo.GetSha256()),
		)
	}

	// chmod with execute permissions if the file is executable
	if updateInfo.GetFormat() == pb.PackageFormat_PACKAGE_FORMAT_EXECUTABLE ||
		updateInfo.GetFormat() == pb.PackageFormat_PACKAGE_FORMAT_XZ_EXECUTABLE {
		if err := os.Chmod(verData.UnpackedPath, 0o755); err != nil {
			return needRestart, err
		}
	} else {
		if err := os.Chmod(verData.UnpackedPath, 0o644); err != nil {
			return needRestart, err
		}
	}

	// symlink the extracted file to bin
	verData.SymlinkPath = path.Join(ViamDirs["bin"], updateInfo.GetFilename())
	if err = ForceSymlink(verData.UnpackedPath, verData.SymlinkPath); err != nil {
		return needRestart, errw.Wrap(err, "creating symlink")
	}

	// update current and previous versions
	if s.CacheData.CurrentVersion != s.CacheData.PreviousVersion {
		s.CacheData.PreviousVersion = s.CacheData.CurrentVersion
	}
	s.CacheData.CurrentVersion = updateInfo.GetVersion()
	verData.Installed = time.Now()

	// if we made it here we performed an update and need to restart
	s.logger.Infof("%s updated to %s", s.name, verData.Version)

	// TODO remove this special case after handling restarts directly via force_restart
	if s.name == "viam-server" {
		s.logger.Info("awaiting user restart to run new viam-server version")
	} else {
		needRestart = true
	}

	// record the cache
	err = s.saveCache()
	if err != nil {
		return needRestart, err
	}

	// if the subsystem has it's own additional update code, run it
	inner, ok := s.inner.(updatable)
	if ok {
		return inner.Update(ctx, cfg)
	}

	return needRestart, nil
}
