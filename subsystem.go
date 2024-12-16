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
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	errw "github.com/pkg/errors"
	autils "github.com/viamrobotics/agent/utils"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/rdk/logging"
)

const (
	ShortFailTime   = time.Second * 30
	StartTimeout    = time.Minute
	StopTermTimeout = time.Second * 30
	StopKillTimeout = time.Second * 10
)

var ErrSubsystemDisabled = errors.New("subsystem disabled")

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
	Update(ctx context.Context, cfg *pb.DeviceSubsystemConfig, newVersion bool) (bool, error)
}

// AgentSubsystem is a wrapper for the real subsystems, mostly allowing sharing of download/update code.
type AgentSubsystem struct {
	mu        sync.Mutex
	CacheData *CacheData
	startTime *time.Time
	disable   bool

	name   string
	logger logging.Logger
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
		return ErrSubsystemDisabled
	}

	info, ok := s.CacheData.Versions[s.CacheData.CurrentVersion]
	if !ok {
		s.CacheData.CurrentVersion = "unknown"
		info = &VersionInfo{Version: s.CacheData.CurrentVersion}
		s.CacheData.Versions[s.CacheData.CurrentVersion] = info
		s.logger.Warnf("cache info not found for %s, version: %s", s.name, s.CacheData.CurrentVersion)
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
	if s.disable {
		return nil
	}
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
	logger logging.Logger,
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

	cache := &CacheData{
		Versions: make(map[string]*VersionInfo),
	}

	cacheFilePath := filepath.Join(ViamDirs["cache"], fmt.Sprintf("%s.json", s.name))
	//nolint:gosec
	cacheBytes, err := os.ReadFile(cacheFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.logger.Error(err)
		}
	} else {
		err = json.Unmarshal(cacheBytes, cache)
		if err != nil {
			s.logger.Error(errw.Wrap(err, "parsing subsystem cache, using new defaults"))
			s.CacheData = &CacheData{
				Versions: make(map[string]*VersionInfo),
			}
			return nil
		}
	}

	s.CacheData = cache
	return nil
}

// saveCache should only be run when protected by mutex locks. Use SaveCache() for normal use.
func (s *AgentSubsystem) saveCache() error {
	cacheFilePath := filepath.Join(ViamDirs["cache"], fmt.Sprintf("%s.json", s.name))

	cacheData, err := json.Marshal(s.CacheData)
	if err != nil {
		return err
	}
	//nolint:gosec
	return errors.Join(os.WriteFile(cacheFilePath, cacheData, 0o644), SyncFS(cacheFilePath))
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
	println("update for", s.name)
	s.mu.Lock()
	defer s.mu.Unlock()

	var needRestart bool

	if s.disable != cfg.GetDisable() {
		s.disable = cfg.GetDisable()
		needRestart = true
		if s.disable {
			s.logger.Infof("%s %s", s.name, "disabled")
			return true, nil
		} else {
			s.logger.Infof("%s %s", s.name, "enabled")
		}
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
			// No update, but let the inner logic run if needed.
			return s.tryInner(ctx, cfg, needRestart)
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
		//nolint:gosec
		if err := os.Chmod(verData.UnpackedPath, 0o755); err != nil {
			return needRestart, err
		}
	} else {
		//nolint:gosec
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
	s.logger.Infof("%s updated from %s to %s", s.name, s.CacheData.PreviousVersion, s.CacheData.CurrentVersion)
	needRestart = true

	// record the cache
	err = s.saveCache()
	if err != nil {
		return needRestart, err
	}

	// if the subsystem has its own additional update code, run it
	return s.tryInner(ctx, cfg, needRestart)
}

func (s *AgentSubsystem) tryInner(ctx context.Context, cfg *pb.DeviceSubsystemConfig, newVersion bool) (bool, error) {
	inner, ok := s.inner.(updatable)
	if ok {
		return inner.Update(ctx, cfg, newVersion)
	}

	return newVersion, nil
}

// InternalSubsystem is shared start/stop/update code between "internal" (not viam-server) subsystems.
type InternalSubsystem struct {
	// only set during New
	name      string
	cmdArgs   []string
	logger    logging.Logger
	cfgPath   string
	uploadAll bool

	// protected by mutex
	mu        sync.Mutex
	cmd       *exec.Cmd
	running   bool
	shouldRun bool
	lastExit  int
	exitChan  chan struct{}

	// for blocking start/stop/check ops while another is in progress
	startStopMu sync.Mutex
}

func NewInternalSubsystem(name string, extraArgs []string, logger logging.Logger, uploadAll bool) (*InternalSubsystem, error) {
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	if logger == nil {
		return nil, errors.New("logger cannot be nil")
	}

	cfgPath := path.Join(ViamDirs["etc"], name+".json")

	is := &InternalSubsystem{
		name:      name,
		cmdArgs:   append([]string{"--config", cfgPath}, extraArgs...),
		cfgPath:   cfgPath,
		logger:    logger,
		uploadAll: uploadAll,
	}
	return is, nil
}

func (is *InternalSubsystem) Start(ctx context.Context) error {
	is.startStopMu.Lock()
	defer is.startStopMu.Unlock()

	is.mu.Lock()

	if is.running {
		is.mu.Unlock()
		return nil
	}
	if is.shouldRun {
		is.logger.Warnf("Restarting %s after unexpected exit", is.name)
	} else {
		is.logger.Infof("Starting %s", is.name)
		is.shouldRun = true
	}

	stdio := NewMatchingLogger(is.logger, false, is.uploadAll)
	stderr := NewMatchingLogger(is.logger, true, is.uploadAll)

	//nolint:gosec
	is.cmd = exec.Command(path.Join(ViamDirs["bin"], is.name), is.cmdArgs...)
	is.cmd.Dir = ViamDirs["viam"]
	autils.PlatformSubprocessSettings(is.cmd)
	is.cmd.Stdout = stdio
	is.cmd.Stderr = stderr

	// watch for this line in the logs to indicate successful startup
	c, err := stdio.AddMatcher("checkStartup", regexp.MustCompile(`startup complete`), false)
	if err != nil {
		is.mu.Unlock()
		return err
	}
	defer stdio.DeleteMatcher("checkStartup")

	err = is.cmd.Start()
	if err != nil {
		is.mu.Unlock()
		return errw.Wrapf(err, "starting %s", is.name)
	}
	is.running = true
	is.exitChan = make(chan struct{})

	// must be unlocked before spawning goroutine
	is.mu.Unlock()
	go func() {
		err := is.cmd.Wait()
		is.mu.Lock()
		defer is.mu.Unlock()
		is.running = false
		is.logger.Infof("%s exited", is.name)
		if err != nil {
			is.logger.Errorw("error while getting process status", "error", err)
		}
		if is.cmd.ProcessState != nil {
			is.lastExit = is.cmd.ProcessState.ExitCode()
			if is.lastExit != 0 {
				is.logger.Errorw("non-zero exit code", "exit code", is.lastExit)
			}
		}
		close(is.exitChan)
	}()

	select {
	case <-c:
		is.logger.Infof("%s started", is.name)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(StartTimeout):
		return errw.New("startup timed out")
	case <-is.exitChan:
		return errw.New("startup failed")
	}
}

func (is *InternalSubsystem) Stop(ctx context.Context) error {
	is.startStopMu.Lock()
	defer is.startStopMu.Unlock()

	is.mu.Lock()
	running := is.running
	is.shouldRun = false
	is.mu.Unlock()

	if !running {
		return nil
	}

	// interrupt early in startup
	if is.cmd == nil {
		return nil
	}

	is.logger.Infof("Stopping %s", is.name)

	err := is.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		is.logger.Error(err)
	}

	if is.waitForExit(ctx, StopTermTimeout) {
		is.logger.Infof("%s successfully stopped", is.name)
		return nil
	}

	is.logger.Warnf("%s refused to exit, killing", is.name)
	autils.PlatformKill(is.logger, is.cmd)

	if is.waitForExit(ctx, StopKillTimeout) {
		is.logger.Infof("%s successfully killed", is.name)
		return nil
	}

	return errw.Errorf("%s process couldn't be killed", is.name)
}

func (is *InternalSubsystem) waitForExit(ctx context.Context, timeout time.Duration) bool {
	is.mu.Lock()
	exitChan := is.exitChan
	running := is.running
	is.mu.Unlock()

	if !running {
		return true
	}

	select {
	case <-exitChan:
		return true
	case <-ctx.Done():
		return false
	case <-time.After(timeout):
		return false
	}
}

func (is *InternalSubsystem) Update(ctx context.Context, cfg *pb.DeviceSubsystemConfig, newVersion bool) (bool, error) {
	jsonBytes, err := cfg.GetAttributes().MarshalJSON()
	if err != nil {
		return true, err
	}

	fileBytes, err := os.ReadFile(is.cfgPath)
	// If no changes, only restart if there was a new version.
	if err == nil && bytes.Equal(fileBytes, jsonBytes) {
		return newVersion, nil
	}

	// If an error reading the config file, restart and return the error
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return true, err
	}

	// If attribute changes, restart after writing the new config file.
	//nolint:gosec
	return true, errors.Join(os.WriteFile(is.cfgPath, jsonBytes, 0o644), SyncFS(is.cfgPath))
}
