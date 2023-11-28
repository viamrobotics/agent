package agent

import (
	"bytes"
	"context"
    "encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	pb "go.viam.com/api/app/agent/v1"
)

const (
	ShortFailTime = time.Second * 30
)

type BasicSubsystem interface {
	// Start runs the subsystem
	Start(ctx context.Context) error

	// Stop signals the subsystem to shutdown
	Stop(ctx context.Context) error

	// HealthCheck reports if a subsystem is running correctly (it is restarted if not)
	HealthCheck(ctx context.Context) error
}

type updatable interface {
	Update(ctx context.Context, cfg *pb.DeviceSubsystemConfig) (bool, error)
}

type AgentSubsystem struct {
	mu        sync.Mutex
	CacheData *CacheData
	startTime *time.Time
	disable   bool

	name   string
	logger *zap.SugaredLogger
	inner  BasicSubsystem
}

type CacheData struct {
	CurVersion  string
	PrevVersion string
	Versions    map[string]*VersionInfo
}

type VersionInfo struct {
	Version        string
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

func (s *AgentSubsystem) Version() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CacheData != nil {
		return s.CacheData.CurVersion
	}
	return ""
}

func (s *AgentSubsystem) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.disable {
		return nil
	}

	info, ok := s.CacheData.Versions[s.CacheData.CurVersion]
	if !ok {
		return errors.Errorf("cache info not found for %s, version: %s", s.name, s.CacheData.CurVersion)
	}
	info.StartCount++
	start := time.Now()
	s.startTime = &start
	err := s.saveCache(ctx)
	if err != nil {
		return err
	}
	return s.inner.Start(ctx)
}

func (s *AgentSubsystem) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startTime = nil
	return s.inner.Stop(ctx)
}

func (s *AgentSubsystem) HealthCheck(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.inner.HealthCheck(ctx)
	if err != nil {
		if s.startTime == nil {
			return err
		}
		failTime := time.Now().Sub(*s.startTime)

		info, ok := s.CacheData.Versions[s.CacheData.CurVersion]
		if !ok {
			return errors.Wrapf(err, "cache info not found for %s, version: %s", s.name, s.CacheData.CurVersion)
		}

		if failTime <= ShortFailTime {
			info.ShortFailCount++
		} else {
			info.LongFailCount++
		}
		s.startTime = nil

		// TODO if shortfails exceed a threshold, revert to previous version.

		return s.saveCache(ctx)
	}

	return nil
}

func NewAgentSubsystem(
	ctx context.Context,
	name string,
	logger *zap.SugaredLogger,
	subsys BasicSubsystem,
) (*AgentSubsystem, error) {
	sub := &AgentSubsystem{name: name, logger: logger, inner: subsys}
	err := sub.LoadCache(ctx)
	if err != nil {
		return nil, err
	}
	return sub, nil
}

func (s *AgentSubsystem) LoadCache(ctx context.Context) error {
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

func (s *AgentSubsystem) saveCache(ctx context.Context) error {
	cacheFilePath := filepath.Join(ViamDirs["cache"], fmt.Sprintf("%s.json", s.name))

	cacheData, err := json.Marshal(s.CacheData)
	if err != nil {
		return err
	}

	return os.WriteFile(cacheFilePath, cacheData, 0o644)
}

func (s *AgentSubsystem) SaveCache(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.saveCache(ctx)
}

func (s *AgentSubsystem) Update(ctx context.Context, cfg *pb.DeviceSubsystemConfig) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var needRestart bool

	s.disable = cfg.GetDisable()
	if s.disable {
		needRestart = true
	}

	updateInfo := cfg.GetUpdateInfo()
	if s.CacheData.CurVersion == updateInfo.GetVersion() {
		shasum, err := GetFileSum(path.Join(ViamDirs["bin"], updateInfo.GetFilename()))
		if err == nil && bytes.Equal(shasum, updateInfo.GetSha256()) {
			return needRestart, nil
		}
	}

	verData, ok := s.CacheData.Versions[updateInfo.GetVersion()]
	if !ok {
		verData = &VersionInfo{Version: updateInfo.GetVersion()}
		s.CacheData.Versions[updateInfo.GetVersion()] = verData
	}

	dlpath, err := DownloadFile(ctx, updateInfo.GetUrl())
	if err != nil {
		return needRestart, errors.Wrapf(err, "downloading %s subsystem", s.name)
	}
	verData.DlPath = dlpath
	dlsha, err := GetFileSum(dlpath)
	if err != nil {
		return needRestart, errors.Wrap(err, "getting file shasum")
	}
	verData.DlSHA = dlsha

	extractedfile := dlpath
	if updateInfo.GetFormat() == pb.PackageFormat_PACKAGE_FORMAT_XZ || updateInfo.GetFormat() == pb.PackageFormat_PACKAGE_FORMAT_XZ_EXECUTABLE {
		extractedfile, err = DecompressFile(dlpath)
		if err != nil {
			return needRestart, errors.Wrapf(err, "decompressing %s subsystem", s.name)
		}
		verData.UnpackedPath = extractedfile
	}

	shasum, err := GetFileSum(extractedfile)
	if err != nil {
		return needRestart, errors.Wrap(err, "getting file shasum")
	}
	verData.UnpackedSHA = shasum
	if !bytes.Equal(shasum, updateInfo.GetSha256()) {
		return needRestart, fmt.Errorf(
			"sha256 of downloaded file (%s) does not match config (%s)",
			base64.StdEncoding.EncodeToString(shasum),
			base64.StdEncoding.EncodeToString(updateInfo.GetSha256()),
		)
	}

	if updateInfo.GetFormat() == pb.PackageFormat_PACKAGE_FORMAT_EXECUTABLE || updateInfo.GetFormat() == pb.PackageFormat_PACKAGE_FORMAT_XZ_EXECUTABLE {
		if err := os.Chmod(extractedfile, 0o755); err != nil {
			return needRestart, err
		}
	} else {
		if err := os.Chmod(extractedfile, 0o644); err != nil {
			return needRestart, err
		}
	}

	symlinkPath := path.Join(ViamDirs["bin"], updateInfo.GetFilename())

	err = os.Remove(symlinkPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return needRestart, errors.Wrap(err, "removing old symlink")
	}

	err = os.Symlink(extractedfile, symlinkPath)
	if err != nil {
		return needRestart, errors.Wrap(err, "symlinking extracted file")
	}
	verData.SymlinkPath = symlinkPath

	if s.CacheData.CurVersion != s.CacheData.PrevVersion {
		s.CacheData.PrevVersion = s.CacheData.CurVersion
	}
	s.CacheData.CurVersion = updateInfo.GetVersion()
	verData.Installed = time.Now()

	needRestart = true

	err = s.saveCache(ctx)
	if err != nil {
		return needRestart, err
	}

	inner, ok := s.inner.(updatable)
	if ok {
		return inner.Update(ctx, cfg)
	}

	return needRestart, nil
}
