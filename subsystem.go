package agent

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	pb "go.viam.com/api/app/agent/v1"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const (
	ShortFailTime = time.Second * 30
)

type Subsystem interface {
	// Start runs the subsystem
	Start(ctx context.Context) error

	// Stop signals the subsystem to shutdown
	Stop(ctx context.Context) error

	// Update validates and/or updates a subsystem, returns true if subsystem should be restarted
	Update(ctx context.Context, cfg *pb.DeviceSubsystemConfig) (bool, error)

	// HealthCheck reports if a subsystem is running correctly (it is restarted if not)
	HealthCheck(ctx context.Context) error
}

type BasicSubsystem interface {
	// Start runs the subsystem
	Start(ctx context.Context) error

	// Stop signals the subsystem to shutdown
	Stop(ctx context.Context) error

	// HealthCheck reports if a subsystem is running correctly (it is restarted if not)
	HealthCheck(ctx context.Context) error
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

	cacheFilePath := filepath.Join(ViamDirs["cache"], fmt.Sprintf("%s.yaml", s.name))
	cacheData, err := os.ReadFile(cacheFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	if err == nil {
		return yaml.Unmarshal(cacheData, s.CacheData)
	}

	s.CacheData = &CacheData{
		Versions: make(map[string]*VersionInfo),
	}

	return nil
}

func (s *AgentSubsystem) saveCache(ctx context.Context) error {
	cacheFilePath := filepath.Join(ViamDirs["cache"], fmt.Sprintf("%s.yaml", s.name))

	cacheData, err := yaml.Marshal(s.CacheData)
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

	s.disable = cfg.Disable

	if s.disable {
		return true, nil
	}

	updateInfo := cfg.UpdateInfo
	if s.CacheData.CurVersion == updateInfo.Version {
		shasum, err := GetFileSum(path.Join(ViamDirs["bin"], updateInfo.Filename))
		if err == nil && bytes.Equal(shasum, updateInfo.Sha256) {
			return false, nil
		}
	}

	verData, ok := s.CacheData.Versions[updateInfo.Version]
	if !ok {
		verData = &VersionInfo{Version: updateInfo.Version}
		s.CacheData.Versions[updateInfo.Version] = verData
	}

	dlpath, err := DownloadFile(ctx, updateInfo.Url)
	if err != nil {
		return false, errors.Wrapf(err, "downloading %s subsystem", s.name)
	}
	verData.DlPath = dlpath
	dlsha, err := GetFileSum(dlpath)
	if err != nil {
		return false, errors.Wrap(err, "getting file shasum")
	}
	verData.DlSHA = dlsha

	extractedfile := dlpath
	if updateInfo.Format == pb.PackageFormat_PACKAGE_FORMAT_XZ || updateInfo.Format == pb.PackageFormat_PACKAGE_FORMAT_XZ_EXECUTABLE {
		extractedfile, err = DecompressFile(dlpath)
		if err != nil {
			return false, errors.Wrapf(err, "decompressing %s subsystem", s.name)
		}
		verData.UnpackedPath = extractedfile
	}

	shasum, err := GetFileSum(extractedfile)
	if err != nil {
		return false, errors.Wrap(err, "getting file shasum")
	}
	verData.UnpackedSHA = shasum
	if !bytes.Equal(shasum, updateInfo.Sha256) {
		return false, fmt.Errorf("sha256 of downloaded file (%x) does not match config (%x)", shasum, updateInfo.Sha256)
	}

	if updateInfo.Format == pb.PackageFormat_PACKAGE_FORMAT_EXECUTABLE || updateInfo.Format == pb.PackageFormat_PACKAGE_FORMAT_XZ_EXECUTABLE {
		if err := os.Chmod(extractedfile, 0o755); err != nil {
			return false, err
		}
	} else {
		if err := os.Chmod(extractedfile, 0o644); err != nil {
			return false, err
		}
	}

	symlinkPath := path.Join(ViamDirs["bin"], updateInfo.Filename)

	err = os.Remove(symlinkPath)
	if err != nil {
		return false, errors.Wrap(err, "removing old symlink")
	}

	err = os.Symlink(extractedfile, symlinkPath)
	if err != nil {
		return false, errors.Wrap(err, "symlinking extracted file")
	}
	verData.SymlinkPath = symlinkPath

	if s.CacheData.CurVersion != s.CacheData.PrevVersion {
		s.CacheData.PrevVersion = s.CacheData.CurVersion
	}
	s.CacheData.CurVersion = updateInfo.Version
	verData.Installed = time.Now()

	return true, s.saveCache(ctx)
}
