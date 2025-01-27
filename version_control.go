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
	"github.com/viamrobotics/agent/subsystems/viamserver"
	"github.com/viamrobotics/agent/utils"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/rdk/logging"
)

const (
	versionCacheFilename = "version_cache.json"
)

func NewVersionCache(logger logging.Logger) *VersionCache {
	cache := &VersionCache{
		ViamAgent:  &Versions{Versions: map[string]*VersionInfo{}},
		ViamServer: &Versions{Versions: map[string]*VersionInfo{}},
		logger:     logger,
	}
	cache.load()
	return cache
}

type VersionCache struct {
	mu         sync.Mutex
	ViamAgent  *Versions `json:"viam_agent"`
	ViamServer *Versions `json:"viam_server"`
	logger     logging.Logger
}

// Versions stores VersionInfo and the current/previous versions for (TODO) rollback.
type Versions struct {
	TargetVersion   string                  `json:"target_version"`
	CurrentVersion  string                  `json:"current_version"`
	PreviousVersion string                  `json:"previous_version"`
	Versions        map[string]*VersionInfo `json:"versions"`
}

// VersionInfo records details about each version of a subsystem.
type VersionInfo struct {
	Version      string
	URL          string
	DlPath       string
	DlSHA        []byte
	UnpackedPath string
	UnpackedSHA  []byte
	SymlinkPath  string
	Installed    time.Time
}

func (c *VersionCache) AgentVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ViamAgent.CurrentVersion
}

func (c *VersionCache) ViamServerVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ViamServer.CurrentVersion
}

func (c *VersionCache) ViamServerPreviousVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ViamServer.PreviousVersion
}

// LoadCache loads the cached data for the subsystem from disk.
func (c *VersionCache) load() {
	c.mu.Lock()
	defer c.mu.Unlock()

	cacheFilePath := filepath.Join(utils.ViamDirs["cache"], versionCacheFilename)
	//nolint:gosec
	cacheBytes, err := os.ReadFile(cacheFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			c.logger.Error(err)
			return
		}
	} else {
		err = json.Unmarshal(cacheBytes, c)
		if err != nil {
			c.logger.Error(errw.Wrap(err, "parsing version cache"))
			return
		}
	}
}

// save should only be run when protected by mutex locks. Use SaveCache() for normal use.
func (c *VersionCache) save() error {
	cacheFilePath := filepath.Join(utils.ViamDirs["cache"], versionCacheFilename)

	cacheData, err := json.Marshal(c)
	if err != nil {
		return err
	}

	_, err = utils.WriteFileIfNew(cacheFilePath, cacheData)
	return err
}

// Save saves the cached data to disk.
func (c *VersionCache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.save()
}

// Update processes data for the two binaries, agent itself, and viam-server.
func (c *VersionCache) Update(cfg *pb.UpdateInfo, binary string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var data *Versions
	if binary == SubsystemName {
		data = c.ViamAgent
	} else if binary == viamserver.SubsysName {
		data = c.ViamServer
	}
	newVersion := cfg.GetVersion()
	if newVersion == "customURL" {
		newVersion = "customURL" + cfg.GetUrl()
	}

	if newVersion == data.TargetVersion {
		return nil
	}

	data.TargetVersion = newVersion
	info, ok := data.Versions[newVersion]
	if !ok {
		info = &VersionInfo{}
		data.Versions[newVersion] = info
	}

	info.Version = newVersion
	info.URL = cfg.GetUrl()
	info.SymlinkPath = path.Join(utils.ViamDirs["bin"], cfg.GetFilename())
	info.UnpackedSHA = cfg.GetSha256()

	return c.save()
}

// UpdateBinary actually downloads and/or validates the targeted version. Returns true if a restart is needed.
//
//nolint:gocognit
func (c *VersionCache) UpdateBinary(ctx context.Context, binary string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var data *Versions
	switch binary {
	case SubsystemName:
		data = c.ViamAgent
	case viamserver.SubsysName:
		data = c.ViamServer
	default:
		return false, errw.Errorf("unknown binary name for update request: %s", binary)
	}

	var needRestart bool

	verData, ok := data.Versions[data.TargetVersion]
	if !ok {
		return needRestart, errw.Errorf("version data not found for %s %s", binary, data.TargetVersion)
	}

	if data.TargetVersion == data.CurrentVersion {
		// if a known version, make sure the symlink is correct
		same, err := utils.CheckIfSame(verData.DlPath, verData.SymlinkPath)
		if err != nil {
			return needRestart, err
		}
		if !same {
			if err := utils.ForceSymlink(verData.UnpackedPath, verData.SymlinkPath); err != nil {
				return needRestart, err
			}
		}

		shasum, err := utils.GetFileSum(verData.UnpackedPath)
		if err == nil && bytes.Equal(shasum, verData.UnpackedSHA) {
			return false, nil
		}
		if err != nil {
			c.logger.Error(err)
		}
	}

	// this is a new version
	c.logger.Infof("new version (%s) found for %s", verData.Version, binary)

	// download and record the sha of the download itself
	var err error
	verData.DlPath, err = utils.DownloadFile(ctx, verData.URL)
	if err != nil {
		return needRestart, errw.Wrapf(err, "downloading %s", binary)
	}
	actualSha, err := utils.GetFileSum(verData.DlPath)
	if err != nil {
		return needRestart, errw.Wrap(err, "getting file shasum")
	}

	// TODO handle compressed formats, for now, the raw download is the same file
	verData.UnpackedPath = verData.DlPath
	verData.DlSHA = actualSha

	if len(verData.UnpackedSHA) > 1 && !bytes.Equal(verData.UnpackedSHA, actualSha) {
		//nolint:goerr113
		return needRestart, fmt.Errorf(
			"sha256 (%s) of downloaded file (%s) does not match provided (%s)",
			base64.StdEncoding.EncodeToString(actualSha),
			verData.UnpackedPath,
			base64.StdEncoding.EncodeToString(verData.UnpackedSHA),
		)
	}

	// chmod with execute permissions if the file is executable
	//nolint:gosec
	if err := os.Chmod(verData.UnpackedPath, 0o755); err != nil {
		return needRestart, err
	}

	// symlink the extracted file to bin
	if err = utils.ForceSymlink(verData.UnpackedPath, verData.SymlinkPath); err != nil {
		return needRestart, errw.Wrap(err, "creating symlink")
	}

	// update current and previous versions
	if data.CurrentVersion != data.PreviousVersion {
		data.PreviousVersion = data.CurrentVersion
	}
	data.CurrentVersion = data.TargetVersion
	verData.Installed = time.Now()

	// if we made it here we performed an update and need to restart
	c.logger.Infof("%s updated from %s to %s", binary, data.PreviousVersion, data.CurrentVersion)
	needRestart = true

	// record the cache
	return needRestart, c.save()
}
