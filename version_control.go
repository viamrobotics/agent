package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gabriel-vasile/mimetype"
	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/subsystems/viamserver"
	"github.com/viamrobotics/agent/utils"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/rdk/logging"
)

// lastModifiedCheckFrequency is the minimum interval for checking
// a customURL's "Last-Modified" header to detect if the file has changed.
// This is to not to overwhelm servers, since we fetch config updates and call UpdateBinary every few seconds.
const lastModifiedCheckFrequency = time.Minute * 2

func getCacheFilePath() string {
	return filepath.Join(utils.ViamDirs.Cache, "version_cache.json")
}

func VersionCacheExists() bool {
	_, err := os.Stat(getCacheFilePath())
	return err == nil
}

func NewVersionCache(logger logging.Logger) *VersionCache {
	cache := &VersionCache{
		ViamAgent:          &Versions{Versions: map[string]*VersionInfo{}},
		ViamServer:         &Versions{Versions: map[string]*VersionInfo{}},
		logger:             logger,
		cacheCleanupLogger: logger.Sublogger("cache_cleanup"),
	}
	cache.load()

	// avoid cleanup during the first fifteen minutes after startup
	// 1425 = (24*60)-15
	if cache.LastCleaned.Add(time.Minute * 1425).Before(time.Now()) {
		cache.LastCleaned = time.Now().Add(time.Minute * -1425)
	}

	return cache
}

type VersionCache struct {
	mu           sync.Mutex
	ViamAgent    *Versions `json:"viam_agent"`
	ViamServer   *Versions `json:"viam_server"`
	LastCleaned  time.Time `json:"last_cleaned"`
	LastShutdown time.Time `json:"last_shutdown"`
	logger       logging.Logger

	// usually it wouldn't make sense to have multiple loggers on a struct, but this struct is doing
	// two wildly different things
	cacheCleanupLogger logging.Logger
}

// Versions stores VersionInfo and the current/previous versions for (TODO) rollback.
type Versions struct {
	TargetVersion   string                  `json:"target_version"`
	CurrentVersion  string                  `json:"current_version"`
	PreviousVersion string                  `json:"previous_version"`
	Versions        map[string]*VersionInfo `json:"versions"`

	// temporary, so not exported for json/caching
	runningVersion string
	brokenTarget   bool
}

// VersionInfo records details about each version of a subsystem.
type VersionInfo struct {
	Version      string
	URL          string
	DlPath       string
	DlSHA        []byte
	UnpackedPath string
	// the sha256 field of the UpdateInfo proto
	UnpackedSHA []byte
	SymlinkPath string
	Installed   time.Time

	// Last-Modified field from http header, if available
	LastModified      time.Time
	LastModifiedCheck time.Time
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

func (c *VersionCache) ViamServerRunningVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ViamServer.runningVersion
}

func (c *VersionCache) MarkViamServerRunningVersion() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ViamServer.runningVersion = c.ViamServer.CurrentVersion
}

// LoadCache loads the cached data for the subsystem from disk.
func (c *VersionCache) load() {
	c.mu.Lock()
	defer c.mu.Unlock()

	cacheFilePath := getCacheFilePath()
	//nolint:gosec
	cacheBytes, err := os.ReadFile(cacheFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			c.logger.Warn(err)
			return
		}
	} else {
		err = json.Unmarshal(cacheBytes, c)
		if err != nil {
			c.logger.Warn(errw.Wrap(err, "parsing version cache"))
			return
		}
	}
}

// save should only be run when protected by mutex locks. Use SaveCache() for normal use.
func (c *VersionCache) save() error {
	cacheFilePath := getCacheFilePath()

	cacheData, err := json.Marshal(c)
	if err != nil {
		return err
	}

	_, err = utils.WriteFileIfNew(cacheFilePath, cacheData)
	return err
}

// Update processes data for the two binaries: agent itself, and viam-server.
func (c *VersionCache) Update(cfg *pb.UpdateInfo, binary string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var data *Versions
	switch binary {
	case SubsystemName:
		data = c.ViamAgent
	case viamserver.SubsysName:
		data = c.ViamServer
	}
	newVersion := cfg.GetVersion()
	if newVersion == "customURL" {
		newVersion = "customURL+" + cfg.GetUrl()
	}
	if newVersion == "" {
		return errw.Errorf("empty string given as version for %v", binary)
	}

	if newVersion == data.TargetVersion {
		return nil
	}

	data.TargetVersion = newVersion
	data.brokenTarget = false
	info, ok := data.Versions[newVersion]
	if !ok {
		info = &VersionInfo{}
		data.Versions[newVersion] = info
	}

	info.Version = newVersion
	info.URL = cfg.GetUrl()
	info.SymlinkPath = path.Join(utils.ViamDirs.Bin, cfg.GetFilename())
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

	var needRestart, goodBytes bool

	if data.brokenTarget {
		return needRestart, nil
	}

	verData, ok := data.Versions[data.TargetVersion]
	if !ok {
		// App has passed down "" as a target version in the past (see RSDK-11966 and linked
		// tickets). Explicitly include that information in the error in that case.
		targetVersion := data.TargetVersion
		if targetVersion == "" {
			targetVersion = "[empty string]"
		}
		return needRestart, errw.Errorf("version data %s not found for binary %s", targetVersion, binary)
	}

	isCustomURL := strings.HasPrefix(verData.Version, "customURL+")
	isFileURL := strings.HasPrefix(verData.URL, "file://")
	shasum, err := utils.GetFileSum(verData.UnpackedPath)
	if err == nil {
		goodBytes = bytes.Equal(shasum, verData.UnpackedSHA)
	} else if verData.UnpackedPath != "" { // custom file:// URLs with have an empty unpacked path; no need to warn
		c.logger.Warnw("Could not calculate shasum", "path", verData.UnpackedPath, "error", err)
	}

	prevLastModified := verData.LastModified
	var lastModified time.Time
	var lastModifiedChanged bool
	if isCustomURL && !isFileURL && time.Since(verData.LastModifiedCheck) > lastModifiedCheckFrequency {
		lastModified = utils.GetLastModified(ctx, verData.URL, c.logger)
		// don't mark changed if we're just storing lastModified for the first time
		lastModifiedChanged = !verData.LastModified.IsZero() && lastModified.After(verData.LastModified)
		// don't allow LastModified to move backwards (mostly likely in case server is misconfigured)
		if lastModified.After(verData.LastModified) {
			verData.LastModified = lastModified
		}
		verData.LastModifiedCheck = time.Now()
	}

	if data.TargetVersion == data.CurrentVersion {
		// if a known version, make sure the symlink is correct
		same, err := utils.CheckIfSame(verData.DlPath, verData.SymlinkPath)
		if err != nil {
			return needRestart, err
		}

		if runtime.GOOS == "windows" && verData.UnpackedPath == "" {
			// This case happens as a result of manual action to fix systems which used the old installer.
			c.logger.Debug("replacing blank UnpackedPath with DlPath")
			verData.UnpackedPath = verData.DlPath
		}

		if !same {
			if err := utils.ForceSymlink(verData.UnpackedPath, verData.SymlinkPath); err != nil {
				return needRestart, err
			}
		}

		// TODO(APP-10012): don't leave bad checksum binary on disk + symlinked
		// if checksums match and lastModified either hasn't changed or wasn't scanned, no update is needed
		if goodBytes && !lastModifiedChanged {
			return false, nil
		}

		// if we're here, we have a mismatched checksum, as likely the URL changed, so wipe it and recompute later
		if isCustomURL {
			verData.UnpackedSHA = []byte{}
		}
	}

	// this is a new version
	c.logger.Infof("new version (%s) found for %s", verData.Version, binary)

	if !goodBytes || lastModifiedChanged {
		if lastModifiedChanged {
			c.logger.Infow("detected change in Last-Modified timestamp. redownloading.",
				"latest", lastModified.String(), "previous", prevLastModified.String(), "url", verData.URL)
		} else {
			c.logger.Warnw("mismatched checksum, redownloading",
				"expected", hex.EncodeToString(verData.UnpackedSHA), "actual", hex.EncodeToString(shasum),
				"url", verData.URL)
		}
		// download and record the sha of the download itself
		verData.DlPath, err = utils.DownloadFile(ctx, verData.URL, c.logger)
		if err != nil {
			if isCustomURL {
				data.brokenTarget = true
			}
			return needRestart, errw.Wrapf(err, "downloading %s", binary)
		}

		actualSha, err := utils.GetFileSum(verData.DlPath)
		if err != nil {
			return needRestart, errw.Wrap(err, "getting file shasum")
		}

		// TODO handle compressed formats, for now, the raw download is the same file
		verData.UnpackedPath = verData.DlPath
		verData.DlSHA = actualSha

		if len(verData.UnpackedSHA) <= 1 && isCustomURL {
			// If we downloaded a custom agent binary, check that it is ostensibly an agent
			// binary. This is primarily to ensure that users do not crash their agents
			// irrevocably by accidentally pointing `version_control.agent` to a viam-server
			// binary, for example.
			if binary == SubsystemName && !utils.IsValidAgentBinary(ctx, verData.DlPath, SubsystemName) {
				data.brokenTarget = true
				return needRestart,
					fmt.Errorf("downloaded file does not appear to be a %s binary, skipping",
						SubsystemName)
			}

			// Also check that the file has an executable MIME type and use the locally
			// generated sha.
			mtype, err := mimetype.DetectFile(verData.UnpackedPath)
			if err != nil {
				return needRestart, errw.Wrapf(err, "determining file type of download")
			}

			expectedMimes := []string{"application/x-elf", "application/x-executable"}
			if runtime.GOOS == "windows" {
				expectedMimes = []string{"application/vnd.microsoft.portable-executable"}
			}

			if !slices.ContainsFunc(expectedMimes, mtype.Is) {
				data.brokenTarget = true
				return needRestart, errw.Errorf("downloaded file is %s, not %s, skipping", mtype, strings.Join(expectedMimes, ", "))
			}
			verData.UnpackedSHA = actualSha
		}

		if len(verData.UnpackedSHA) > 1 && !bytes.Equal(verData.UnpackedSHA, actualSha) {
			// TODO(APP-10012): don't leave bad checksum file on disk
			//nolint:goerr113
			return needRestart, fmt.Errorf(
				"sha256 (%s) of downloaded file (%s) does not match provided (%s)",
				base64.StdEncoding.EncodeToString(actualSha),
				verData.UnpackedPath,
				base64.StdEncoding.EncodeToString(verData.UnpackedSHA),
			)
		}
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

// files we will always refuse to delete.
var baseProtectedFiles = []string{"config_cache.json", "version_cache.json", "viam-agent.pid"}

// Creates a list of files to not delete, and removes unprotected files
// from the Versions lists.
func (c *VersionCache) getProtectedFilesAndCleanVersions(ctx context.Context, maxAgeDays int) []string {
	protectedFiles := make([]string, len(baseProtectedFiles))
	copy(protectedFiles, baseProtectedFiles)

	// add protection for the current symlinked binaries
	for _, path := range []string{"viam-agent", "viam-server"} {
		if runtime.GOOS == "windows" {
			path += ".exe"
		}

		destPath, err := filepath.EvalSymlinks(filepath.Join(utils.ViamDirs.Bin, path))
		if err != nil {
			c.cacheCleanupLogger.Warn(err)
			continue
		}
		protectedFiles = append(protectedFiles, filepath.Base(destPath))
	}

	// add protection for recent/new/etc
	for _, system := range []*Versions{c.ViamAgent, c.ViamServer} {
		for ver, info := range system.Versions {
			if ctx.Err() != nil {
				return nil
			}
			if ver == system.CurrentVersion ||
				ver == system.PreviousVersion ||
				ver == system.TargetVersion ||
				ver == system.runningVersion ||
				// protect the last N days worth of updates in case of rollbacks
				info.Installed.After(time.Now().Add(time.Hour*-24*time.Duration(maxAgeDays))) {
				protectedFiles = append(protectedFiles, filepath.Base(info.UnpackedPath))
				continue
			}
			// not protecting, remove from the cache
			delete(system.Versions, ver)
		}
	}
	return protectedFiles
}

func (c *VersionCache) CleanCache(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// this can be set to the number of days to keep, ex: "VIAM_AGENT_FORCE_CLEAN=5"
	forceVal := os.Getenv("VIAM_AGENT_FORCE_CLEAN")
	maxAgeDays, err := strconv.Atoi(forceVal)
	if err != nil {
		maxAgeDays = 30
	}
	if maxAgeDays < 1 {
		maxAgeDays = 1
	}

	// only do this once every 24 hours
	if time.Now().Before(c.LastCleaned.Add(time.Hour*24)) && forceVal == "" {
		return
	}
	c.cacheCleanupLogger.Info("Starting cache cleanup")
	c.LastCleaned = time.Now()

	protectedFiles := c.getProtectedFilesAndCleanVersions(ctx, maxAgeDays)
	if ctx.Err() != nil {
		return
	}

	// save the cleaned cache
	if err := c.save(); err != nil {
		c.cacheCleanupLogger.Error(err)
	}

	// actually remove files
	for _, dir := range []string{utils.ViamDirs.Cache, utils.ViamDirs.Tmp} {
		files, err := os.ReadDir(dir)
		if err != nil {
			c.cacheCleanupLogger.Error(err)
			continue
		}
		for _, f := range files {
			if ctx.Err() != nil {
				return
			}
			if slices.Contains(protectedFiles, f.Name()) {
				c.cacheCleanupLogger.Debugf("cache cleanup skipping: %s", f.Name())
				continue
			}
			c.cacheCleanupLogger.Infof("cache cleanup removing: %s", f.Name())
			if err := os.Remove(filepath.Join(dir, f.Name())); err != nil {
				c.cacheCleanupLogger.Error(errw.Wrapf(err, "removing file %s", f.Name()))
			}
		}
	}

	c.cacheCleanupLogger.Info("Finished cache cleanup")
	c.CleanPartials(ctx) //nolint:errcheck,gosec
}

// CleanPartials is called by CleanCache and cleans up incomplete partial downloads that have not been modified for 3 days.
// The 3-day grace period is 1) to avoid breaking ongoing downloads and 2) to give spotty connections a chance to resolve.
func (c *VersionCache) CleanPartials(ctx context.Context) error {
	c.cacheCleanupLogger.Info("Starting partials cleanup")
	matches, err := filepath.Glob(filepath.Join(utils.ViamDirs.Partials, "*", "*.part"))
	if err != nil {
		c.cacheCleanupLogger.Errorw("error cleaning partials", "matches", strings.Join(matches, ", ")[:200])
		return err
	}
	var joinedErrors error
	for _, match := range matches {
		if stat, err := os.Stat(match); err != nil {
			c.cacheCleanupLogger.Errorw("error statting partial", "match", match, "err", err)
			joinedErrors = errors.Join(joinedErrors, err)
		} else {
			if stat.ModTime().Add(time.Hour * 24 * 3).Before(time.Now()) {
				if err := errors.Join(os.Remove(match), os.Remove(filepath.Dir(match))); err != nil {
					c.cacheCleanupLogger.Errorw("error removing partial or parent dir", "match", match, "err", err)
					joinedErrors = errors.Join(joinedErrors, err)
				} else {
					c.cacheCleanupLogger.Infow("removed expired partial download", "match", match)
				}
			} else {
				c.cacheCleanupLogger.Debugw("keeping recent partial download", "match", match)
			}
		}
	}
	return joinedErrors
}

// MarkShutdownAndSave writes the current timestamp as LastShutdown and saves the cache.
// LastShutdown is referenced in forwardRecentSystemdAgentLogs.
func (c *VersionCache) MarkShutdownAndSave() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastShutdown = time.Now()
	return c.save()
}
