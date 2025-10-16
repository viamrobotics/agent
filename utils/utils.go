// Package utils contains helper functions shared between the main agent and subsystems
package utils

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-getter"
	errw "github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"github.com/ulikunitz/xz"
	"go.viam.com/rdk/logging"
	goutils "go.viam.com/utils"
	"go.viam.com/utils/rpc"
)

var (
	// versions embedded at build time.
	Version     = ""
	GitRevision = ""

	ViamDirs ViamDirsData

	HealthCheckTimeout = time.Minute
)

type ViamDirsData struct {
	Viam  string
	Bin   string
	Cache string
	Tmp   string
	Etc   string
	// partial downloads
	Partials string
}

// Values returns an [iter.Seq] over the field values in ViamDirsData at the
// time it is called.
func (v ViamDirsData) Values() iter.Seq[string] {
	return func(yield func(string) bool) {
		refViamDirs := reflect.ValueOf(v)
		numFields := refViamDirs.NumField()
		for i := range numFields {
			val := refViamDirs.Field(i)
			strVal := val.Interface().(string)
			if strVal == "" {
				continue
			}
			if !yield(strVal) {
				return
			}
		}
	}
}

// GetVersion returns the version embedded at build time.
func GetVersion() string {
	if Version == "" {
		return "custom"
	}
	return Version
}

// GetRevision returns the git revision embedded at build time.
func GetRevision() string {
	if GitRevision == "" {
		return "unknown"
	}
	return GitRevision
}

func init() {
	ViamDirs.Viam = "/opt/viam"
	if runtime.GOOS == "windows" {
		ViamDirs.Viam = "c:/opt/viam"
		// note: forward slash isn't an abs path on windows, but resolves to one.
		var err error
		ViamDirs.Viam, err = filepath.Abs(ViamDirs.Viam)
		if err != nil {
			panic(err)
		}
	}
	ViamDirs.Bin = filepath.Join(ViamDirs.Viam, "bin")
	ViamDirs.Cache = filepath.Join(ViamDirs.Viam, "cache")
	ViamDirs.Partials = filepath.Join(ViamDirs.Cache, "part")
	ViamDirs.Tmp = filepath.Join(ViamDirs.Viam, "tmp")
	ViamDirs.Etc = filepath.Join(ViamDirs.Viam, "etc")
}

func InitPaths() error {
	uid := os.Getuid()
	expectedPerms := os.FileMode(0o755)
	if runtime.GOOS == "windows" {
		expectedPerms = 0o777
	}
	for p := range ViamDirs.Values() {
		info, err := os.Stat(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				//nolint:gosec
				if err := os.MkdirAll(p, 0o755); err != nil {
					return errw.Wrapf(err, "creating directory %s", p)
				}
				continue
			}
			return errw.Wrapf(err, "checking directory %s", p)
		}
		if err := checkPathOwner(uid, info); err != nil {
			return err
		}
		if !info.IsDir() {
			return errw.Errorf("%s should be a directory, but is not", p)
		}
		if info.Mode().Perm() != expectedPerms {
			return errw.Errorf("%s should have permission set to %#o, but has permissions %#o", p, expectedPerms, info.Mode().Perm())
		}
	}
	return nil
}

// DownloadFile downloads or copies a file into the cache directory and returns a path to the file.
// If this is an http/s URL, you must check the checksum of the result; the partial logic does not check etags.
func DownloadFile(ctx context.Context, rawURL string, logger logging.Logger) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	logger.Infof("Starting download of %s", rawURL)
	parsedPath := parsedURL.Path

	// don't want to accidentally overwrite anything in the cache directory by accident
	// old agent versions used a different cache format, so it's possible we could be re-downloading ourself
	var outPath string
	for n := range 100 {
		var suffix string
		if n > 0 {
			suffix = fmt.Sprintf(".duplicate-%03d", n)
		}
		outPath = filepath.Join(ViamDirs.Cache, path.Base(parsedPath)+suffix)
		if runtime.GOOS == "windows" && !strings.HasSuffix(outPath, ".exe") {
			outPath += ".exe"
		}

		_, err = os.Stat(outPath)
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
	}

	// I think getter.Client is the only way to pass down context.
	getterClient := &getter.Client{Ctx: ctx}
	switch parsedURL.Scheme {
	case "file":
		g := getter.FileGetter{Copy: true}
		g.SetClient(getterClient)
		if err := g.GetFile(outPath, parsedURL); err != nil {
			return "", errw.Wrap(err, "copying file")
		}
	case "http", "https":
		// note: we shrink the hash to avoid system path length limits
		partialDest := path.Join(ViamDirs.Partials, hashString(rawURL, 7), last(strings.Split(parsedURL.Path, "/"), "")+".part")

		// Use SOCKS proxy from environment as gRPC proxy dialer. Do not use
		// if trying to connect to a local address.
		httpClient := &http.Client{Transport: &http.Transport{
			DialContext: rpc.SocksProxyFallbackDialContext(parsedURL.String(), logger),
		}}
		g := getter.HttpGetter{Client: httpClient}
		g.SetClient(getterClient)

		if stat, err := os.Stat(partialDest); err == nil {
			logger.Infof("download to existing %q, size %d", partialDest, stat.Size())
		}

		done := make(chan struct{})
		defer close(done)
		goutils.PanicCapturingGo(func() { fileSizeProgress(done, ctx, logger, rawURL, partialDest) })
		if err := g.GetFile(partialDest, parsedURL); err != nil {
			return "", errw.Wrap(err, "downloading file")
		}

		// move completed .part to outPath and remove url-hash dir
		logger.Debugf("moving successful download %q to outPath", partialDest)
		if err := errors.Join(os.Rename(partialDest, outPath), os.Remove(path.Dir(partialDest))); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unhandled scheme %q in URL %q", parsedURL.Scheme, rawURL)
	}
	logger.Infof("finished copying %q", rawURL)

	if runtime.GOOS == "windows" {
		if err := allowFirewall(logger, outPath); err != nil {
			return "", err
		}
	}

	return outPath, nil
}

// helper: return last item of `items` slice, or `default_` if items is empty.
func last[T any](items []T, default_ T) T {
	if len(items) == 0 {
		return default_
	}
	return items[len(items)-1]
}

// helper: last N digits of md5sum of input string.
func hashString(input string, n int) string {
	h := md5.New() //nolint:gosec
	h.Write([]byte(input))
	ret := hex.EncodeToString(h.Sum(nil))
	if n > 0 {
		return ret[len(ret)-n:]
	}
	return ret
}

// on windows only, create a firewall exception for the newly-downloaded file.
func allowFirewall(logger logging.Logger, outPath string) error {
	// todo: confirm this is right; this isn't the final destination. Does the rule move when the file is renamed? Link to docs.
	cmd := exec.Command( //nolint:gosec
		"netsh", "advfirewall", "firewall", "add", "rule", "name="+path.Base(outPath),
		"dir=in", "action=allow", "program=\""+outPath+"\"", "enable=yes",
	)
	if err := cmd.Start(); err != nil {
		return errw.Wrap(err, "creating firewall rule")
	}
	err := cmd.Wait()
	if err != nil {
		user, _ := user.Current() //nolint:errcheck
		if user.Name != "SYSTEM" {
			// note: otherwise, we end up with a mostly-correct download but no version, which leads to other problems.
			logger.Info("Ignoring netsh error on non-SYSTEM windows")
		}
	} else {
		logger.Debugf("created firewall exception for %q", outPath)
	}
	return err
}

// DecompressFile extracts a compressed file and returns the path to the extracted file.
func DecompressFile(inPath string) (outPath string, errRet error) {
	//nolint:gosec
	in, err := os.Open(inPath)
	if err != nil {
		return "", err
	}
	defer func() {
		errRet = errors.Join(errRet, in.Close())
	}()

	reader, err := xz.NewReader(bufio.NewReader(in))
	if err != nil {
		return "", err
	}

	out, err := os.CreateTemp(ViamDirs.Tmp, "*")
	if err != nil {
		return "", err
	}

	defer func() {
		errRet = errors.Join(errRet, out.Close(), SyncFS(ViamDirs.Tmp))
		if err := os.Remove(out.Name()); err != nil && !os.IsNotExist(err) {
			errRet = errors.Join(errRet, err)
		}
	}()

	_, err = io.Copy(out, reader)
	if err != nil && !os.IsNotExist(err) {
		errRet = errors.Join(errRet, err)
	}

	outPath = filepath.Join(ViamDirs.Cache, strings.Replace(filepath.Base(inPath), ".xz", "", 1))
	errRet = errors.Join(errRet, os.Rename(out.Name(), outPath), SyncFS(outPath))
	return outPath, errRet
}

func GetFileSum(filepath string) (outSum []byte, errRet error) {
	//nolint:gosec
	in, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer func() {
		errRet = errors.Join(errRet, in.Close())
	}()

	h := sha256.New()
	_, errRet = io.Copy(h, in)
	return h.Sum(nil), errRet
}

func FuzzTime(duration time.Duration, pct float64) time.Duration {
	// pct is fuzz factor percentage 0.0 - 1.0
	// example +/- 5% is 0.05
	//nolint:gosec
	random := rand.New(rand.NewSource(time.Now().UnixNano())).Float64()
	slop := float64(duration) * pct * 2
	return time.Duration(float64(duration) - slop + (random * slop))
}

func CheckIfSame(path1, path2 string) (bool, error) {
	curPath, err := filepath.EvalSymlinks(path1)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errw.Wrapf(err, "evaluating symlinks pointing to %s", path1)
	}

	stat1, err := os.Stat(curPath)
	if err != nil {
		return false, errw.Wrapf(err, "statting %s", curPath)
	}

	realPath, err := filepath.EvalSymlinks(path2)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errw.Wrapf(err, "evaluating symlinks pointing to %s", path2)
	}

	stat2, err := os.Stat(realPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errw.Wrapf(err, "statting %s", realPath)
	}

	return os.SameFile(stat1, stat2), nil
}

func ForceSymlink(orig, symlink string) error {
	err := os.Remove(symlink)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errw.Wrap(err, "removing old symlink")
	}

	err = os.Symlink(orig, symlink)
	if err != nil {
		// note: this will fail on windows if you are not privileged unless you enable developer mode
		// https://learn.microsoft.com/en-us/windows/apps/get-started/enable-your-device-for-development
		return errw.Wrap(err, "symlinking file")
	}

	return SyncFS(symlink)
}

// WriteFileIfNew returns true if contents changed and a write happened.
func WriteFileIfNew(outPath string, data []byte) (bool, error) {
	//nolint:gosec
	curFileBytes, err := os.ReadFile(outPath)
	if err != nil {
		if !errw.Is(err, fs.ErrNotExist) {
			return false, errw.Wrapf(err, "opening %s for reading", outPath)
		}
	} else if bytes.Equal(curFileBytes, data) {
		return false, nil
	}

	//nolint:gosec
	if err := os.MkdirAll(path.Dir(outPath), 0o755); err != nil {
		return true, errw.Wrapf(err, "creating directory for %s", outPath)
	}

	//nolint:gosec
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return true, errw.Wrapf(err, "writing %s", outPath)
	}

	return true, SyncFS(outPath)
}

type Health struct {
	mu      sync.Mutex
	last    time.Time
	Timeout time.Duration
}

func NewHealth() *Health {
	return &Health{Timeout: HealthCheckTimeout, last: time.Now()}
}

func (h *Health) MarkGood() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.last = time.Now()
}

func (h *Health) Sleep(ctx context.Context, timeout time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(timeout):
		h.mu.Lock()
		defer h.mu.Unlock()
		h.last = time.Now()
		return true
	}
}

func (h *Health) IsHealthy() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return time.Since(h.last) < h.Timeout
}

func Recover(logger logging.Logger, inner func(r any)) {
	// if something panicked, log it and allow things to continue
	r := recover()
	if r != nil {
		logger.Error("encountered a panic, attempting to recover")
		logger.Errorf("panic: %s\n%s", r, debug.Stack())
		if inner != nil {
			inner(r)
		}
	}
}

const maxBufferSize = 16 * 1024 * 1024

type SafeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *SafeBuffer) Write(p []byte) (n int, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.buf.Len() > maxBufferSize {
		sb.buf.Reset()
	}
	return sb.buf.Write(p)
}

func (sb *SafeBuffer) Read(p []byte) (n int, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Read(p)
}

func (sb *SafeBuffer) String() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	defer sb.buf.Reset()
	return sb.buf.String()
}

func (sb *SafeBuffer) Len() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Len()
}

func (sb *SafeBuffer) Reset() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.buf.Reset()
}

// starts a goroutine that watches `dest` file size, logs progress until `dest` no longer exists or `done` is closed.
func fileSizeProgress(done chan struct{}, ctx context.Context, logger logging.Logger, url, dest string) {
	// note: go-getter is also doing a HEAD request internally, so this is redundant, but we don't have access to it.
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		logger.Warnf("progress bar failed: %s", err)
		return
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Warnf("progress bar failed: %s", err)
		return
	}
	size := res.ContentLength
	res.Body.Close() //nolint:errcheck,gosec

	bar := progressbar.NewOptions64(
		size,
		progressbar.OptionSetDescription("Downloading "+filepath.Base(dest)),
		progressbar.OptionSetWriter(io.Discard),
		progressbar.OptionShowBytes(true),
		progressbar.OptionShowTotalBytes(true),
		progressbar.OptionSetWidth(10),
		progressbar.OptionShowCount(),
		progressbar.OptionSpinnerType(0),
	)
	bar.ChangeMax64(size)
	if err := bar.RenderBlank(); err != nil {
		logger.Warn(err)
	}

	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-ticker.C:
			stat, err := os.Stat(dest)
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					// we don't warn if the file is missing because that means completion
					logger.Warnf("progress bar stat error: %s", err)
				}
				return
			}
			// todo: use fancy progress bar instead
			bar.Set64(stat.Size()) //nolint:errcheck,gosec
			logger.Info(bar)
		case <-done:
			return
		}
	}
}

// AtomicCopy implements a best effort to atomically copy the file at src to
// dst. It does this by copying first to a temporary file in the same directory
// as dst, then renaming that file to the final expected path.
func AtomicCopy(dst, src string) error {
	//nolint:gosec
	infile, err := os.Open(src)
	if err != nil {
		return errw.Wrap(err, "opening source file for atomic copy")
	}
	//nolint:errcheck
	defer infile.Close()
	tmpDst := dst + ".tmp"
	//nolint:gosec
	tmpOutFile, err := os.OpenFile(tmpDst, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		return errw.Wrap(err, "opening temporary destination file for atomic copy")
	}
	_, err = io.Copy(tmpOutFile, infile)
	//nolint:errcheck,gosec
	tmpOutFile.Close()
	if err != nil {
		return errw.Wrap(err, "performing atomic copy")
	}
	//nolint:errcheck,gosec
	tmpOutFile.Close()
	err = os.Rename(tmpDst, dst)
	if err != nil {
		return errw.Wrap(err, "renaming copied file during atomic copy")
	}
	return nil
}

// GoArchToOSArch translates CPU architecture IDs used by Go such as "arm64" to
// architucture IDs used by operating systems and their package managers, such
// as "aarch64". It returns an empty string for unknown architectures.
func GoArchToOSArch(goarch string) string {
	switch goarch {
	case "arm64":
		return "aarch64"
	case "amd64":
		return "x86_64"
	}
	return ""
}
