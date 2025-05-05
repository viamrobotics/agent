// Package utils contains helper functions shared between the main agent and subsystems
package utils

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	errw "github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"github.com/ulikunitz/xz"
	"go.viam.com/rdk/logging"
	"go.viam.com/utils/rpc"
)

var (
	// versions embedded at build time.
	Version     = ""
	GitRevision = ""

	ViamDirs = map[string]string{"viam": "/opt/viam"}

	HealthCheckTimeout = time.Minute
)

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
	if runtime.GOOS == "windows" {
		ViamDirs["viam"] = "c:/opt/viam"
		// note: forward slash isn't an abs path on windows, but resolves to one.
		var err error
		ViamDirs["viam"], err = filepath.Abs(ViamDirs["viam"])
		if err != nil {
			panic(err)
		}
	}
	ViamDirs["bin"] = filepath.Join(ViamDirs["viam"], "bin")
	ViamDirs["cache"] = filepath.Join(ViamDirs["viam"], "cache")
	ViamDirs["tmp"] = filepath.Join(ViamDirs["viam"], "tmp")
	ViamDirs["etc"] = filepath.Join(ViamDirs["viam"], "etc")
}

func InitPaths() error {
	uid := os.Getuid()
	expectedPerms := os.FileMode(0o755)
	if runtime.GOOS == "windows" {
		expectedPerms = 0o777
	}
	for _, p := range ViamDirs {
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
			return errw.Errorf("%s should be have permission set to %#o, but has permissions %#o", p, expectedPerms, info.Mode().Perm())
		}
	}
	return nil
}

// DownloadFile downloads a file into the cache directory and returns a path to the file.
func DownloadFile(ctx context.Context, rawURL string, logger logging.Logger) (outPath string, errRet error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	logger.Infof("Starting download of %s", rawURL)

	parsedPath := parsedURL.Path

	outPath = filepath.Join(ViamDirs["cache"], path.Base(parsedPath))

	if runtime.GOOS == "windows" && !strings.HasSuffix(outPath, ".exe") {
		outPath += ".exe"
	}

	//nolint:nestif
	if parsedURL.Scheme == "file" {
		if runtime.GOOS == "windows" {
			parsedPath = strings.TrimLeft(parsedPath, "/")
		}

		infd, err := os.Open(parsedPath) //nolint:gosec
		if err != nil {
			return "", err
		}
		defer func() {
			errRet = errors.Join(errRet, infd.Close())
		}()

		//nolint:gosec
		if err := os.MkdirAll(ViamDirs["tmp"], 0o755); err != nil {
			return "", err
		}

		outfd, err := os.CreateTemp(ViamDirs["tmp"], "*")
		if err != nil {
			return "", err
		}
		defer func() {
			// we might double close because we have to explicitly close before the rename for windows
			errClose := outfd.Close()
			if !errors.Is(errClose, os.ErrClosed) {
				errRet = errors.Join(errRet, errClose)
			}
			errRet = errors.Join(errRet, SyncFS(outPath))
			if err := os.Remove(outfd.Name()); err != nil && !os.IsNotExist(err) {
				errRet = errors.Join(errRet, err)
			}
		}()

		_, err = io.Copy(outfd, infd)
		if err != nil {
			return "", errors.Join(errRet, err)
		}
		errRet = errors.Join(errRet, outfd.Close(), os.Rename(outfd.Name(), outPath))
		if errRet == nil {
			logger.Infof("Download (local file copy) complete for %s", rawURL)
		}
		return outPath, errRet
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", errw.Errorf("unsupported url scheme %s", parsedURL.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return "", errw.Wrap(err, "downloading file")
	}

	// Use SOCKS proxy from environment as gRPC proxy dialer. Do not use
	// if trying to connect to a local address.
	httpClient := &http.Client{Transport: &http.Transport{
		DialContext: rpc.SocksProxyFallbackDialContext(parsedURL.String(), logger),
	}}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", errw.Wrapf(err, "downloading file %s", rawURL)
	}
	defer func() {
		errRet = errors.Join(errRet, resp.Body.Close())
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", errw.Errorf("got response '%s' while downloading %s", resp.Status, parsedURL)
	}

	//nolint:gosec
	if err := os.MkdirAll(ViamDirs["tmp"], 0o755); err != nil {
		return "", err
	}

	out, err := os.CreateTemp(ViamDirs["tmp"], "*")
	if err != nil {
		return "", err
	}
	// `closed` suppresses double-close
	closed := false
	defer func() {
		if !closed {
			errRet = errors.Join(errRet, out.Close())
		}
		if runtime.GOOS != "windows" {
			// todo(windows): doc why we don't do this / test adding it back
			errRet = errors.Join(errRet, SyncFS(out.Name()))
		}
		if err := os.Remove(out.Name()); err != nil && !os.IsNotExist(err) {
			errRet = errors.Join(errRet, err)
		}
	}()

	workers := &sync.WaitGroup{}
	writer, cancelFunc := downloadProgressSetup(ctx, out, outPath, resp.ContentLength, logger, workers)
	defer workers.Wait()
	defer cancelFunc()

	_, err = io.Copy(writer, resp.Body)
	if err != nil && !os.IsNotExist(err) {
		errRet = errors.Join(errRet, err)
	}
	errRet = errors.Join(errRet, out.Close())
	closed = true

	errRet = errors.Join(errRet, os.Rename(out.Name(), outPath), SyncFS(outPath))

	if errRet == nil {
		logger.Infof("Download complete for %s", rawURL)
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command( //nolint:gosec
			"netsh", "advfirewall", "firewall", "add", "rule", "name="+path.Base(outPath),
			"dir=in", "action=allow", "program=\""+outPath+"\"", "enable=yes",
		)
		errRet = errors.Join(errRet, cmd.Start())
		if errRet == nil {
			waitErr := cmd.Wait()
			if waitErr != nil {
				user, _ := user.Current() //nolint:errcheck
				if user.Name != "SYSTEM" {
					// note: otherwise, we end up with a mostly-correct download but no version, which leads to other problems.
					logger.Info("Ignoring netsh error on non-SYSTEM windows")
				} else {
					errRet = errors.Join(errRet, waitErr)
				}
			}
		}
	}
	return outPath, errRet
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

	out, err := os.CreateTemp(ViamDirs["tmp"], "*")
	if err != nil {
		return "", err
	}

	defer func() {
		errRet = errors.Join(errRet, out.Close(), SyncFS(ViamDirs["tmp"]))
		if err := os.Remove(out.Name()); err != nil && !os.IsNotExist(err) {
			errRet = errors.Join(errRet, err)
		}
	}()

	_, err = io.Copy(out, reader)
	if err != nil && !os.IsNotExist(err) {
		errRet = errors.Join(errRet, err)
	}

	outPath = filepath.Join(ViamDirs["cache"], strings.Replace(filepath.Base(inPath), ".xz", "", 1))
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

// Simple io.WriteSeeker type for progress bar.
type progressMultiWriter struct {
	progressBar io.Writer
	outFile     io.WriteSeeker
}

func (pmw *progressMultiWriter) Write(p []byte) (n int, err error) {
	for _, w := range []io.Writer{pmw.progressBar, pmw.outFile} {
		n, err = w.Write(p)
		if err != nil {
			return
		}
		if n != len(p) {
			err = io.ErrShortWrite
			return
		}
	}
	return len(p), nil
}

func (pmw *progressMultiWriter) Seek(offset int64, whence int) (int64, error) {
	return pmw.outFile.Seek(offset, whence)
}

func downloadProgressSetup(ctx context.Context,
	outWriter io.WriteSeeker,
	outPath string,
	size int64,
	logger logging.Logger,
	workers *sync.WaitGroup,
) (io.WriteSeeker, context.CancelFunc) {
	bar := progressbar.NewOptions64(
		size,
		progressbar.OptionSetDescription("Downloading "+filepath.Base(outPath)),
		progressbar.OptionSetWriter(io.Discard),
		progressbar.OptionShowBytes(true),
		progressbar.OptionShowTotalBytes(true),
		progressbar.OptionSetWidth(10),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionSpinnerType(0),
	)
	writer := &progressMultiWriter{progressBar: bar, outFile: outWriter}
	barCtx, cancel := context.WithCancel(ctx)
	if err := bar.RenderBlank(); err != nil {
		logger.Warn(err)
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		logger.Info(bar.String())
		for {
			select {
			case <-barCtx.Done():
				logger.Info(bar.String())
				return
			case <-time.After(time.Second * 10):
				logger.Info(bar.String())
			}
		}
	}()
	return writer, cancel
}
