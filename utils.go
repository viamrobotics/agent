// Package agent contains the public interfaces, functions, consts, and vars for the viam-server agent.
package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	errw "github.com/pkg/errors"
	"github.com/ulikunitz/xz"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	// versions embedded at build time.
	Version     = ""
	GitRevision = ""

	ViamDirs = map[string]string{"viam": "/opt/viam"}
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
	ViamDirs["bin"] = filepath.Join(ViamDirs["viam"], "bin")
	ViamDirs["cache"] = filepath.Join(ViamDirs["viam"], "cache")
	ViamDirs["tmp"] = filepath.Join(ViamDirs["viam"], "tmp")
	ViamDirs["etc"] = filepath.Join(ViamDirs["viam"], "etc")
}

func InitPaths() error {
	uid := os.Getuid()
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
		if info.Mode().Perm() != 0o755 {
			return errw.Errorf("%s should be have permission set to 0755, but has permissions %d", p, info.Mode().Perm())
		}
	}
	return nil
}

// DownloadFile downloads a file into the cache directory and returns a path to the file.
func DownloadFile(ctx context.Context, rawURL string) (outPath string, errRet error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	outPath = filepath.Join(ViamDirs["cache"], path.Base(parsedURL.Path))

	//nolint:nestif
	if parsedURL.Scheme == "file" {
		infd, err := os.Open(parsedURL.Path)
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
			errRet = errors.Join(errRet, outfd.Close(), SyncFS(outPath))
			if err := os.Remove(outfd.Name()); err != nil && !os.IsNotExist(err) {
				errRet = errors.Join(errRet, err)
			}
		}()

		_, err = io.Copy(outfd, infd)
		if err != nil {
			return "", err
		}
		errRet = errors.Join(errRet, os.Rename(outfd.Name(), outPath))
		return outPath, errRet
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", errw.Errorf("unsupported url scheme %s", parsedURL.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return "", errw.Wrap(err, "checking viam-server status")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errw.Wrap(err, "checking viam-server status")
	}
	defer func() {
		errRet = errors.Join(errRet, resp.Body.Close())
	}()

	//nolint:gosec
	if err := os.MkdirAll(ViamDirs["tmp"], 0o755); err != nil {
		return "", err
	}

	out, err := os.CreateTemp(ViamDirs["tmp"], "*")
	if err != nil {
		return "", err
	}
	defer func() {
		errRet = errors.Join(errRet, out.Close(), SyncFS(out.Name()))
		if err := os.Remove(out.Name()); err != nil && !os.IsNotExist(err) {
			errRet = errors.Join(errRet, err)
		}
	}()

	_, err = io.Copy(out, resp.Body)
	if err != nil && !os.IsNotExist(err) {
		errRet = errors.Join(errRet, err)
	}

	errRet = errors.Join(errRet, os.Rename(out.Name(), outPath), SyncFS(outPath))
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

func fuzzTime(duration time.Duration, pct float64) time.Duration {
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
		return errw.Wrap(err, "symlinking file")
	}

	return SyncFS(symlink)
}

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

	return true, nil
}

func ConvertAttributes[T any](attributes *structpb.Struct) (*T, error) {
	jsonBytes, err := attributes.MarshalJSON()
	if err != nil {
		return new(T), err
	}

	newConfig := new(T)
	if err = json.Unmarshal(jsonBytes, newConfig); err != nil {
		return new(T), err
	}

	return newConfig, nil
}
