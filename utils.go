// Package agent contains the public interfaces, functions, consts, and vars for the viam-server agent.
package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
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
)

var ViamDirs = map[string]string{"viam": "/opt/viam"}

func init() {
	ViamDirs["bin"] = filepath.Join(ViamDirs["viam"], "bin")
	ViamDirs["cache"] = filepath.Join(ViamDirs["viam"], "cache")
	ViamDirs["tmp"] = filepath.Join(ViamDirs["viam"], "tmp")
	ViamDirs["etc"] = filepath.Join(ViamDirs["viam"], "etc")
}

// DownloadFile downloads a file into the cache directory and returns a path to the file.
func DownloadFile(ctx context.Context, rawURL string) (outPath string, errRet error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	outPath = filepath.Join(ViamDirs["cache"], path.Base(parsedURL.Path))

	if parsedURL.Scheme == "file" {
		infd, err := os.Open(parsedURL.Path)
		if err != nil {
			return "", err
		}
		defer func() {
			errRet = errors.Join(errRet, infd.Close())
		}()

		if err := os.MkdirAll(ViamDirs["tmp"], 0o755); err != nil {
			return "", err
		}

		outfd, err := os.CreateTemp(ViamDirs["tmp"], "*")
		if err != nil {
			return "", err
		}
		defer func() {
			errRet = errors.Join(errRet, outfd.Close())
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

	if err := os.MkdirAll(ViamDirs["tmp"], 0o755); err != nil {
		return "", err
	}

	out, err := os.CreateTemp(ViamDirs["tmp"], "*")
	if err != nil {
		return "", err
	}
	defer func() {
		errRet = errors.Join(errRet, out.Close())
		if err := os.Remove(out.Name()); err != nil && !os.IsNotExist(err) {
			errRet = errors.Join(errRet, err)
		}
	}()

	_, err = io.Copy(out, resp.Body)
	if err != nil && !os.IsNotExist(err) {
		errRet = errors.Join(errRet, err)
	}

	errRet = errors.Join(errRet, os.Rename(out.Name(), outPath))
	return outPath, errRet
}

// DecompressFile extracts a compressed file and returns the path to the extracted file.
func DecompressFile(inPath string) (outPath string, errRet error) {
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
		errRet = errors.Join(errRet, out.Close())
		if err := os.Remove(out.Name()); err != nil && !os.IsNotExist(err) {
			errRet = errors.Join(errRet, err)
		}
	}()

	_, err = io.Copy(out, reader)
	if err != nil && !os.IsNotExist(err) {
		errRet = errors.Join(errRet, err)
	}

	outPath = filepath.Join(ViamDirs["cache"], strings.Replace(filepath.Base(inPath), ".xz", "", 1))
	errRet = errors.Join(errRet, os.Rename(out.Name(), outPath))
	return outPath, errRet
}

func GetFileSum(filepath string) (outSum []byte, errRet error) {
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
		return false, errw.Wrapf(err, "cannot evaluate symlinks pointing to %s", path1)
	}

	stat1, err := os.Stat(curPath)
	if err != nil {
		return false, errw.Wrapf(err, "cannot stat %s", curPath)
	}

	realPath, err := filepath.EvalSymlinks(path2)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errw.Wrapf(err, "cannot evaluate symlinks pointing to %s", path2)
	}

	stat2, err := os.Stat(realPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errw.Wrapf(err, "cannot stat %s", realPath)
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
	return nil
}
