// Package agent contains the public interfaces, functions, consts, and vars for the viam-server agent.
package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/ulikunitz/xz"
	"go.uber.org/multierr"
)

var ViamDirs = map[string]string{"viam": "/opt/viam"}

func init() {
	ViamDirs["etc"] = filepath.Join(ViamDirs["viam"], "etc")
	ViamDirs["bin"] = filepath.Join(ViamDirs["viam"], "bin")
	ViamDirs["cache"] = filepath.Join(ViamDirs["viam"], "cache")
	ViamDirs["tmp"] = filepath.Join(ViamDirs["viam"], "tmp")
}

func DownloadFile(ctx context.Context, url string) (filename string, errRet error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", errors.Wrap(err, "checking viam-server status")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "checking viam-server status")
	}
	defer resp.Body.Close()

	if err := os.MkdirAll(ViamDirs["tmp"], 0o755); err != nil {
		return "", err
	}

	out, err := os.CreateTemp(ViamDirs["tmp"], "*")
	if err != nil {
		return "", err
	}
	defer func() {
		err := out.Close()
		if err != nil {
			errRet = multierr.Combine(errRet, err)
		}
		err = os.Remove(out.Name())
		if err != nil && !os.IsNotExist(err) {
			errRet = multierr.Combine(errRet, err)
		}
	}()

	_, err = io.Copy(out, resp.Body)
	if err != nil && !os.IsNotExist(err) {
		errRet = multierr.Combine(errRet, err)
	}

	filename = filepath.Join(ViamDirs["cache"], path.Base(url))
	return filename, os.Rename(out.Name(), filename)
}

func DecompressFile(inPath string) (outPath string, errRet error) {
	in, err := os.Open(inPath)
	if err != nil {
		return "", err
	}
	defer in.Close()

	reader, err := xz.NewReader(bufio.NewReader(in))
	if err != nil {
		return "", err
	}

	out, err := os.CreateTemp(ViamDirs["tmp"], "*")
	if err != nil {
		return "", err
	}

	defer func() {
		err := out.Close()
		if err != nil {
			errRet = multierr.Combine(errRet, err)
		}
		err = os.Remove(out.Name())
		if err != nil && !os.IsNotExist(err) {
			errRet = multierr.Combine(errRet, err)
		}
	}()

	_, err = io.Copy(out, reader)
	if err != nil && !os.IsNotExist(err) {
		errRet = multierr.Combine(errRet, err)
	}

	outPath = filepath.Join(ViamDirs["cache"], strings.Replace(filepath.Base(inPath), ".xz", "", 1))
	return outPath, os.Rename(out.Name(), outPath)
}

func GetFileSum(filepath string) ([]byte, error) {
	in, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	h := sha256.New()
	_, err = io.Copy(h, in)
	return h.Sum(nil), err
}
