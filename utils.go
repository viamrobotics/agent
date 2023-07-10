// Package agent contains the public interfaces, functions, consts, and vars for the viam-server agent.
package agent

import (
	"bufio"
	"crypto/sha256"
	"io"
	"net/http"
	"os"
	"path"

	"github.com/ulikunitz/xz"
)

const (
	ViamDir = "/opt/viam"
)

func DownloadFile(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if err := os.MkdirAll(path.Join(ViamDir, "tmp"), 0o755); err != nil {
		return "", err
	}

	out, err := os.CreateTemp(path.Join(ViamDir, "tmp"), "*")
	if err != nil {
		return "", err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return out.Name(), err
}

func DecompressFile(filepath string) (string, error) {
	in, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer in.Close()

	reader, err := xz.NewReader(bufio.NewReader(in))
	if err != nil {
		return "", err
	}

	out, err := os.CreateTemp(path.Join(ViamDir, "tmp"), "*")
	if err != nil {
		return "", err
	}
	defer out.Close()

	_, err = io.Copy(out, reader)
	return out.Name(), err
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