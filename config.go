package agent

import (
	"encoding/hex"
	"time"
)

type Config struct {
	UpdateInfo
	SubsystemConfigs map[string]SubsystemConfig
	CheckInterval    time.Duration
}

type UpdateInfo struct {
	Filename string
	URL      string
	Version  string
	SHA256   []byte
	Format   Format
}

type SubsystemConfig struct {
	Name string
	UpdateInfo
	Disable      bool
	ForceRestart bool
}

type Format uint8

const (
	// unknown/unset (autodetection may be attempted)
	FORMAT_UNSPECIFIED = Format(iota)
	// do nothing
	FORMAT_RAW
	// decompress .xz file
	FORMAT_XZ
	// set executable permissions
	FORMAT_EXECUTABLE
	// decompress and set executable
	FORMAT_XZ_EXECUTABLE
)

func GetTestConfig() Config {
	url := "https://storage.googleapis.com/packages.viam.com/apps/viam-server/viam-server-stable-x86_64"
	sha, _ := hex.DecodeString("0f362a74cfcb5e18158af7342ac7a9fc053b75a19065550b111b1756f5631eed")
	version := "0.3.0"

	cfg := Config{
		UpdateInfo: UpdateInfo{
			Filename: "viam-agent",
			URL:      "",
			Version:  "0.0.1-rc0",
			SHA256:   []byte{},
			Format:   FORMAT_UNSPECIFIED,
		},
		SubsystemConfigs: map[string]SubsystemConfig{
			"viam-server": {
				Name: "viam-server",
				UpdateInfo: UpdateInfo{
					Filename: "viam-server",
					URL:      url,
					Version:  version,
					SHA256:   sha,
					Format:   FORMAT_UNSPECIFIED,
				},
				Disable:      false,
				ForceRestart: false,
			},
		},
		CheckInterval: time.Second * 10,
	}

	return cfg
}
