package agent

import (
	"encoding/hex"
	"time"

	"github.com/Masterminds/semver"
)

type Config struct {
	UpdateInfo
	SubsystemConfigs map[string]SubsystemConfig
	CheckInterval    time.Duration
}

type UpdateInfo struct {
	Filename string
	URL      string
	Version  *semver.Version
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
	// unknown/unset (autodetection may be attempted).
	FormatUnspecified = Format(iota)
	// do nothing.
	FormatRaw
	// decompress .xz file.
	FormatXZ
	// set executable permissions.
	FormatExecutable
	// decompress and set executable.
	FormatXZExecutable
)

// TODO fetch the actual config from the WIP endpoint on App
func GetTestConfig() Config {
	url := "https://storage.googleapis.com/packages.viam.com/apps/viam-server/viam-server-v0.6.0-x86_64"
	//nolint:errcheck
	// v0.3.0 sha, _ := hex.DecodeString("0f362a74cfcb5e18158af7342ac7a9fc053b75a19065550b111b1756f5631eed")
	sha, _ := hex.DecodeString("12112b05cc50045add9fba432992e0bb283e48659e048dcea1a9ba3d55149195")
	//nolint:errcheck
	version, _ := semver.NewVersion("v0.6.0")

	cfg := Config{
		UpdateInfo: UpdateInfo{
			Filename: "viam-agent",
			URL:      "",
			Version:  nil,
			SHA256:   []byte{},
			Format:   FormatUnspecified,
		},
		SubsystemConfigs: map[string]SubsystemConfig{
			"viam-server": {
				Name: "viam-server",
				UpdateInfo: UpdateInfo{
					Filename: "viam-server",
					URL:      url,
					Version:  version,
					SHA256:   sha,
					Format:   FormatExecutable,
				},
				Disable:      false,
				ForceRestart: false,
			},
		},
		CheckInterval: time.Second * 10,
	}

	return cfg
}
