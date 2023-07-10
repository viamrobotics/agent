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

func GetTestConfig() Config {
	url := "https://storage.googleapis.com/packages.viam.com/apps/viam-server/viam-server-stable-x86_64"
	//nolint:errcheck
	sha, _ := hex.DecodeString("0f362a74cfcb5e18158af7342ac7a9fc053b75a19065550b111b1756f5631eed")
	version := "0.3.0"

	cfg := Config{
		UpdateInfo: UpdateInfo{
			Filename: "viam-agent",
			URL:      "",
			Version:  "0.0.1-rc0",
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
					Format:   FormatUnspecified,
				},
				Disable:      false,
				ForceRestart: false,
			},
		},
		CheckInterval: time.Second * 10,
	}

	return cfg
}
