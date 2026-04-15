package main

import (
	"bytes"
	"fmt"

	"github.com/jessevdk/go-flags"
)

// APIKey is inlined from github.com/viamrobotics/agent/utils to avoid depending on the parent module.
type APIKey struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

func (a APIKey) IsEmpty() bool {
	return a.ID == "" && a.Key == ""
}

func (a APIKey) IsFullySet() bool {
	return a.ID != "" && a.Key != ""
}

func (a APIKey) IsPartiallySet() bool {
	return !a.IsEmpty() && !a.IsFullySet()
}

var opts struct {
	BTMode   bool   `description:"Bluetooth Mode" long:"bluetooth"                           short:"b"`
	BTScan   bool   `description:"Bluetooth Scan" long:"scan"`
	BTFilter string `default:"viam-setup"         description:"Bluetooth Device Name Prefix" long:"filter" short:"f"`

	UnlockPairing bool `description:"Unlock bluetooth pairing (for tethering)" long:"pairing" short:"p"`

	Address string `description:"GRPC address/port to dial (ex: 'localhost:4772')" long:"address" short:"a"`

	WifiSSID string `description:"SSID to set"           long:"wifi-ssid"`
	WifiPSK  string `description:"PSK/Password for wifi" long:"wifi-psk"`

	PSK string `description:"psk for bluetooth security" long:"psk"`

	AppAddr   string `default:"https://app.viam.com:443"              description:"Cloud address to set in viam.json" long:"app-addr"`
	PartID    string `description:"PartID to set in viam.json"        long:"part-id"`
	Secret    string `description:"Device secret to set in viam.json" long:"secret"`
	APIKeyID  string `description:"API Key ID"                        long:"api-key-id"`
	APIKeyKey string `description:"API Key secret"                    long:"api-key-key"`
	APIKey    APIKey

	Exit bool `description:"Tell the device to exit provisioning mode" long:"exit" short:"e"`

	Status   bool `description:"Get device status"      long:"status"   short:"s"`
	Info     bool `description:"Get device info"        long:"info"     short:"i"`
	Networks bool `description:"List networks"          long:"networks" short:"n"`
	Help     bool `description:"Show this help message" long:"help"     short:"h"`
}

func SetAPIKey() {
	opts.APIKey = APIKey{
		ID:  opts.APIKeyID,
		Key: opts.APIKeyKey,
	}
}

func parseOpts() bool {
	parser := flags.NewParser(&opts, flags.IgnoreUnknown)
	parser.Usage = "runs as a background service and manages updates and the process lifecycle for viam-server."

	_, err := parser.Parse()
	if err != nil {
		panic(err)
	}

	if (!opts.BTScan && !opts.BTMode) &&
		(opts.Address == "" || (opts.PartID == "" && opts.WifiSSID == "" && !opts.Networks && !opts.Status && !opts.Info)) {
		opts.Help = true
	}

	if opts.Help {
		var b bytes.Buffer
		parser.WriteHelp(&b)

		fmt.Println(b.String())
		return false
	}

	SetAPIKey()
	if opts.PartID != "" || opts.Secret != "" || !opts.APIKey.IsEmpty() {
		if opts.PartID == "" || opts.AppAddr == "" {
			fmt.Println("Error: Must set PartID and AppAddr when configuring credentials!")
			return false
		}

		if opts.APIKey.IsPartiallySet() {
			fmt.Println("Error: API Key must have both ID and Key set, or neither!")
			return false
		}

		if opts.Secret == "" && opts.APIKey.IsEmpty() {
			fmt.Println("Error: Must provide either Secret or complete API Key!")
			return false
		}
	}

	return true
}
