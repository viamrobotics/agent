package main

import (
	"bytes"
	"fmt"

	"github.com/jessevdk/go-flags"
)

var opts struct {
	BTMode   bool   `description:"Bluetooth Mode" long:"bluetooth"                           short:"b"`
	BTScan   bool   `description:"Bluetooth Scan" long:"scan"`
	BTFilter string `default:"viam-setup"         description:"Bluetooth Device Name Prefix" long:"filter" short:"f"`

	Address string `description:"GRPC address/port to dial (ex: 'localhost:4772')" long:"address" short:"a"`

	WifiSSID string `description:"SSID to set"           long:"wifi-ssid"`
	WifiPSK  string `description:"PSK/Password for wifi" long:"wifi-psk"`

	PSK string `description:"psk for bluetooth security" long:"psk"`

	AppAddr string `default:"https://app.viam.com:443"              description:"Cloud address to set in viam.json" long:"app-addr"`
	PartID  string `description:"PartID to set in viam.json"        long:"part-id"`
	Secret  string `description:"Device secret to set in viam.json" long:"secret"`

	Exit bool `description:"Tell the device to exit provisioning mode" long:"exit" short:"e"`

	Status   bool `description:"Get device status"      long:"status"   short:"s"`
	Info     bool `description:"Get device info"        long:"info"     short:"i"`
	Networks bool `description:"List networks"          long:"networks" short:"n"`
	Help     bool `description:"Show this help message" long:"help"     short:"h"`
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

	if opts.PartID != "" || opts.Secret != "" {
		if opts.PartID == "" || opts.Secret == "" || opts.AppAddr == "" {
			fmt.Println("Error: Must set both Secret and PartID (and optionally AppAddr) at the same time!")
			return false
		}
	}

	return true
}
