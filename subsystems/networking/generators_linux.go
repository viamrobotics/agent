package networking

import (
	"encoding/binary"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	gnm "github.com/viamrobotics/gonetworkmanager/v2"
)

// This file contains the wifi/hotspot setting generation functions.

func generateHotspotSettings(id NetKey, psk string) gnm.ConnectionSettings {
	IPAsUint32, err := generateAddress(PortalBindAddr)
	if err != nil {
		// BindAddr is a const, so should only ever fail if code itself is changed/broken
		panic(err)
	}

	settings := gnm.ConnectionSettings{
		"connection": map[string]any{
			"id":             id.String(),
			"uuid":           uuid.New().String(),
			"type":           "802-11-wireless",
			"autoconnect":    false,
			"interface-name": id.Interface(),
		},
		"802-11-wireless": map[string]any{
			"mode": "ap",
			"ssid": []byte(id.SSID()),
		},
		"802-11-wireless-security": map[string]any{
			"key-mgmt": "wpa-psk",
			"psk":      psk,
		},
		"ipv4": map[string]any{
			"method":        "shared",
			"addresses":     [][]uint32{{IPAsUint32, 24, IPAsUint32}},
			"never-default": true,
		},
		"ipv6": map[string]any{
			"method": "disabled",
		},
	}
	return settings
}

func generateNetworkSettings(id NetKey, cfg utils.NetworkDefinition) (gnm.ConnectionSettings, error) {
	if id.Name() == "" || id.ifname == "" {
		return nil, errw.New("id cannot be empty")
	}
	settings := gnm.ConnectionSettings{}

	var netType string
	switch id.Type() {
	case NetworkTypeWifi:
		netType = "802-11-wireless"
	case NetworkTypeWired:
		netType = "802-3-ethernet"
	case NetworkTypeBluetooth:
		netType = NetworkTypeBluetooth
	default:
		return nil, errw.Errorf("unknown network type: %s", id.Type())
	}

	settings["connection"] = map[string]any{
		"id":                   id.String(),
		"uuid":                 uuid.New().String(),
		"type":                 netType,
		"autoconnect":          true,
		"autoconnect-priority": cfg.Priority,
	}

	if id.Type() != NetworkTypeBluetooth && id.Interface() != "" {
		settings["connection"]["interface-name"] = id.Interface()
	}

	// Handle Wifi
	if id.Type() == NetworkTypeWifi {
		settings["802-11-wireless"] = map[string]any{
			"mode": "infrastructure",
			"ssid": []byte(id.SSID()),
		}
		if cfg.PSK != "" {
			settings["802-11-wireless-security"] = map[string]any{"key-mgmt": "wpa-psk", "psk": cfg.PSK}
		}
	}

	// Handle bluetooth
	if id.Type() == NetworkTypeBluetooth {
		macAddr, err := net.ParseMAC(id.Interface())
		if err != nil {
			return nil, errw.Wrapf(err, "parsing bluetooth device address for %s", id.Interface())
		}

		settings[NetworkTypeBluetooth] = map[string]any{
			"type":   "panu",
			"bdaddr": macAddr,
		}
	}

	// Handle IP Config
	ip4, err := generateIPv4Settings(cfg)
	if err != nil {
		return settings, err
	}
	settings["ipv4"] = ip4

	return settings, nil
}

func generateIPv4Settings(cfg utils.NetworkDefinition) (map[string]any, error) {
	// -1 is special for "automatic"
	if cfg.IPv4RouteMetric == 0 {
		cfg.IPv4RouteMetric = -1
	}

	if cfg.IPv4Address == "" {
		return map[string]any{"method": "auto", "route-metric": cfg.IPv4RouteMetric}, nil
	}

	// CIDR format, ex: 192.168.0.1/24
	ip4Regex := regexp.MustCompile(`^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/?([0-9]{1,2})?$`)
	ret := ip4Regex.FindStringSubmatch(cfg.IPv4Address)
	if len(ret) != 3 {
		return nil, errw.Errorf("invalid ipv4 address: %s", cfg.IPv4Address)
	}

	ip, err := generateAddress(ret[1])
	if err != nil {
		return nil, err
	}

	var gateway uint32
	if len(cfg.IPv4Gateway) > 0 {
		gateway, err = generateAddress(cfg.IPv4Gateway)
		if err != nil {
			return nil, err
		}
	}

	mask, err := strconv.ParseUint(ret[2], 10, 32)
	if err != nil {
		return nil, errw.Wrapf(err, "parsing ipv4 netmask: %s", cfg.IPv4Address)
	}

	ip4 := map[string]any{
		"method":       "manual",
		"addresses":    [][]uint32{{ip, uint32(mask), gateway}},
		"route-metric": cfg.IPv4RouteMetric,
	}

	if len(cfg.IPv4DNS) > 0 {
		var dnsData []uint32
		for _, dns := range cfg.IPv4DNS {
			dnsInt, err := generateAddress(dns)
			if err != nil {
				return nil, errw.Errorf("error parsing DNS ipv4 address: %s", dns)
			}
			dnsData = append(dnsData, dnsInt)
		}
		ip4["dns"] = dnsData
	}

	return ip4, nil
}

// converts an ipv4 string (192.168.0.1) to a uint32 in network byte order.
func generateAddress(addr string) (uint32, error) {
	parseErr := errw.Errorf("parsing ipv4: %s", addr)
	// double-check with another library for correctness
	if net.ParseIP(addr) == nil {
		return 0, parseErr
	}

	ret := strings.Split(addr, ".")
	if len(ret) != 4 {
		return 0, parseErr
	}

	var outBytes []byte
	for _, nibble := range ret {
		b, err := strconv.ParseUint(nibble, 10, 8)
		if err != nil {
			return 0, parseErr
		}
		outBytes = append(outBytes, byte(b))
	}

	return binary.LittleEndian.Uint32(outBytes), nil
}
