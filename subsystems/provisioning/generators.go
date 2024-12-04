package provisioning

import (
	"encoding/binary"
	"net"
	"regexp"
	"strconv"
	"strings"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	"github.com/google/uuid"
	errw "github.com/pkg/errors"
)

// This file contains the wifi/hotspot setting generation functions.

func generateHotspotSettings(id, ssid, psk, ifName string) gnm.ConnectionSettings {
	IPAsUint32, err := generateAddress(PortalBindAddr)
	if err != nil {
		// BindAddr is a const, so should only ever fail if code itself is changed/broken
		panic(err)
	}

	settings := gnm.ConnectionSettings{
		"connection": map[string]any{
			"id":             id,
			"uuid":           uuid.New().String(),
			"type":           "802-11-wireless",
			"autoconnect":    false,
			"interface-name": ifName,
		},
		"802-11-wireless": map[string]any{
			"mode": "ap",
			"ssid": []byte(ssid),
		},
		"802-11-wireless-security": map[string]any{
			"key-mgmt": "wpa-psk",
			"psk":      psk,
		},
		"ipv4": map[string]any{
			"method":    "shared",
			"addresses": [][]uint32{{IPAsUint32, 24, IPAsUint32}},
		},
		"ipv6": map[string]any{
			"method": "disabled",
		},
	}
	return settings
}

func generateNetworkSettings(id string, cfg NetworkConfig) (gnm.ConnectionSettings, error) {
	settings := gnm.ConnectionSettings{}
	if id == "" {
		return nil, errw.New("id cannot be empty")
	}

	var netType string
	switch cfg.Type {
	case NetworkTypeWifi:
		netType = "802-11-wireless"
	case NetworkTypeWired:
		netType = "802-3-ethernet"
	default:
		return nil, errw.Errorf("unknown network type: %s", cfg.Type)
	}

	settings["connection"] = map[string]any{
		"id":                   id,
		"uuid":                 uuid.New().String(),
		"type":                 netType,
		"autoconnect":          true,
		"autoconnect-priority": cfg.Priority,
	}

	if cfg.Interface != "" {
		settings["connection"]["interface-name"] = cfg.Interface
	}

	// Handle Wifi
	if cfg.Type == NetworkTypeWifi {
		settings["802-11-wireless"] = map[string]any{
			"mode": "infrastructure",
			"ssid": []byte(cfg.SSID),
		}
		if cfg.PSK != "" {
			settings["802-11-wireless-security"] = map[string]any{"key-mgmt": "wpa-psk", "psk": cfg.PSK}
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

func generateIPv4Settings(cfg NetworkConfig) (map[string]any, error) {
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
		"addresses":    [][]uint32{{ip, uint32(mask), gateway}}, //nolint:gosec
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
