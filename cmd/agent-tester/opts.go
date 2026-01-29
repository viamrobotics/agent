// nolint: lll
package main

type options struct {
	Help         bool   `description:"Show this help message" long:"help"                                                         short:"h"`
	SerialDevice string `default:"/dev/ttyUSB0"               description:"Path to serial device used to control viam-agent host" long:"serial-device" short:"d"`
	ConfigPath   string `default:"./agent-test.json"          description:"Path to config file for tests"                         long:"config"        short:"c"`
}
