package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/edaniels/golog"
	"github.com/jessevdk/go-flags"
	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/viamserver"
)

var (
	activeBackgroundWorkers sync.WaitGroup

	// only changed/set at startup, so no mutex.
	globalLogger = golog.NewDevelopmentLogger("viam-agent")

	viamConf = "/etc/viam.json"

	// mutex protected.
	subsystemsMu sync.Mutex
	subsystems   map[string]agent.Subsystem
)

func main() {
	ctx := setupExitSignalHandling(context.TODO())
	subsystems = make(map[string]agent.Subsystem)

	var opts struct {
		Config    string `default:"/etc/viam.json"                            description:"Path to config file" long:"config"    short:"c"`
		Debug     bool   `description:"enable debug logging (for agent only)" long:"debug"                      short:"d"`
		Help      bool   `description:"Show this help message"                long:"help"                       short:"h"`
		UpdateURL string `description:"Force URL for viam-server download"    env:"FORCE_URL"                   long:"force-url"`
	}

	parser := flags.NewParser(&opts, flags.IgnoreUnknown)
	parser.Usage = "runs as a background service and manages updates and the process lifecycle for viam-server."

	_, err := parser.Parse()
	exitIfError(err)

	if opts.Help {
		var b bytes.Buffer
		parser.WriteHelp(&b)
		//nolint:forbidigo
		fmt.Println(b.String())
		return
	}

	if opts.Debug {
		globalLogger = golog.NewDebugLogger("viam-agent")
	}
	viamConf = opts.Config

	startBackgroundChecks(ctx)

	<-ctx.Done()

	// close all subsystems
	for _, sub := range subsystems {
		if err := sub.Stop(); err != nil {
			globalLogger.Error(err)
		}
	}

	activeBackgroundWorkers.Wait()
}

func loadConfig(cfgPath string) agent.Config {
	// load local config
	globalLogger.Debugw("NOT loading", "config", cfgPath)
	// connect client

	// get agent config

	return agent.GetTestConfig()
}

func startBackgroundChecks(ctx context.Context) {
	activeBackgroundWorkers.Add(1)
	go func() {
		checkInterval := checkUpdates(ctx)
		timer := time.NewTimer(checkInterval)
		defer timer.Stop()
		defer activeBackgroundWorkers.Done()
		for {
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			// case <-sigHUP:
			// 	checkUpdates(ctx)
			case <-timer.C:
				checkInterval = checkUpdates(ctx)
				timer.Reset(checkInterval)
			}
		}
	}()
}

func setupExitSignalHandling(ctx context.Context) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 16)
	activeBackgroundWorkers.Add(1)
	go func() {
		defer activeBackgroundWorkers.Done()
		defer cancel()
		for {
			var sig os.Signal
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case sig = <-sigChan:
			}

			switch sig {
			// things we exit for
			case os.Interrupt:
				fallthrough
			case syscall.SIGQUIT:
				fallthrough
			case syscall.SIGABRT:
				fallthrough
			case syscall.SIGTERM:
				globalLogger.Info("exiting")
				signal.Ignore(os.Interrupt)
				return

			// this is handled elsewhere as a restart, not exit
			case syscall.SIGHUP:

			// ignore SIGURG entirely, it's used for real-time scheduling notifications
			case syscall.SIGURG:

			// log everything else
			default:
				globalLogger.Debugw("received unknown signal", "signal", sig)
			}
		}
	}()

	// TODO remove and handle ALL signals
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	return ctx
}

func exitIfError(err error) {
	if err != nil {
		globalLogger.Error(err)
		os.Exit(1)
	}
}

func subsystemUpdates(ctx context.Context, cfg agent.Config) {
	// TODO check updates for subsystems
	subsystemsMu.Lock()
	defer subsystemsMu.Unlock()
	// stop/remove orphaned subsystems
	for key, sub := range subsystems {
		if _, ok := cfg.SubsystemConfigs[key]; !ok {
			if err := sub.Stop(); err != nil {
				globalLogger.Error(err)
				continue
			}
			delete(subsystems, key)
		}
	}

	// add new subsystems
	for key, subCfg := range cfg.SubsystemConfigs {
		if _, ok := subsystems[key]; !ok {
			switch key {
			case "viam-server":
				subsystems[key] = viamserver.NewSubsystem(ctx, subCfg, globalLogger)
			default:
				globalLogger.Warnw("unknown subsystem", "name", key)
			}
		}
	}

	// check updates and (re)start
	for key, sub := range subsystems {
		cancelCtx, cancel := context.WithTimeout(ctx, time.Minute*5)
		defer cancel()
		restart, err := sub.Update(cancelCtx, cfg.SubsystemConfigs[key])
		if err != nil {
			globalLogger.Error(err)
			continue
		}
		if restart {
			if err := sub.Stop(); err != nil {
				globalLogger.Error(err)
				continue
			}
		}
		if err := sub.Start(); err != nil {
			globalLogger.Error(err)
			continue
		}
	}
}

func checkUpdates(ctx context.Context) time.Duration {
	globalLogger.Info("SMURF check")
	cfg := loadConfig(viamConf)

	// TODO check self-update

	// update and (re)start subsystems
	subsystemUpdates(ctx, cfg)

	// TODO fuzz the checkInterval
	return cfg.CheckInterval
}
