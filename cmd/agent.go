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
	"go.viam.com/utils/pexec"
)

var (
	activeBackgroundWorkers sync.WaitGroup

	// only changed/set at startup, so no mutex
	globalLogger = golog.NewDevelopmentLogger("viam-agent")
	viamDir      = "/opt/viam"
	viamConf     = "/etc/viam.json"

	// mutex protected
	subsystemsMu sync.Mutex
	subsystems   map[string]agent.Subsystem
)

func main() {
	ctx := setupExitSignalHandling(context.TODO())
	subsystems = make(map[string]agent.Subsystem)

	var opts struct {
		Config    string `long:"config" short:"c" description:"Path to config file" default:"/etc/viam.json"`
		Debug     bool   `long:"debug" short:"d" description:"enable debug logging (for agent only)"`
		UpdateURL string `long:"force-url" description:"Force URL for viam-server download" env:"FORCE_URL"`
		Help      bool   `long:"help" short:"h" description:"Show this help message"`
	}

	p := flags.NewParser(&opts, flags.IgnoreUnknown)
	p.Usage = "runs as a background service and manages updates and the process lifecycle for viam-server."

	_, err := p.Parse()
	exitIfError(err)

	if opts.Help {
		var b bytes.Buffer
		p.WriteHelp(&b)
		fmt.Println(b.String())
		return
	}

	if opts.Debug {
		globalLogger = golog.NewDebugLogger("viam-agent")
	}
	viamConf = opts.Config

	// background process to check for updates
	activeBackgroundWorkers.Add(1)
	go func() {
		checkInterval := checkUpdates(ctx)
		timer := time.NewTimer(checkInterval)
		defer timer.Stop()
		defer activeBackgroundWorkers.Done()
		for {
			if ctx.Err() != nil {
				break
			}
			select {
			case <-ctx.Done():
				break
			// case <-sigHUP:
			// 	checkUpdates(ctx)
			case <-timer.C:
				checkInterval = checkUpdates(ctx)
				timer.Reset(checkInterval)
			}
		}
	}()

	<-ctx.Done()

	// close all subsystems
	for _, sub := range subsystems {
		if err := sub.Stop(); err != nil {
			globalLogger.Error(err)
		}
	}

	activeBackgroundWorkers.Wait()
	return
}

func loadConfig(ctx context.Context, cfgPath string) (agent.Config, error) {
	// load local config

	// connect client

	// get agent config

	return agent.GetTestConfig(), nil
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
				break
			}
			select {
			case <-ctx.Done():
				break
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
				globalLogger.Debugw("recieved unknown signal", "signal", sig)
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
	for k, sub := range subsystems {
		if _, ok := cfg.SubsystemConfigs[k]; !ok {
			if err := sub.Stop(); err != nil {
				globalLogger.Error(err)
				continue
			}
			delete(subsystems, k)
		}
	}

	// add new subsystems
	for k, subCfg := range cfg.SubsystemConfigs {
		if _, ok := subsystems[k]; !ok {
			switch k {
			case "viam-server":
				subsystems[k] = newViamServerSubsystem(ctx, subCfg)
			default:
				globalLogger.Warnw("unknown subsystem", "name", k)
			}
		}
	}

	// check updates and (re)start
	for k, sub := range subsystems {
		cancelCtx, cancel := context.WithTimeout(ctx, time.Minute*5)
		defer cancel()
		restart, err := sub.Update(cancelCtx, cfg.SubsystemConfigs[k])
		if err != nil {
			globalLogger.Error(err)
			continue
		}
		if restart {
			// if err := sub.Stop(); err != nil {
			// 	globalLogger.Error(err)
			// 	continue
			// }
		}
		if err := sub.Start(); err != nil {
			globalLogger.Error(err)
			continue
		}
	}
}

func checkUpdates(ctx context.Context) time.Duration {
	globalLogger.Info("SMURF check")
	cfg, _ := loadConfig(ctx, viamConf)

	// TODO check self-update

	// update and (re)start subsystems
	subsystemUpdates(ctx, cfg)

	// TODO fuzz the checkInterval
	return cfg.CheckInterval
}

type viamServerSubSystem struct {
	agent.DefaultSubsystem
}

func newViamServerSubsystem(ctx context.Context, updateConf agent.SubsystemConfig) agent.Subsystem {
	cfg := pexec.ProcessConfig{
		ID:        "viam-server",
		Name:      "bin/viam-server",
		Args:      []string{"-config", viamConf},
		CWD:       viamDir,
		Log:       true,
		LogWriter: nil,
		OnUnexpectedExit: func(sig int) bool {
			return true
		},
	}
	subSys := &viamServerSubSystem{}
	subSys.Logger = globalLogger.Named("viam-server")
	subSys.Process = pexec.NewManagedProcess(cfg, subSys.Logger)
	return subSys
}
