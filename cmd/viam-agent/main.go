package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/edaniels/golog"
	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/viamserver"
)

var (
	activeBackgroundWorkers sync.WaitGroup

	// only changed/set at startup, so no mutex.
	globalLogger = golog.NewDevelopmentLogger("viam-agent")

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

	// create all needed directories
	exitIfError(initPaths())
	exitIfError(loadConfig(opts.Config))

	startBackgroundChecks(ctx)

	<-ctx.Done()

	// close all subsystems
	for _, sub := range subsystems {
		if err := sub.Stop(context.Background()); err != nil {
			globalLogger.Error(err)
		}
	}

	activeBackgroundWorkers.Wait()
}

func initPaths() error {
	// TODO Walk all files for ownership/permissions

	uid := os.Getuid()
	for _, p := range agent.ViamDirs {
		info, err := os.Stat(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				if err := os.MkdirAll(p, 0o755); err != nil {
					return err
				}
				continue
			}
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			// should be impossible on Linux
			return errors.New("cannot convert to syscall.Stat_t")
		}
		if uid != int(stat.Uid) {
			return errors.Errorf("%s is owned by UID %d but the current UID is %d", p, stat.Uid, uid)
		}
		if !info.IsDir() {
			return errors.Errorf("%s should be a directory, but is not", p)
		}
		if info.Mode().Perm() != 0o755 {
			return errors.Errorf("%s should be have permission set to 0755, but has permissions %d", p, info.Mode().Perm())
		}
	}
	return nil
}

func loadConfig(cfgPath string) error {
	globalLogger.Debugw("loading", "config", cfgPath)
	b, err := os.ReadFile(cfgPath)
	exitIfError(err)

	cfg := make(map[string]map[string]string)
	exitIfError(json.Unmarshal(b, &cfg))

	cloud, ok := cfg["cloud"]
	if !ok {
		exitIfError(errors.New("no cloud section in local config file"))
	}
	return agent.Dial(context.TODO(), globalLogger, cloud["app_address"], cloud["id"], cloud["secret"])
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
				subsystemHealthChecks(ctx)
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
				signal.Ignore(os.Interrupt, syscall.SIGTERM, syscall.SIGABRT) // SMURF keeping SIGQUIT for stack trace debugging
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
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGABRT) // SMURF SIGQUIT reserved for stack trace debugging
	return ctx
}

func exitIfError(err error) {
	if err != nil {
		globalLogger.Error(err)
		os.Exit(1)
	}
}

func subsystemUpdates(ctx context.Context, cfg agent.Config) {
	subsystemsMu.Lock()
	defer subsystemsMu.Unlock()
	// stop/remove orphaned subsystems
	for key, sub := range subsystems {
		if _, ok := cfg.SubsystemConfigs[key]; !ok {
			if err := sub.Stop(ctx); err != nil {
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
				sub, err := agent.NewAgentSubsystem(ctx, subCfg, globalLogger, viamserver.NewSubsystem(ctx, subCfg, globalLogger))
				if err != nil {
					globalLogger.Error(err)
					continue
				}
				subsystems[key] = sub
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
			if err := sub.Stop(ctx); err != nil {
				globalLogger.Error(err)
				continue
			}
		}
		if err := sub.Start(ctx); err != nil {
			globalLogger.Error(err)
			continue
		}
	}
}

func checkUpdates(ctx context.Context) time.Duration {
	globalLogger.Info("SMURF check for update")
	cfg, err := agent.GetConfig(ctx)
	if err != nil {
		globalLogger.Error(err)
	}

	fmt.Println("SMURF CONFIG", cfg)

	// check for agent updates
	selfUpdate(ctx, *cfg)

	// update and (re)start subsystems
	subsystemUpdates(ctx, *cfg)

	// randomly fuzz the interval by +/- 5%
	return fuzzTime(cfg.CheckInterval, 0.05)
}

func subsystemHealthChecks(ctx context.Context) {
	globalLogger.Info("SMURF check statuses")
	subsystemsMu.Lock()
	defer subsystemsMu.Unlock()
	for _, sub := range subsystems {
		ctxTimeout, cancelFunc := context.WithTimeout(ctx, time.Second*15)
		if err := sub.HealthCheck(ctxTimeout); err != nil {
			globalLogger.Error("subsystem healthcheck failed")
			if err := sub.Stop(ctx); err != nil {
				globalLogger.Error(errors.Wrap(err, "stopping subsystem"))
			}
			if err := sub.Start(ctx); err != nil {
				globalLogger.Error(errors.Wrap(err, "restarting subsystem"))
			}
		}
		cancelFunc()
	}
}

func fuzzTime(duration time.Duration, pct float64) time.Duration {
	// pct is fuzz factor percentage 0.0 - 1.0
	// example +/- 5% is 0.05
	random := rand.New(rand.NewSource(time.Now().UnixNano())).Float64()
	slop := float64(duration) * pct * 2
	return time.Duration(float64(duration) - slop + (random * slop))
}

func selfUpdate(ctx context.Context, cfg agent.Config) {
	// SMURF TODO
	return
}
