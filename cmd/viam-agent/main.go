package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/edaniels/golog"
	"github.com/jessevdk/go-flags"
	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems/viamagent"
	"github.com/viamrobotics/agent/subsystems/viamserver"
)

var (
	activeBackgroundWorkers sync.WaitGroup

	// only changed/set at startup, so no mutex.
	globalLogger = golog.NewDevelopmentLogger("viam-agent")
)

func main() {
	ctx := setupExitSignalHandling(context.Background())

	var opts struct {
		Config  string `default:"/etc/viam.json"                            description:"Path to config file" long:"config" short:"c"`
		Debug   bool   `description:"enable debug logging (for agent only)" long:"debug"                      short:"d"`
		Help    bool   `description:"Show this help message"                long:"help"                       short:"h"`
		Version bool   `description:"Show version"                          long:"version"                    short:"v"`
		Install bool   `description:"Install systemd service"               long:"install"`
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

	if opts.Version {
		fmt.Printf("Version: %s\nGit Revision: %s\n", viamagent.GetVersion(), viamagent.GetRevision())
		return
	}

	// tie the manager config to the viam-server config
	absPath, err := filepath.Abs(opts.Config)
	exitIfError(err)
	viamserver.ConfigFilePath = absPath
	globalLogger.Infof("config file path: %s", absPath)

	if opts.Install {
		err := viamagent.Install()
		if err != nil {
			globalLogger.Error(err)
		}
		return
	}

	if opts.Debug {
		globalLogger = golog.NewDebugLogger("viam-agent")
	}

	// main manager structure
	manager, err := agent.NewManager(ctx, globalLogger, opts.Config)
	exitIfError(err)

	// Check for self-update and restart if needed.
	needRestart, err := manager.SelfUpdate(ctx, globalLogger)
	if err != nil {
		globalLogger.Error(err)
	}
	if needRestart {
		return
	}

	manager.StartBackgroundChecks(ctx, globalLogger)

	<-ctx.Done()

	closeContext, cancelFunc := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFunc()

	manager.CloseAll(closeContext, globalLogger)

	activeBackgroundWorkers.Wait()
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
				signal.Ignore(os.Interrupt, syscall.SIGTERM, syscall.SIGABRT) // keeping SIGQUIT for stack trace debugging
				return

			// this will eventually be handled elsewhere as a restart, not exit
			case syscall.SIGHUP:

			// ignore SIGURG entirely, it's used for real-time scheduling notifications
			case syscall.SIGURG:

			// log everything else
			default:
				globalLogger.Debugw("received unknown signal", "signal", sig)
			}
		}
	}()

	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGABRT)
	return ctx
}

func exitIfError(err error) {
	if err != nil {
		globalLogger.Fatal(err)
	}
}
