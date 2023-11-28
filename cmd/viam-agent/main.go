package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/edaniels/golog"
	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
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
		Debug   bool   `description:"Enable debug logging (for agent only)" long:"debug"                      short:"d"`
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

	if opts.Debug {
		globalLogger = golog.NewDebugLogger("viam-agent")
	}

	// need to be root to go any further than this
	curUser, err := user.Current()
	exitIfError(err)
	if curUser.Uid != "0" {
		fmt.Printf("viam-agent must be run as root (uid 0), but current user is %s (uid %s)\n", curUser.Username, curUser.Uid)
		return
	}

	if opts.Install {
		err := viamagent.Install(globalLogger)
		if err != nil {
			globalLogger.Error(err)
		}
		return
	}

	if os.Getenv("VIAM_AGENT_DEVMODE") == "" {
		// confirm that we're running from a proper install
		if !strings.HasPrefix(os.Args[0], agent.ViamDirs["viam"]) {
			fmt.Printf("viam-agent is intended to be run as a system service and installed in %s.\n" +
				"Please install with '%s --install' and then start the service with 'systemctl start viam-agent'\n" +
				"Note you may need to preface the above commands with 'sudo' if you are not currently root.\n",
				agent.ViamDirs["viam"], os.Args[0])
			return
		}
	}

	// tie the manager config to the viam-server config
	absConfigPath, err := filepath.Abs(opts.Config)
	exitIfError(err)
	_, err = os.Stat(absConfigPath)
	exitIfError(errors.Wrap(err, "checking for config file"))

	viamserver.ConfigFilePath = absConfigPath
	globalLogger.Infof("config file path: %s", absConfigPath)

	// main manager structure
	manager, err := agent.NewManager(ctx, globalLogger, absConfigPath)
	exitIfError(err)

	// Check for self-update and restart if needed.
	needRestart, err := manager.SelfUpdate(ctx, globalLogger)
	if err != nil {
		globalLogger.Error(err)
	}
	if needRestart {
		globalLogger.Info("updated self, exiting to await restart with new version")
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
