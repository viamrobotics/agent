package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/edaniels/golog"
	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	_ "github.com/viamrobotics/agent/subsystems/viamserver"
)

var (
	activeBackgroundWorkers sync.WaitGroup

	// only changed/set at startup, so no mutex.
	globalLogger = golog.NewDevelopmentLogger("viam-agent")
)

func main() {
	ctx := setupExitSignalHandling(context.TODO())

	var opts struct {
		Config    string `default:"/opt/viam/etc/viam.json"                   description:"Path to config file" long:"config"    short:"c"`
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
	exitIfError(loadLocalConfig(opts.Config))

	agent.StartBackgroundChecks(ctx, globalLogger)

	<-ctx.Done()

	closeContext, cancelFunc := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFunc()

	agent.CloseAll(closeContext, globalLogger)

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

func loadLocalConfig(cfgPath string) error {
	globalLogger.Debugw("loading", "config", cfgPath)
	b, err := os.ReadFile(cfgPath)
	exitIfError(err)

	cfg := make(map[string]map[string]string)
	exitIfError(json.Unmarshal(b, &cfg))

	cloud, ok := cfg["cloud"]
	if !ok {
		exitIfError(errors.New("no cloud section in local config file"))
	}

	for _, req := range []string{"app_address", "id", "secret"} {
		field, ok := cloud[req]
		if !ok {
			exitIfError(errors.Errorf("no cloud config field for %s", field))
		}
	}

	return agent.Dial(context.TODO(), globalLogger, cloud["app_address"], cloud["id"], cloud["secret"])
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
		globalLogger.Fatal(err)
	}
}
