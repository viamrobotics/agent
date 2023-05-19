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
	"go.viam.com/rdk/config"
	"go.viam.com/utils"
)

var (
	activeBackgroundWorkers sync.WaitGroup
	logger = golog.NewDevelopmentLogger("viam-agent")
)

func main() {
	ctx := setupSignalHandling(context.TODO())

	var opts struct {
		Config     string `long:"config" short:"c" description:"Path to config file" default:"/etc/viam.json"`
		Debug      bool   `long:"debug" short:"d" description:"enable debug logging (for agent only)"`
		UpdateURL  string `long:"force-url" description:"Force URL for viam-server download" env:"FORCE_URL"`
		Help       bool   `long:"help" short:"h" description:"Show this help message"`
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
		logger = golog.NewDebugLogger("viam-agent")
	}

	exitIfError(loadConfig(ctx, opts.Config))

	activeBackgroundWorkers.Add(1)
	go func(){
		defer activeBackgroundWorkers.Done()
		testWorker(ctx)
	}()



	activeBackgroundWorkers.Wait()
	return
}

func loadConfig(ctx context.Context, cfgPath string) error {
	cfg, err := config.Read(ctx, cfgPath, logger)
	fmt.Println(cfg)
	return err
}

func setupSignalHandling(ctx context.Context) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 16)
	activeBackgroundWorkers.Add(1)
	go func(){
		defer activeBackgroundWorkers.Done()
		defer cancel()
		for {
			sig := <-sigChan
			switch sig {

			// things we exit for
			case os.Interrupt:
				fallthrough
			case syscall.SIGQUIT:
				fallthrough
			case syscall.SIGABRT:
				fallthrough
			case syscall.SIGTERM:
				logger.Info("exiting")
				signal.Ignore()
				return

			// things we ignore entirely
			case syscall.SIGURG:

			// log everything else
			default:
				logger.Debugw("recieved unknown signal", "signal", sig)
			}
		}
	}()
	signal.Notify(sigChan)
	return ctx
}


func testWorker(ctx context.Context) {
	for {
		fmt.Println("SMURF")
		if !utils.SelectContextOrWait(ctx, time.Second) {
			return
		}
	}
}

func exitIfError(err error) {
	if err != nil {
		logger.Error(err)
		os.Exit(1)
	}
}