package main

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/edaniels/golog"
	"github.com/jessevdk/go-flags"
	"github.com/nightlyone/lockfile"
	"github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems/provisioning"
	"github.com/viamrobotics/agent/subsystems/syscfg"
	"github.com/viamrobotics/agent/subsystems/viamagent"
	"github.com/viamrobotics/agent/subsystems/viamserver"
	"go.viam.com/utils"
)

var (
	activeBackgroundWorkers sync.WaitGroup

	// only changed/set at startup, so no mutex.
	globalLogger = golog.NewDevelopmentLogger("viam-agent")
)

//nolint:gocognit
func main() {
	ctx := setupExitSignalHandling()

	var opts struct {
		Config  string `default:"/etc/viam.json"                            description:"Path to config file" long:"config" short:"c"`
		Debug   bool   `description:"Enable debug logging (for agent only)" env:"VIAM_AGENT_DEBUG"            long:"debug"  short:"d"`
		Fast    bool   `description:"Enable faststart mode"                 env:"VIAM_AGENT_FASTSTART"        long:"fast"   short:"f"`
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
		//nolint:forbidigo
		fmt.Printf("Version: %s\nGit Revision: %s\n", viamagent.GetVersion(), viamagent.GetRevision())
		return
	}

	if opts.Debug {
		globalLogger = golog.NewDebugLogger("viam-agent")
		provisioning.Debug = true
		syscfg.Debug = true
	}

	// need to be root to go any further than this
	curUser, err := user.Current()
	exitIfError(err)
	if curUser.Uid != "0" {
		//nolint:forbidigo
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
			//nolint:forbidigo
			fmt.Printf("viam-agent is intended to be run as a system service and installed in %s.\n"+
				"Please install with '%s --install' and then start the service with 'systemctl start viam-agent'\n"+
				"Note you may need to preface the above commands with 'sudo' if you are not currently root.\n",
				agent.ViamDirs["viam"], os.Args[0])
			return
		}
	}

	// set up folder structure
	exitIfError(agent.InitPaths())

	// use a lockfile to prevent running two agents on the same machine
	pidFile, err := getLock()
	exitIfError(err)
	defer func() {
		if err := pidFile.Unlock(); err != nil {
			globalLogger.Error(errors.Wrapf(err, "unlocking %s", pidFile))
		}
	}()

	// tie the manager config to the viam-server config
	absConfigPath, err := filepath.Abs(opts.Config)
	exitIfError(err)

	viamserver.ConfigFilePath = absConfigPath
	provisioning.AppConfigFilePath = absConfigPath
	globalLogger.Infof("config file path: %s", absConfigPath)

	// main manager structure
	manager, err := agent.NewManager(ctx, globalLogger)
	exitIfError(err)

	err = manager.LoadConfig(absConfigPath)
	//nolint:nestif
	if err != nil {
		// If the local /etc/viam.json config is corrupted, invalid, or missing (due to a new install), we can get stuck here.
		// Rename the file (if it exists) and wait to provision a new one.
		if !errors.Is(err, fs.ErrNotExist) {
			if err := os.Rename(absConfigPath, absConfigPath+".old"); err != nil {
				// if we can't rename the file, we're up a creek, and it's fatal
				globalLogger.Error(errors.Wrapf(err, "removing invalid config file %s", absConfigPath))
				globalLogger.Error("unable to continue with provisioning, exiting")
				manager.CloseAll()
				return
			}
		}

		// We manually start the provisioning service to allow the user to update it and wait.
		// The user may be updating it soon, so better to loop quietly than to exit and let systemd keep restarting infinitely.
		globalLogger.Infof("main config file %s missing or corrupt, entering provisioning mode", absConfigPath)

		if err := manager.StartSubsystem(ctx, provisioning.SubsysName); err != nil {
			if errors.Is(err, agent.ErrSubsystemDisabled) {
				globalLogger.Warn("provisioning subsystem disabled, please manually update /etc/viam.json and connect to internet")
			} else {
				globalLogger.Error(errors.Wrapf(err,
					"could not start provisioning subsystem, please manually update /etc/viam.json and connect to internet"))
			}
		}

		for {
			globalLogger.Warn("waiting for user provisioning")
			if !utils.SelectContextOrWait(ctx, time.Second*10) {
				manager.CloseAll()
				activeBackgroundWorkers.Wait()
				return
			}
			if err := manager.LoadConfig(absConfigPath); err == nil {
				break
			}
		}
	}

	// if faststart is set, skip updates and start viam-server immediately, the proceed as normal
	if opts.Fast {
		if err := manager.StartSubsystem(ctx, viamserver.SubsysName); err != nil {
			globalLogger.Error(err)
		}
	} else {
		// wait to be online
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		for {
			cmd := exec.CommandContext(timeoutCtx, "systemctl", "is-active", "network-online.target")
			_, err := cmd.CombinedOutput()

			if err == nil {
				break
			}

			if errors.As(err, &exec.ExitError{}) {
				// if it's not an ExitError, that means it didn't even start, so bail out
				globalLogger.Error(errors.Wrap(err, "running 'systemctl is-active network-online.target'"))
				break
			}
			if !utils.SelectContextOrWait(timeoutCtx, time.Second) {
				break
			}
		}

		// Check for self-update and restart if needed.
		needRestart, err := manager.SelfUpdate(ctx)
		if err != nil {
			globalLogger.Error(err)
		}
		if needRestart {
			globalLogger.Info("updated self, exiting to await restart with new version")
			return
		}
	}

	manager.StartBackgroundChecks(ctx)
	<-ctx.Done()
	manager.CloseAll()

	activeBackgroundWorkers.Wait()
}

func setupExitSignalHandling() context.Context {
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

func getLock() (lockfile.Lockfile, error) {
	pidFile, err := lockfile.New(filepath.Join(agent.ViamDirs["tmp"], "viam-agent.pid"))
	if err != nil {
		return "", errors.Wrap(err, "init lockfile")
	}
	err = pidFile.TryLock()
	if err == nil {
		return pidFile, nil
	}

	globalLogger.Warn(errors.Wrapf(err, "locking %s", pidFile))

	// if it's a potentially temporary error, retry
	if errors.Is(err, lockfile.ErrBusy) || errors.Is(err, lockfile.ErrNotExist) {
		time.Sleep(2 * time.Second)
		globalLogger.Warn("retrying lock")
		err = pidFile.TryLock()
		if err == nil {
			return pidFile, nil
		}

		// if (still) busy, validate that the PID in question is actually viam-agent
		// some systems use sequential, low numbered PIDs that can easily repeat after a reboot or crash
		// this could result some other valid/running process that matches a leftover lockfile PID
		if errors.Is(err, lockfile.ErrBusy) {
			var staleFile bool
			proc, err := pidFile.GetOwner()
			if err != nil {
				globalLogger.Error(errors.Wrap(err, "getting lockfile owner"))
				staleFile = true
			}
			runPath, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/%d/exe", proc.Pid))
			if err != nil {
				globalLogger.Error(errors.Wrap(err, "cannot get info on lockfile owner"))
				staleFile = true
			} else if !strings.Contains(runPath, agent.SubsystemName) {
				globalLogger.Warnf("lockfile owner isn't %s", agent.SubsystemName)
				staleFile = true
			}
			if staleFile {
				globalLogger.Warnf("deleting lockfile %s", pidFile)
				if err := os.RemoveAll(string(pidFile)); err != nil {
					return "", errors.Wrap(err, "removing lockfile")
				}
				return pidFile, pidFile.TryLock()
			}
			return "", errors.Errorf("other instance of viam-agent is already running with PID: %d", proc.Pid)
		}
	}
	return "", err
}
