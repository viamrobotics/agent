package main

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/nightlyone/lockfile"
	"github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems/networking"
	_ "github.com/viamrobotics/agent/subsystems/syscfg"
	"github.com/viamrobotics/agent/utils"
	"go.uber.org/zap"
	"go.viam.com/rdk/logging"
	goutils "go.viam.com/utils"
)

var (
	activeBackgroundWorkers sync.WaitGroup

	// only changed/set at startup, so no mutex.
	globalLogger = logging.NewLogger("viam-agent")
)

//nolint:lll
type agentOpts struct {
	Config         string `default:"/etc/viam.json"                        description:"Path to machine credentials file"   long:"config"   short:"c"`
	DefaultsConfig string `default:"/etc/viam-defaults.json"               description:"Path to manufacturer defaults file" long:"defaults"`
	Debug          bool   `description:"Enable debug logging (agent only)" env:"VIAM_AGENT_DEBUG"                           long:"debug"    short:"d"`
	UpdateFirst    bool   `description:"Update versions before starting"   env:"VIAM_AGENT_WAIT_FOR_UPDATE"                 long:"wait"     short:"w"`
	Help           bool   `description:"Show this help message"            long:"help"                                      short:"h"`
	Version        bool   `description:"Show version"                      long:"version"                                   short:"v"`
	Install        bool   `description:"Install systemd service"           long:"install"`
	DevMode        bool   `description:"Allow non-root and non-service"    env:"VIAM_AGENT_DEVMODE"                         long:"dev-mode"`
}

//nolint:gocognit
func commonMain() {
	ctx, cancel := setupExitSignalHandling()

	defer func() {
		cancel()
		activeBackgroundWorkers.Wait()
	}()

	var opts agentOpts
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
		fmt.Printf("Version: %s\nGit Revision: %s\n", utils.GetVersion(), utils.GetRevision())
		return
	}

	if opts.Debug {
		utils.CLIDebug = true
		globalLogger.SetLevel(logging.DEBUG)
	}

	if opts.UpdateFirst {
		utils.CLIWaitForUpdateCheck = true
	}

	// need to be root to go any further than this
	curUser, err := user.Current()
	exitIfError(err)
	if runtime.GOOS != "windows" && curUser.Uid != "0" && !opts.DevMode {
		//nolint:forbidigo
		fmt.Printf("viam-agent must be run as root (uid 0), but current user is %s (uid %s)\n", curUser.Username, curUser.Uid)
		return
	}

	if opts.Install {
		exitIfError(agent.Install(globalLogger))
		return
	}

	if runtime.GOOS != "windows" && !opts.DevMode {
		// confirm that we're running from a proper install
		if !strings.HasPrefix(os.Args[0], utils.ViamDirs["viam"]) {
			//nolint:forbidigo
			fmt.Printf("viam-agent is intended to be run as a system service and installed in %s.\n"+
				"Please install with '%s --install' and then start the service with 'systemctl start viam-agent'\n"+
				"Note you may need to preface the above commands with 'sudo' if you are not currently root.\n",
				utils.ViamDirs["viam"], os.Args[0])
			return
		}
	}

	// set up folder structure
	exitIfError(utils.InitPaths())

	// use a lockfile to prevent running two agents on the same machine
	pidFile, err := getLock()
	exitIfError(err)
	defer func() {
		if err := pidFile.Unlock(); err != nil {
			globalLogger.Error(errors.Wrapf(err, "unlocking %s", pidFile))
		}
	}()

	utils.DefaultsFilePath, err = filepath.Abs(opts.DefaultsConfig)
	exitIfError(err)
	globalLogger.Infof("manufacturer defaults file path: %s", utils.DefaultsFilePath)

	utils.AppConfigFilePath, err = filepath.Abs(opts.Config)
	exitIfError(err)
	globalLogger.Infof("machine credentials file path: %s", utils.AppConfigFilePath)

	cfg, err := utils.LoadConfigFromCache()
	exitIfError(err)

	cfg = utils.ApplyCLIArgs(cfg)

	// main manager structure
	manager := agent.NewManager(ctx, globalLogger, cfg)

	err = manager.LoadAppConfig()
	//nolint:nestif
	if err != nil {
		if cfg.AdvancedSettings.DisableNetworkConfiguration {
			globalLogger.Errorf("Cannot read %s and network configuration is disabled. Please correct and restart viam-agent.",
				utils.AppConfigFilePath)
			manager.CloseAll()
			return
		}

		// If the local /etc/viam.json config is corrupted, invalid, or missing (due to a new install), we can get stuck here.
		// Rename the file (if it exists) and wait to provision a new one.
		if !errors.Is(err, fs.ErrNotExist) {
			globalLogger.Error(errors.Wrapf(err, "reading %s", utils.AppConfigFilePath))
			globalLogger.Warn("renaming %s to %s.old", utils.AppConfigFilePath, utils.AppConfigFilePath)
			if err := os.Rename(utils.AppConfigFilePath, utils.AppConfigFilePath+".old"); err != nil {
				// if we can't rename the file, we're up a creek, and it's fatal
				globalLogger.Error(errors.Wrapf(err, "removing invalid config file %s", utils.AppConfigFilePath))
				globalLogger.Error("unable to continue with provisioning, exiting")
				manager.CloseAll()
				return
			}
		}

		// We manually start the provisioning service to allow the user to update it and wait.
		// The user may be updating it soon, so better to loop quietly than to exit and let systemd keep restarting infinitely.
		globalLogger.Infof("machine credentials file %s missing or corrupt, entering provisioning mode", utils.AppConfigFilePath)

		if err := manager.StartSubsystem(ctx, networking.SubsysName); err != nil {
			globalLogger.Error(errors.Wrapf(err, "could not start networking subsystem, "+
				"please manually update /etc/viam.json and connect to internet"))
			manager.CloseAll()
			return
		}

		for {
			globalLogger.Warn("waiting for user provisioning")
			if !goutils.SelectContextOrWait(ctx, time.Second*10) {
				manager.CloseAll()
				return
			}
			if err := manager.LoadAppConfig(); err == nil {
				break
			}
		}
	}

	// valid viam.json from this point forward
	netAppender, err := manager.CreateNetAppender()
	if err != nil {
		globalLogger.Errorf("error creating NetAppender: %s", err)
	} else {
		globalLogger.AddAppender(netAppender)
	}

	// wait until now when we (potentially) have a network logger to record this
	globalLogger.Infof("Viam Agent Version: %s Git Revision: %s", utils.GetVersion(), utils.GetRevision())

	if cfg.AdvancedSettings.WaitForUpdateCheck {
		// wait to be online
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		waitOnline(timeoutCtx)

		// Check for self-update and restart if needed.
		needRestart, err := manager.SelfUpdate(ctx)
		if err != nil {
			globalLogger.Error(err)
		}
		if needRestart {
			manager.CloseAll()
			globalLogger.Info("updated self, exiting to await restart with new version")
			return
		}
	}

	manager.StartBackgroundChecks(ctx)
	<-ctx.Done()
	manager.CloseAll()
}

func setupExitSignalHandling() (context.Context, func()) {
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

			// log everything else
			default:
				if !ignoredSignal(sig) {
					globalLogger.Debugw("received unknown signal", "signal", sig)
				}
			}
		}
	}()

	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGABRT)
	return ctx, cancel
}

// helper to log.Fatal if error is non-nil.
func exitIfError(err error) {
	if err != nil {
		globalLogger.WithOptions(zap.AddCallerSkip(1)).Fatal(err)
	}
}

func getLock() (lockfile.Lockfile, error) {
	pidFile, err := lockfile.New(filepath.Join(utils.ViamDirs["tmp"], "viam-agent.pid"))
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
